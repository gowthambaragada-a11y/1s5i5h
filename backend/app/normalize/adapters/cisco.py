"""Cisco IOS / IOS-XE / NX-OS normalizer.

Reference syntax handled::

    interface GigabitEthernet0/1
     description USER-LAN
     ip address 10.10.10.1 255.255.255.0
    ip access-list extended OUTSIDE_IN
     permit tcp any host 203.0.113.5 eq 23
     deny   ip any any log
    ip ssh version 2
    line vty 0 4
     transport input ssh
    snmp-server community public RO
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

from app.normalize.base import VendorNormalizer
from app.normalize.models import (
    AccessList,
    AccessRule,
    AdminState,
    CredentialSet,
    CryptoConfig,
    DeviceIdentity,
    DeviceRole,
    Endpoint,
    Interface,
    InterfaceKind,
    LoggingConfig,
    ManagementService,
    NormalizedConfig,
    PortRange,
    Protocol,
    RoutingConfig,
    RuleAction,
    ServiceBinding,
    SourceRef,
    SourceRefs,
    Vendor,
    describe_secret,
)
from app.normalize.util import (
    make_endpoint,
    strip_bang,
    wildcard_to_prefix,
)

_IFACE = re.compile(r"^interface\s+(\S+)", re.I)
_IPV4 = re.compile(r"^\s*ip\s+address\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)(.*)$", re.I)
_IPV6 = re.compile(r"^\s*ipv6\s+address\s+([0-9A-Fa-f:]+(?:/\d+)?)", re.I)
_VRF = re.compile(r"^\s*vrf\s+forwarding\s+(\S+)", re.I)
_IPV6_VRF = re.compile(r"^\s*vrf\s+member\s+(\S+)", re.I)
_SWITCHPORT_ACCESS = re.compile(r"^\s*switchport\s+mode\s+access", re.I)
_SWITCHPORT_TRUNK = re.compile(r"^\s*switchport\s+mode\s+trunk", re.I)
_VLAN = re.compile(r"^\s*switchport\s+access\s+vlan\s+(\d+)", re.I)
_TRUNK_VLANS = re.compile(
    r"^\s*switchport\s+trunk\s+(?:allowed\s+)?vlan(?:s)?\s+(?:add\s+)?([\d,\- ]+)", re.I
)

_STD_ACE = re.compile(
    r"^\s*(?P<action>permit|deny)\s+(?P<proto>ip|tcp|udp|icmp|igmp|gre|esp|ahp|ospf)\s+"
    r"(?P<src>\S+)(?:\s+(?P<src_wc>\S+))?\s+"
    r"(?P<dst>\S+)(?:\s+(?P<dst_wc>\S+))?"
    r"(?P<tail>.*)$",
    re.I,
)
_EXT_ACE_TAIL = re.compile(r"\b(?P<mod>eq|gt|lt|neq|range)\s+(?P<vals>[\d\-\s,]+)", re.I)

_CRED_USER = re.compile(
    r"^username\s+(?P<name>\S+)(?:\s+(?P<kind>privilege|secret|password|view)\s+(?P<val>\S+))?", re.I
)
_SNMP_COMM = re.compile(r"^snmp-server\s+community\s+(?P<comm>\S+)(?:\s+(?P<perm>\S+))?", re.I)
_SNMP_HOST = re.compile(r"^snmp-server\s+host\s+(\S+)", re.I)
_LOG_HOST = re.compile(r"^logging\s+host\s+(\S+)", re.I)
_LOG_TRAP = re.compile(r"^\s*logging\s+trap\s+(\S+)", re.I)
_LOG_BUF = re.compile(r"^\s*logging\s+buffered\s+(\d+)", re.I)
_LOG_CONF_T = re.compile(r"^\s*logging\s+config-log\s", re.I)

_VTY = re.compile(r"^line\s+(vty|console)\s*(.*)$", re.I)
# Capture *every* protocol, not just the first: 'transport input telnet ssh'
# enables both, and reading only the leading token silently reported SSH as
# disabled on a device that was using it.
_VTY_TRANSPORT = re.compile(r"^\s*transport\s+input(?:\s+(?!all\b)\S+)+", re.I)
_VTY_TIMEOUT = re.compile(r"^\s*exec-timeout\s+(\d+)", re.I)
_VTY_ACCESS = re.compile(r"^\s*access-class\s+(\S+)", re.I)
_VTY_LOGIN = re.compile(r"^\s*login\s+(?:local|network\s+\S+)?", re.I)

_STATIC_ROUTE = re.compile(r"^ip\s+route\s+", re.I)
_DEFAULT_ROUTE = re.compile(r"^ip\s+route\s+0\.0\.0\.0\s+0\.0\.0\.0", re.I)
_ROUTING_PROTO = re.compile(r"^\s*router\s+(\w+)", re.I)
_ISAKMP = re.compile(r"^\s*crypto\s+isakmp\s+(policy|key)", re.I)
_CRYPTO_MAP = re.compile(r"^\s*crypto\s+map\s+", re.I)
_TRANSFORM = re.compile(r"set\s+transform|set\s+esp", re.I)
_KEYEX = re.compile(r"\b(des|3des|rc4|md5|768|1024|1|2)\b", re.I)
_BANNER = re.compile(r"^banner\s+(\w+)", re.I)
_SERVICES = re.compile(r"^\s*(ntp|snmp-server|ip\s+nhcp|tacacs-server|radius-server)\s", re.I)

#: Transport sub-commands on vty lines -> service they expose.
_TRANSPORT_SERVICE = {"ssh": ManagementService.SSH, "telnet": ManagementService.TELNET}


def _snmp_svc() -> dict[str, Any]:
    """A fresh ``snmp-server`` accumulator so refs are never shared between lines."""
    return {"refs": [], "communities": [], "hosts": [], "version": None}


class CiscoIOSNormalizer(VendorNormalizer):
    vendor: ClassVar[Vendor] = Vendor.CISCO_IOS
    rule_pack: ClassVar[str] = "cis_cisco_ios"

    # ------------------------------------------------------------------ #
    @classmethod
    def supports(cls, raw_text: str) -> float:
        head = raw_text[:4000].lower()
        score = 0.0
        if (
            "current configuration" in head
            or head.lstrip().startswith("version ")
            or "! last configuration change" in head
        ):
            score += 0.45
        if re.search(r"^\s*building configuration", raw_text, re.M | re.I):
            score += 0.3
        if re.search(r"^\s*(interface|ip access-list|line vty|hostname)\s", raw_text, re.M | re.I):
            score += 0.2
        if re.search(r"^\s*switchport\s+", raw_text, re.M | re.I):
            score += 0.15
        if "cisco systems" in head or "ios-xe" in head or "nx-os" in head:
            score += 0.25
        # Cisco NX-OS is a distinct vendor enum for rule-pack purposes.
        if re.search(r"^\s*system\s*\{", raw_text, re.M | re.I) or "nxos" in head:
            score -= 0.1
        return min(score, 1.0)

    @classmethod
    def priority(cls) -> int:
        return 55

    # ------------------------------------------------------------------ #
    def parse(self, raw_text: str) -> dict[str, Any]:
        """Flat-scan into a lightweight AST keyed by IOS command families."""
        ast: dict[str, Any] = {
            "identity": {},
            "interfaces": {},
            "access_lists": {},
            "services": {},
            "credentials": [],
            "logging": {},
            "routing": {},
            "crypto": {},
            "banners": {},
            "warnings": [],
        }
        recognised: set[str] = set()
        current_iface: str | None = None
        current_acl: str | None = None
        current_vty: str | None = None

        for line_no, raw in enumerate(raw_text.splitlines(), start=1):
            line = strip_bang(raw)
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip())
            body = line.strip()
            recognised.add(body)

            # ---- interface ------------------------------------------- #
            if _IFACE.match(body):
                current_iface = _IFACE.match(body).group(1)  # type: ignore[union-attr]
                current_acl = current_vty = None
                ast["interfaces"].setdefault(current_iface, {"name": current_iface, "lines": []})
                ast["interfaces"][current_iface].setdefault("refs", []).append(
                    SourceRef(line_no=line_no, raw=raw.strip())
                )
                continue

            # ---- access-list ----------------------------------------- #
            m = re.match(r"^ip\s+access-list\s+(standard|extended|resequence)?\s*(\S+)", body, re.I)
            if m and not indent:
                current_acl = m.group(2)
                current_iface = current_vty = None
                ast["access_lists"].setdefault(
                    current_acl,
                    {"name": current_acl, "kind": m.group(1) or "extended", "aces": [], "refs": []},
                )
                ast["access_lists"][current_acl]["refs"].append(SourceRef(line_no=line_no, raw=raw.strip()))
                continue
            if body.lower().startswith("access-list ") and not indent:
                current_acl = body.split()[1]
                ast["access_lists"].setdefault(
                    current_acl, {"name": current_acl, "kind": "numbered", "aces": [], "refs": []}
                )
                continue

            # ---- line vty ------------------------------------------- #
            if _VTY.match(body) and not indent:
                current_vty = body.split(None, 1)[1] if " " in body else "vty"
                current_iface = current_acl = None
                ast["services"].setdefault(current_vty, {"refs": [], "transport": [], "access_class": None})
                ast["services"][current_vty]["refs"].append(SourceRef(line_no=line_no, raw=raw.strip()))
                continue

            target = (
                ast["interfaces"].get(current_iface)
                if current_iface
                else ast["access_lists"].get(current_acl)
                if current_acl
                else ast["services"].get(current_vty)
                if current_vty
                else None
            )
            if target is not None and "refs" in target:
                target["refs"].append(SourceRef(line_no=line_no, raw=raw.strip()))

            self._dispatch_global(body, raw, line_no, ast, indent)

            if current_acl and target is not None and "aces" in target:
                ace = self._parse_ace(body, line_no, raw)
                if ace:
                    target["aces"].append(ace)
            elif current_vty and target is not None:
                if mt := _VTY_TRANSPORT.match(body):
                    # Everything after 'transport input' is a protocol list;
                    # 'none' alone means no remote protocol is permitted.
                    protocols = mt.group(0).split()
                    protocols = protocols[protocols.index("input") + 1 :] if "input" in protocols else []
                    target["transport"] = [t.lower() for t in protocols if t.lower() != "none"]
                if ma := _VTY_ACCESS.match(body):
                    target["access_class"] = ma.group(1)
                if me := _VTY_TIMEOUT.match(body):
                    target["exec_timeout"] = int(me.group(1))
                if _VTY_LOGIN.match(body):
                    target["login"] = True
            elif current_iface and target is not None:
                self._parse_interface_line(body, current_iface, ast)

        ast["_unparsed_ratio"] = self.count_unparsed(raw_text, recognised)
        return ast

    # -- dispatch ---------------------------------------------------- #
    def _dispatch_global(self, body: str, raw: str, line_no: int, ast: dict[str, Any], indent: int) -> None:
        ident = ast["identity"]
        if m := re.match(r"^hostname\s+(\S+)", body, re.I):
            ident["hostname"] = m.group(1)
        elif m := re.match(r"^version\s+(\S+)", body, re.I):
            ident["software_version"] = m.group(1)
        elif m := re.match(r"^model\s+(?:number\s+)?(\S+)", body, re.I):
            ident["model"] = m.group(1)
        elif m := re.match(r"^boot\s+system\s+flash:(\S+)", body, re.I):
            ident.setdefault("image", m.group(1))

        if m := _CRED_USER.match(body):
            ast["credentials"].append(
                {
                    "username": m.group("name"),
                    "kind": (m.group("kind") or "").lower() or None,
                    "value_type": (m.group("val") or ""),
                    "refs": [SourceRef(line_no=line_no, raw=raw.strip())],
                }
            )
        elif m := _SNMP_COMM.match(body):
            ast["services"].setdefault("__snmp__", _snmp_svc())
            svc = ast["services"]["__snmp__"]
            svc["communities"].append(
                {"community": m.group("comm"), "perm": (m.group("perm") or "RO").upper()}
            )
            svc["refs"].append(SourceRef(line_no=line_no, raw=raw.strip()))
        elif m := _SNMP_HOST.match(body):
            ast["services"].setdefault("__snmp__", _snmp_svc())
            ast["services"]["__snmp__"]["hosts"].append(m.group(1))
        elif m := re.match(r"^snmp-server\s+version\s+(\S+)", body, re.I):
            ast["services"].setdefault("__snmp__", _snmp_svc())
            ast["services"]["__snmp__"]["version"] = m.group(1)

        if m := _LOG_HOST.match(body):
            ast["logging"].setdefault("hosts", []).append(m.group(1))
            ast["logging"].setdefault("refs", []).append(SourceRef(line_no=line_no, raw=raw.strip()))
        elif m := _LOG_TRAP.match(body):
            ast["logging"]["trap_level"] = m.group(1).lower()
            ast["logging"].setdefault("refs", []).append(SourceRef(line_no=line_no, raw=raw.strip()))
        elif m := _LOG_BUF.match(body):
            ast["logging"]["buffered"] = int(m.group(1))
        elif _LOG_CONF_T.match(body):
            ast["logging"]["config_log"] = True

        if _DEFAULT_ROUTE.match(body):
            ast["routing"]["default_route"] = True
            ast["routing"].setdefault("refs", []).append(SourceRef(line_no=line_no, raw=raw.strip()))
        elif _STATIC_ROUTE.match(body):
            ast["routing"]["static_count"] = ast["routing"].get("static_count", 0) + 1
        elif m := _ROUTING_PROTO.match(body):
            ast["routing"].setdefault("protocols", []).append(m.group(1).lower())

        if _ISAKMP.match(body) or _CRYPTO_MAP.match(body):
            ast["crypto"]["any_ipsec"] = True
            if _TRANSFORM.match(body) and (m := re.search(r"set\s+transform\s+(\S+)", body, re.I)):
                ast["crypto"].setdefault("transforms", []).append(m.group(1))
                if re.search(r"\b(des|3des|rc4|md5|768|1024)\b", m.group(1), re.I):
                    ast["crypto"].setdefault("weak", []).append(m.group(1))
        if m := _BANNER.match(body):
            ast["banners"][m.group(1).lower()] = True

        if m := re.match(r"^ip\s+ssh\s+version\s+(\S+)", body, re.I):
            ast["services"].setdefault("__ssh__", {"refs": [], "version": m.group(1)})
            ast["services"]["__ssh__"]["version"] = m.group(1)
            ast["services"]["__ssh__"]["refs"].append(SourceRef(line_no=line_no, raw=raw.strip()))
        elif m := re.match(r"^ip\s+domain\s+name\s+(\S+)", body, re.I):
            known = ast["services"].get("__ssh__", {})
            ast["services"].setdefault("__ssh__", {"refs": [], "version": known.get("version")})
            ast["services"]["__ssh__"]["domain_name"] = m.group(1)
        elif m := re.match(r"^service\s+password-encryption", body, re.I):
            ast["services"].setdefault("__pw_encrypt__", {"refs": [], "enabled": True})
            ast["services"]["__pw_encrypt__"]["refs"].append(SourceRef(line_no=line_no, raw=raw.strip()))
        elif m := re.match(r"^no\s+service\s+timestamps?\b", body, re.I):
            ast["services"].setdefault("__timestamps__", {"refs": [], "enabled": False})
        elif m := re.match(r"^service\s+timestamps?\b", body, re.I):
            ast["services"].setdefault("__timestamps__", {"refs": [], "enabled": True})
        elif m := re.match(r"^version\s+(\S+)", body, re.I):
            pass

    def _parse_interface_line(self, body: str, name: str, ast: dict[str, Any]) -> None:
        iface = ast["interfaces"][name]
        if m := re.match(r"^\s*description\s+(.+)$", body, re.I):
            iface["description"] = m.group(1).strip()
        elif m := _IPV4.match(body):
            iface.setdefault("ipv4", []).append(f"{m.group(1)}/{ip_prefix(m.group(2))}")
        elif m := _IPV6.match(body):
            iface.setdefault("ipv6", []).append(m.group(1))
        elif m := re.match(r"^\s*no\s+shutdown", body, re.I):
            iface["admin_state"] = "up"
        elif re.match(r"^\s*shutdown", body, re.I):
            iface["admin_state"] = "shutdown"
        elif m := _VLAN.match(body):
            iface.setdefault("vlans", []).append(int(m.group(1)))
        elif m := _TRUNK_VLANS.match(body):
            iface.setdefault("vlans", []).extend(expand_vlan_spec(m.group(1)))
        elif _SWITCHPORT_ACCESS.match(body):
            iface["kind"] = "l2_access"
        elif _SWITCHPORT_TRUNK.match(body):
            iface["kind"] = "l2_trunk"
        elif (m := _VRF.match(body)) or (m := _IPV6_VRF.match(body)):
            iface["vrf"] = m.group(1)
        elif re.match(r"^\s*(no\s+)?ip\s+address", body, re.I) and "ipv4" in iface:
            iface["ipv4"] = []
        if iface.get("ipv4") or iface.get("ipv6"):
            iface.setdefault("kind", "routed")

    def _parse_ace(self, body: str, line_no: int, raw: str) -> dict[str, Any] | None:
        m = _STD_ACE.match(body)
        if not m:
            return None
        tail = m.group("tail") or ""
        proto = Protocol(m.group("proto").lower())

        src = make_endpoint(m.group("src"), wildcard_to_prefix(m.group("src_wc") or ""))
        dst = make_endpoint(m.group("dst"), wildcard_to_prefix(m.group("dst_wc") or ""))
        # "host X" means /32; make_endpoint saw the literal token, so fix it up.
        if m.group("src").lower() == "host":
            src = Endpoint(address=m.group("src_wc") or "any", prefix_len=32)
        if m.group("dst").lower() == "host":
            dst = Endpoint(address=m.group("dst_wc") or "any", prefix_len=32)

        # Extended ACE port qualifiers: "eq 443", "range 1024 65535", "gt 1024".
        ports: list[tuple[str, int | None, int | None]] = []
        for q in _EXT_ACE_TAIL.finditer(tail):
            op = q.group("mod").lower()
            nums = [int(x) for x in re.findall(r"\d+", q.group("vals"))]
            if not nums:
                continue
            if op == "eq":
                ports.append(("eq", nums[0], nums[0]))
            elif op == "range" and len(nums) >= 2:
                ports.append(("range", nums[0], nums[1]))
            elif op == "lt":
                ports.append(("lt", 1, max(0, nums[0] - 1)))
            elif op == "gt":
                ports.append(("gt", nums[0] + 1, 65535))
            elif op == "neq":
                ports.append(("neq", nums[0], nums[0]))

        logging = bool(re.search(r"\blog(ging)?\b", tail, re.I))
        return {
            "action": RuleAction.ALLOW if m.group("action").lower() == "permit" else RuleAction.DENY,
            "protocol": proto,
            "source": src,
            "destination": dst,
            "ports": ports,
            "logging": logging,
            "established": bool(re.search(r"\bestablished\b", tail, re.I)),
            "ref": SourceRef(line_no=line_no, raw=raw.strip()),
        }

    # ------------------------------------------------------------------ #
    def normalize(self, ast: dict[str, Any]) -> NormalizedConfig:
        cfg = NormalizedConfig(
            device_id="pending", vendor=self.vendor, role=DeviceRole.UNKNOWN, access_lists=[]
        )
        ident = ast.get("identity", {})
        cfg.identity = DeviceIdentity(
            hostname=ident.get("hostname"),
            software_version=ident.get("software_version"),
            model=ident.get("model"),
        )
        cfg.unparsed_line_ratio = ast.get("_unparsed_ratio")

        cfg.interfaces = [self._norm_interface(d) for d in ast.get("interfaces", {}).values()]
        acl_items = ast.get("access_lists", {}).items()
        cfg.access_lists = [self._norm_acl(name, d, i) for i, (name, d) in enumerate(acl_items)]
        cfg.services = self._norm_services(ast.get("services", {}))
        cfg.credentials = [self._norm_cred(c) for c in ast.get("credentials", [])]
        cfg.logging = self._norm_logging(ast.get("logging", {}))

        routing = ast.get("routing", {})
        rrefs = SourceRefs(refs=list(routing.get("refs", [])))
        cfg.routing = RoutingConfig(
            static_routes=routing.get("static_count", 0),
            default_route_present=routing.get("default_route", False),
            dynamic_protocols=routing.get("protocols", []),
            source_refs=rrefs,
        )

        crypto = ast.get("crypto", {})
        cfg.crypto = CryptoConfig(
            any_ipsec=crypto.get("any_ipsec", False), weak_ciphers=crypto.get("weak", [])
        )

        cfg.role = self._infer_role(cfg)
        cfg.parse_warnings.extend(
            f"cisco: unrecognised interface commands on {n} interface(s)"
            for n, d in ast.get("interfaces", {}).items()
            if not d.get("ipv4") and not d.get("description")
        )
        return cfg

    def _norm_interface(self, d: dict[str, Any]) -> Interface:
        refs = SourceRefs(refs=list(d.get("refs", [])))
        return Interface(
            name=d["name"],
            kind=InterfaceKind(d.get("kind", "unknown")),
            admin_state=AdminState(d.get("admin_state", "up")),
            description=d.get("description"),
            ipv4=d.get("ipv4", []),
            ipv6=d.get("ipv6", []),
            vrf=d.get("vrf"),
            vlans=sorted(set(d.get("vlans", []))),
            is_l3=bool(d.get("kind") == "routed"),
            source=refs,
        )

    def _norm_acl(self, name: str, d: dict[str, Any], position: int) -> AccessList:
        refs = SourceRefs()
        for r in d.get("refs", []):
            refs.add(r)
        rules: list[AccessRule] = []
        for i, ace in enumerate(d.get("aces", [])):
            port = self._port_from_ace(ace)
            ace_refs = SourceRefs()
            ace_refs.add(ace["ref"])
            rules.append(
                AccessRule(
                    rule_id=f"{name}_{i}",
                    position=i,
                    source=ace["source"],
                    destination=ace["destination"],
                    service=port,
                    action=ace["action"],
                    logging=ace["logging"],
                    tags=[t for t in ("established",) if ace.get(t)],
                    source_refs=ace_refs,
                )
            )
        # Cisco semantics: an extended ACL always ends in an implicit deny-all.
        if d.get("kind") == "extended" and not any(r.is_default for r in rules):
            rules.append(
                AccessRule(
                    rule_id=f"{name}_implicit_deny",
                    position=len(rules),
                    source=Endpoint(is_any=True, address="any"),
                    destination=Endpoint(is_any=True, address="any"),
                    service=PortRange(protocol=Protocol.IP, low=None, high=None),
                    action=RuleAction.DENY,
                    is_default=True,
                    source_refs=SourceRefs(refs=[refs.refs[0]] if refs.refs else []),
                )
            )
        direction = _acl_direction(name)
        return AccessList(
            name=name,
            kind="acl",
            vendor=self.vendor,
            direction=direction,
            position=position,
            rules=rules,
            source_refs=refs,
        )

    @staticmethod
    def _port_from_ace(ace: dict[str, Any]) -> PortRange:
        """Collapse extended-ACE port qualifiers into a PortRange.

        With multiple qualifiers (source eq + dest eq) we keep the first, which
        matches how the security rules reason about exposure.
        """
        proto = ace["protocol"]
        ports = ace.get("ports") or []
        if not ports:
            return PortRange(protocol=proto, low=None, high=None)
        _op, low, high = ports[0]
        if proto is Protocol.TCP or proto is Protocol.UDP:
            return PortRange(protocol=proto, low=low, high=high)
        return PortRange(protocol=proto, low=None, high=None)

    def _norm_services(self, services: dict[str, Any]) -> list[ServiceBinding]:
        out: list[ServiceBinding] = []

        ssh_meta = services.get("__ssh__", {})
        pw_encrypt = services.get("__pw_encrypt__", {}).get("enabled", False)

        # vty lines drive SSH/Telnet exposure.
        vty_names = [k for k in services if k.startswith(("vty", "console"))]
        ssh_enabled = any("ssh" in services[v].get("transport", []) for v in vty_names)
        telnet_enabled = any("telnet" in services[v].get("transport", []) for v in vty_names)

        for name in vty_names:
            data = services[name]
            refs = SourceRefs(refs=list(data.get("refs", [])))
            for svc, port in ((ManagementService.SSH, 22), (ManagementService.TELNET, 23)):
                enabled = (svc is ManagementService.SSH and ssh_enabled) or (
                    svc is ManagementService.TELNET and telnet_enabled
                )
                if not enabled:
                    continue
                # access-class present => restricted; absent => world reachable.
                restriction = (
                    [Endpoint(address=f"acl:{data['access_class']}", is_any=False)]
                    if data.get("access_class")
                    else []
                )
                out.append(
                    ServiceBinding(
                        service=svc,
                        enabled=enabled,
                        version=ssh_meta.get("version"),
                        transport="tcp",
                        port=PortRange(protocol=Protocol.TCP, low=port, high=port),
                        restricted_to=restriction,
                        timeout_seconds=data.get("exec_timeout"),
                        acl_applied=data.get("access_class"),
                        source_refs=refs,
                    )
                )

        if ssh_meta:
            refs = SourceRefs(refs=list(ssh_meta.get("refs", [])))
            if not any(b.service is ManagementService.SSH for b in out):
                out.append(
                    ServiceBinding(
                        service=ManagementService.SSH,
                        enabled=True,
                        version=ssh_meta.get("version"),
                        port=PortRange(protocol=Protocol.TCP, low=22, high=22),
                        restricted_to=[Endpoint(address="any", is_any=True)],
                        source_refs=refs,
                    )
                )

        snmp = services.get("__snmp__")
        if snmp:
            refs = SourceRefs(refs=list(snmp.get("refs", [])))
            communities = snmp.get("communities", [])
            hosts = snmp.get("hosts", [])
            out.append(
                ServiceBinding(
                    service=ManagementService.SNMP,
                    enabled=True,
                    version=snmp.get("version") or ("v2c" if communities else None),
                    transport="udp",
                    port=PortRange(protocol=Protocol.UDP, low=161, high=161),
                    # ACL/name restriction is implied by presence of snmp-server host
                    restricted_to=[Endpoint(address=h, is_any=False) for h in hosts] if hosts else [],
                    acl_applied=None,
                    credentials=[
                        # Classify, never retain: the community string itself is a
                        # credential and must not reach the API or the graph.
                        describe_secret(c["community"], kind="community")
                        for c in communities
                    ],
                    version_notes="v3 preferred" if not snmp.get("version") else None,
                    source_refs=refs,
                )
            )

        if pw_encrypt:
            refs = SourceRefs(refs=list(services["__pw_encrypt__"].get("refs", [])))
            out.append(
                ServiceBinding(
                    service=ManagementService.OTHER,
                    enabled=True,
                    version="service password-encryption",
                    restricted_to=[Endpoint(address="n/a", is_any=False)],
                    source_refs=refs,
                )
            )
        return out

    @staticmethod
    def _norm_cred(c: dict[str, Any]) -> CredentialSet:
        priv_match = re.search(r"^(\d{1,2})$", c.get("value_type") or "")
        kind = c.get("kind") or ""
        return CredentialSet(
            username=c["username"],
            privilege=int(priv_match.group(1)) if priv_match else None,
            auth_method="local",
            is_privileged=bool(priv_match and int(priv_match.group(1)) >= 15) or kind == "secret",
            has_password_set=bool(kind in {"secret", "password"}),
            source_refs=SourceRefs(refs=list(c.get("refs", []))),
        )

    @staticmethod
    def _norm_logging(d: dict[str, Any]) -> LoggingConfig:
        refs = SourceRefs(refs=list(d.get("refs", [])))
        return LoggingConfig(
            enabled=bool(d.get("hosts") or d.get("trap_level")),
            remote_servers=[make_endpoint(h) for h in d.get("hosts", [])],
            severity_level=d.get("trap_level"),
            local_buffer=bool(d.get("buffered")),
            logs_config_changes=bool(d.get("config_log")),
            source_refs=refs,
        )

    @staticmethod
    def _infer_role(cfg: NormalizedConfig) -> DeviceRole:
        access_ports = [i for i in cfg.interfaces if i.kind is InterfaceKind.L2_ACCESS]
        routed = [i for i in cfg.interfaces if i.kind is InterfaceKind.ROUTED]
        if access_ports or cfg.identity.model and "3560" in (cfg.identity.model or ""):
            return DeviceRole.SWITCH
        if len(routed) > 2 and not cfg.access_lists:
            return DeviceRole.ROUTER
        if cfg.access_lists:
            return DeviceRole.ROUTER
        return DeviceRole.UNKNOWN


def ip_prefix(netmask: str) -> int:
    import ipaddress

    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except ValueError:
        return 32


def expand_vlan_spec(spec: str) -> list[int]:
    """Expand ``1,3-5`` into ``[1, 3, 4, 5]``."""
    out: list[int] = []
    for chunk in re.split(r"[,\s]+", spec.strip()):
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            if a.strip().isdigit() and b.strip().isdigit():
                out.extend(range(int(a), int(b) + 1))
        elif chunk.isdigit():
            out.append(int(chunk))
    return out


def _acl_direction(name: str) -> str | None:
    n = name.lower()
    if any(k in n for k in ("in", "ingress", "inbound")):
        return "inbound"
    if any(k in n for k in ("out", "egress", "outbound")):
        return "outbound"
    return None


# --------------------------------------------------------------------------- #
class CiscoNXOSNormalizer(CiscoIOSNormalizer):
    """NX-OS is close enough to IOS that only fingerprints and roles differ."""

    vendor: ClassVar[Vendor] = Vendor.CISCO_NXOS
    rule_pack: ClassVar[str] = "cis_cisco_nxos"

    @classmethod
    def supports(cls, raw_text: str) -> float:
        head = raw_text[:4000].lower()
        score = 0.0
        if "nxos" in head or "cisco nexus" in head:
            score += 0.5
        if re.search(
            r"^\s*(feature|vpc domain|interface ethernet|system default switchport)", raw_text, re.M | re.I
        ):
            score += 0.25
        if re.search(r"^\s*switchport\s+mode\s+(access|trunk)", raw_text, re.M | re.I):
            score += 0.15
        return min(score, 1.0)

    @classmethod
    def priority(cls) -> int:
        return 70
