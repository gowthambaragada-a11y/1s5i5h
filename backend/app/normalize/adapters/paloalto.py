"""Palo Alto PAN-OS normalizer.

Handles two shapes:

1. ``set`` command form (``running-config.xml`` CLI output)::

       set rulebase security-policy rules 'web-out' from trust ...

2. ``<config><devices>...</devices></config>`` XML form (native config export).

The interesting part for Deliverable 4 is :meth:`PaloAltoPANOSNormalizer.normalize`,
which flattens a hierarchical rulebase into the same ``AccessRule`` list a
Cisco ACL produces -- including synthesizing the implicit ``any-any`` catch-all
that PAN-OS ships as an explicit default rule.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar
from xml.etree.ElementTree import Element

from defusedxml.ElementTree import ParseError, fromstring, tostring  # type: ignore[import-untyped]

from app.normalize.base import VendorNormalizer
from app.normalize.models import (
    AccessList,
    AccessRule,
    AdminState,
    CredentialSet,
    CryptoConfig,
    DeviceIdentity,
    DeviceRole,
    Interface,
    InterfaceKind,
    LoggingConfig,
    ManagementService,
    NormalizedConfig,
    PortRange,
    Protocol,
    RuleAction,
    ServiceBinding,
    SourceRef,
    SourceRefs,
    Vendor,
)
from app.normalize.util import make_endpoint, parse_port_spec

_MEMBER = re.compile(r"'([^']+)'|\"([^\"]+)\"|(\S+)")
_XML_LINE = re.compile(r"<([a-zA-Z0-9_-]+)")
_XML_ENTRY = re.compile(r'<entry\s+name="([^"]+)"')
#: Opening tags of management services, e.g. ``<ssh>`` -> "ssh".
_XML_MGMT_TAG = re.compile(r"<(ssh|telnet|http|https|snmp)>")

#: ``<ssh-options><management><ssh><enabled>yes`` -> unified service.
_MGMT_TAGS = {
    "ssh": ManagementService.SSH,
    "telnet": ManagementService.TELNET,
    "http": ManagementService.HTTP,
    "https": ManagementService.HTTPS,
}

#: Identity tags map straight onto :class:`DeviceIdentity` fields.
_IDENTITY_TAG = {
    "hostname": lambda ast, v: ast["identity"].__setitem__("hostname", v),
    "serial-number": lambda ast, v: ast["identity"].__setitem__("serial", v),
    "model-type": lambda ast, v: ast["identity"].__setitem__("model", v),
    "sw-version": lambda ast, v: ast["identity"].__setitem__("software_version", v),
}


def _yes(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"yes", "true", "1"}


def _port_for(svc: ManagementService) -> tuple[int, Protocol]:
    """Well-known port for a management service."""
    return {
        ManagementService.SSH: (22, Protocol.TCP),
        ManagementService.TELNET: (23, Protocol.TCP),
        ManagementService.HTTP: (80, Protocol.TCP),
        ManagementService.HTTPS: (443, Protocol.TCP),
        ManagementService.SNMP: (161, Protocol.UDP),
    }.get(svc, (0, Protocol.TCP))


def _clip(text: str, limit: int = 240) -> str:
    """Collapse an XML fragment to a single citable line."""
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "\u2026"


def _line_index(raw_text: str) -> dict[str, int]:
    """Map config identifiers to their line number, for evidence.

    Two shapes are indexed because PAN-OS exports both ways:
      ``<entry name="dmz-ghost-services">``  -> keyed by the bare name
      ``<ssh>`` / ``</ssh>``                 -> keyed ``management.ssh``
    """
    index: dict[str, int] = {}
    for line_no, line in enumerate(raw_text.splitlines(), start=1):
        for m in _XML_ENTRY.finditer(line):
            index.setdefault(m.group(1), line_no)
        for m in _XML_MGMT_TAG.finditer(line):
            index.setdefault(f"management.{m.group(1)}", line_no)
    return index


def _members(value: str | None) -> list[str]:
    """Extract quoted or bare members from a PAN-OS CLI value string."""
    if not value:
        return []
    out: list[str] = []
    for m in _MEMBER.finditer(value):
        out.append(next(g for g in m.groups() if g is not None))
    return out


class PaloAltoPANOSNormalizer(VendorNormalizer):
    vendor: ClassVar[Vendor] = Vendor.PALOALTO_PANOS
    rule_pack: ClassVar[str] = "cis_panos"

    # ------------------------------------------------------------------ #
    @classmethod
    def supports(cls, raw_text: str) -> float:
        head = raw_text[:6000].lower()
        score = 0.0
        if "<config" in head and "paloaltonworks" in head:
            score += 0.55
        if "paloalto" in head or "pan-os" in head or "panos" in head:
            score += 0.25
        if re.search(r"set\s+(?:deviceconfig|rulebase|vsys|network|mgt-config)\b", raw_text, re.I):
            score += 0.3
        if re.search(r"<\s*(security-policy|rulebase|vsys|deviceconfig|log-settings)\b", raw_text, re.I):
            score += 0.25
        if re.search(r"^\s*set\s+(address|service|application)\s+'", raw_text, re.M | re.I):
            score += 0.1
        return min(score, 1.0)

    @classmethod
    def priority(cls) -> int:
        return 80

    # ------------------------------------------------------------------ #
    def parse(self, raw_text: str) -> dict[str, Any]:
        if re.search(r"^\s*set\s+\S+", raw_text, re.M) and not raw_text.lstrip().startswith("<"):
            return self._parse_cli(raw_text)
        return self._parse_xml(raw_text)

    # -- XML ------------------------------------------------------------- #
    def _parse_xml(self, raw_text: str) -> dict[str, Any]:
        ast: dict[str, Any] = {
            "identity": {},
            "interfaces": [],
            "rules": [],
            "zones": [],
            "services": {},
            "credentials": [],
            "logging": {},
            "warnings": [],
        }
        # PAN-OS exports are valid XML but sometimes contain a bare '&'.
        cleaned = re.sub(r"&(?!(?:amp|lt|gt|quot|apos|#\d+);)", "&amp;", raw_text)
        try:
            root = fromstring(cleaned)
        except ParseError as exc:
            ast["warnings"].append(f"PAN-OS XML parse failed: {exc}; falling back to regex extraction")
            return self._parse_cli(raw_text)

        # Build the line index *before* walking: _walk attaches source_refs as it
        # descends, so indexing afterwards left every ref at line_no 0.
        ast["_line_anchor"] = _line_index(raw_text)
        self._walk(root, ast)
        ast["_unparsed_ratio"] = 0.0
        return ast

    def _walk(self, elem: Element, ast: dict[str, Any], parent_tag: str = "") -> None:
        """Depth-first walk collecting rules, interfaces, services and identity.

        ``parent_tag`` is the discriminator: PAN-OS uses one tag name for many
        things, so an ``<entry>`` means a Security Policy rule under
        ``<security-policy>`` but an interface under ``<ethernet>``.
        """
        for child in elem:
            tag = child.tag
            value = (child.text or "").strip()

            if parent_tag == "security-policy" and tag == "entry":
                ast["rules"].append(self._rule_from_entry(child, ast))
                continue
            if parent_tag in {"ethernet", "aggregate-ethernet"} and tag == "entry":
                iface = self._iface_from_entry(child, parent_tag, ast)
                if iface:
                    ast["interfaces"].append(iface)
                continue
            if parent_tag == "management" and tag in _MGMT_TAGS:
                svc = _MGMT_TAGS[tag]
                enabled = _yes(child.findtext("enabled"))
                entry = ast["services"].setdefault(svc.value, {"refs": [], "enabled": False})
                entry["enabled"] = enabled
                # Keep the raw <ssh>...</ssh> element as the cited evidence so a
                # telnet finding on PAN-OS points at a real config line rather
                # than at nothing.
                entry["refs"] = [
                    SourceRef(
                        line_no=ast.get("_line_anchor", {}).get(f"management.{tag}", 0),
                        raw=_clip(tostring(child, encoding="unicode")),
                        context=[f"device-config/{parent_tag}/{tag}"],
                    )
                ]
                continue
            if parent_tag == "admin" and tag == "entry":
                ast["credentials"].append(
                    {
                        "username": child.get("name") or "unknown",
                        "role": (child.findtext("role") or "").strip() or None,
                        "auth_method": "local",
                        "refs": [
                            SourceRef(
                                line_no=ast.get("_line_anchor", {}).get(child.get("name", ""), 0),
                                raw=f'<admin><entry name="{child.get("name")}">',
                            )
                        ],
                    }
                )
                continue

            if parent_tag in {"traffic", "threat", "config"} and tag == "enable":
                ast["logging"][parent_tag] = value.strip().lower() == "yes"
                continue
            if tag in _IDENTITY_TAG and value:
                _IDENTITY_TAG[tag](ast, value)

            if len(child):
                self._walk(child, ast, tag)

    def _iface_from_entry(self, elem: Element, parent_tag: str, ast: dict[str, Any]) -> dict[str, Any] | None:
        name = elem.get("name")
        if not name:
            return None
        ipv4 = [ip for ip in (elem.findtext("ip"),) if ip]
        ipv6 = [ip for ip in (elem.findtext("ipv6"),) if ip]
        ipv4 += [c.text.strip() for c in elem.findall("secondary-ip/member") if c.text]
        comment = elem.findtext("comment")
        anchors = ast.get("_line_anchor", {})
        return {
            "name": name,
            "kind": "routed" if parent_tag == "ethernet" else "aggregate",
            "ipv4": ipv4,
            "ipv6": ipv6,
            "description": comment,
            "admin_state": "down" if elem.find("disable") is not None else "up",
            # Resolve the real line from the pre-built index; a hardcoded 0 made
            # every interface finding unciteable in the UI.
            "refs": [
                SourceRef(
                    line_no=anchors.get(name, 0),
                    raw=f'<entry name="{name}">',
                    context=[f"device-config/{parent_tag}"],
                )
            ],
        }

    def _rule_from_entry(self, elem: Element, ast: dict[str, Any]) -> dict[str, Any]:
        def members(path: str) -> list[str]:
            return [(m.text or "").strip() for m in elem.findall(path) if (m.text or "").strip()]

        def txt(tag: str) -> str | None:
            node = elem.find(tag)
            if node is None:
                return None
            inner = node.findtext("member")
            return (inner or (node.text or "")).strip() or None

        name = elem.get("name") or "unnamed"
        anchors = ast.get("_line_anchor", {})
        rule: dict[str, Any] = {
            "name": name,
            "uuid": elem.get("uuid"),
            "from_zones": members("from/member"),
            "to_zones": members("to/member"),
            "source": members("source/member"),
            "destination": members("destination/member"),
            "services": members("service/member"),
            "applications": members("application/member"),
            "users": members("source-user/member"),
            "url_categories": members("url-category/member"),
            "action": (txt("action") or "deny").lower(),
            "disabled": _yes(txt("disabled")),
            "log_start": _yes(txt("log-start")),
            "log_end": _yes(txt("log-end")),
            # PAN-OS ships a terminal rule literally named "any-any".
            "is_default": name.lower() in {"any-any", "any-any-any"},
            "tags": members("tag/member"),
            "ref": SourceRef(
                line_no=anchors.get(name, 0),
                raw=f'<entry name="{name}">  (security-policy)',
            ),
        }
        ast.setdefault("zones", []).extend(rule["from_zones"] + rule["to_zones"])
        return rule

    # -- CLI -------------------------------------------------------------- #
    def _parse_cli(self, raw_text: str) -> dict[str, Any]:
        ast: dict[str, Any] = {
            "identity": {},
            "interfaces": [],
            "rules": [],
            "zones": [],
            "services": {},
            "credentials": [],
            "logging": {},
            "warnings": [],
        }
        recognised: set[str] = set()
        # Accumulate `set rulebase security-policy rules NAME key value` triples.
        rule_ctx: dict[str, dict[str, Any]] = {}
        order: list[str] = []

        for line_no, raw in enumerate(raw_text.splitlines(), start=1):
            line = raw.strip()
            if not line:
                continue
            recognised.add(line)
            if not line.lower().startswith("set "):
                continue
            tokens = line[4:].split()
            if not tokens:
                continue

            head = tokens[0]
            # identity
            if head == "deviceconfig" and len(tokens) > 2 and tokens[2] == "hostname":
                ast["identity"]["hostname"] = tokens[-1]
                continue

            # management services
            if head in {"ssh", "telnet", "http", "https"} and "management" in line:
                svc = {
                    "ssh": ManagementService.SSH,
                    "telnet": ManagementService.TELNET,
                    "http": ManagementService.HTTP,
                    "https": ManagementService.HTTPS,
                }[head]
                enabled = "yes" in tokens
                ast["services"].setdefault(svc.value, {"refs": [], "enabled": False})["enabled"] = enabled
                ast["services"][svc.value]["refs"].append(SourceRef(line_no=line_no, raw=line))
                continue

            # security policy rules
            if head == "rulebase" and len(tokens) >= 4 and tokens[1] == "security-policy":
                if tokens[2] == "rules":
                    name = tokens[3]
                    if name not in rule_ctx:
                        rule_ctx[name] = {
                            "name": name,
                            "ref": SourceRef(line_no=line_no, raw=line),
                            "from_zones": [],
                            "to_zones": [],
                        }
                        order.append(name)
                    self._apply_rule_kv(rule_ctx[name], tokens[4:])
                continue

            # interfaces
            if head == "network" and len(tokens) >= 3 and tokens[1] == "interface":
                iface = self._parse_cli_interface(tokens, line_no, line)
                if iface:
                    ast["interfaces"].append(iface)
                continue

            # logging
            if head == "log-settings":
                if "traffic" in tokens:
                    ast["logging"]["traffic"] = "yes" in tokens
                if "threat" in tokens:
                    ast["logging"]["threat"] = "yes" in tokens
                logging_ref = ast["logging"].get("refs", []) + [SourceRef(line_no=line_no, raw=line)]
                ast["logging"]["refs"] = logging_ref
                continue

            # local users
            if head == "vsys" and "config" in tokens and "vsys" in line and "user" in line:
                name = tokens[-1]
                ast["credentials"].append(
                    {"username": name, "refs": [SourceRef(line_no=line_no, raw=line)], "value_type": ""}
                )
                continue

        ast["rules"] = [rule_ctx[n] for n in order]
        ast["_unparsed_ratio"] = self.count_unparsed(raw_text, recognised)
        return ast

    def _apply_rule_kv(self, rule: dict[str, Any], toks: list[str]) -> None:
        """Apply ``KEY <value...>`` to the in-progress rule dict."""
        if not toks:
            return
        key, vals = toks[0].lower(), toks[1:]
        mapping: dict[str, Any] = {
            "from": "from_zones",
            "to": "to_zones",
            "source": "source",
            "destination": "destination",
            "service": "services",
            "application": "applications",
            "source-user": "users",
            "url-category": "url_categories",
            "tag": "tags",
        }
        if key in mapping:
            rule[mapping[key]] = _members(" ".join(_quote(v) for v in vals))
        elif key == "action":
            rule["action"] = vals[0].lower() if vals else "deny"
        elif key == "disabled":
            rule["disabled"] = (vals[0].lower() == "yes") if vals else False
        elif key == "log-end":
            rule["log_end"] = (vals[0].lower() == "yes") if vals else False
        elif key == "log-start":
            rule["log_start"] = (vals[0].lower() == "yes") if vals else False
        elif key == "uuid":
            rule["uuid"] = vals[0] if vals else None

    def _parse_cli_interface(self, tokens: list[str], line_no: int, line: str) -> dict[str, Any] | None:
        """``set network interface ethernet ethernet1/1 ip 10.0.0.1/24``"""
        try:
            idx = tokens.index("interface")
        except ValueError:
            return None
        ifmtype = tokens[idx + 1]
        name = tokens[idx + 2] if len(tokens) > idx + 2 else ""
        iface: dict[str, Any] = {
            "name": name,
            "kind": "routed" if ifmtype == "ethernet" else ifmtype,
            "refs": [SourceRef(line_no=line_no, raw=line)],
        }
        rest = tokens[idx + 3 :]
        for i, tok in enumerate(rest):
            if tok == "ip" and i + 1 < len(rest) and "/" in rest[i + 1]:
                iface.setdefault("ipv4", []).append(rest[i + 1])
            elif tok in {"comment", "description"} and i + 1 < len(rest):
                iface["description"] = rest[i + 1]
            elif tok in {"disable", "shut"}:
                iface["admin_state"] = "shutdown"
            elif tok == "mode" and i + 1 < len(rest):
                iface["kind"] = {"l3": "routed", "l2": "l2_trunk", "virtual-wire": "tunnel"}.get(
                    rest[i + 1], "unknown"
                )
        return iface

    # ------------------------------------------------------------------ #
    def normalize(self, ast: dict[str, Any]) -> NormalizedConfig:
        cfg = NormalizedConfig(device_id="pending", vendor=self.vendor, role=DeviceRole.FIREWALL)
        ident = ast.get("identity", {})
        cfg.identity = DeviceIdentity(
            hostname=ident.get("hostname"),
            software_version=ident.get("software_version"),
            model=ident.get("model"),
            serial=ident.get("serial"),
        )
        cfg.unparsed_line_ratio = ast.get("_unparsed_ratio")
        cfg.zones = sorted(set(ast.get("zones", [])))
        cfg.interfaces = [self._norm_iface(i) for i in ast.get("interfaces", [])]
        cfg.access_lists = [self._norm_policy(ast.get("rules", []))]
        cfg.services = self._norm_services(ast.get("services", {}))
        cfg.credentials = [self._norm_cred(c) for c in ast.get("credentials", [])]
        logging = ast.get("logging", {})
        log_line = ast.get("_line_anchor", {}).get("localhost.localdomain", 0)
        cfg.logging = LoggingConfig(
            enabled=any(logging.values()),
            severity_level="traffic" if logging.get("traffic") else None,
            logs_config_changes=bool(logging.get("config")),
            source_refs=SourceRefs(refs=[SourceRef(line_no=log_line, raw="<log-settings>")]),
        )
        # IPSec/SSL VPN is configured under vsys -> network -> ike-gateway, which we
        # do not model yet. Recorded as absent rather than guessed.
        cfg.crypto = CryptoConfig(any_ipsec=ast.get("any_ipsec", False))
        return cfg

    def _norm_iface(self, d: dict[str, Any]) -> Interface:
        return Interface(
            name=d.get("name", ""),
            kind=InterfaceKind(d.get("kind", "routed")),
            admin_state=AdminState(d.get("admin_state", "up")),
            description=d.get("description"),
            ipv4=d.get("ipv4", []),
            vlans=d.get("vlans", []),
            is_l3=d.get("kind") == "routed",
            source=SourceRefs(refs=list(d.get("refs", []))),
        )

    def _norm_policy(self, rules: list[dict[str, Any]]) -> AccessList:
        """Flatten the PAN-OS rulebase into the unified AccessRule list.

        PAN-OS policy is a cross-product (zones x addresses x services x apps).
        We emit one AccessRule per (source, destination) pair and keep the
        service as a set of PortRanges on a representative rule, since the
        unified model has a single ``service`` field. Applications are retained
        on ``application`` so L7 rules stay inspectable.
        """
        refs = SourceRefs()
        out: list[AccessRule] = []
        for r in rules:
            ref = r.get("ref") or SourceRef(line_no=0, raw=f"rule {r.get('name')}")
            ace_refs = SourceRefs(refs=[ref])
            if r.get("is_default"):
                continue  # synthesized below
            sources = [make_endpoint(s) for s in (r.get("source") or ["any"])]
            dests = [make_endpoint(d) for d in (r.get("destination") or ["any"])]
            services = r.get("services") or ["any"]
            ports = [self._service_to_port(s) for s in services]
            extra_tags = [r["disabled_tag"]] if r.get("disabled") else []
            for src in sources:
                for dst in dests:
                    for port in ports:
                        out.append(
                            AccessRule(
                                rule_id=f"{r.get('name')}",
                                position=len(out),
                                source=src,
                                destination=dst,
                                service=port,
                                action=self._map_action(r),
                                logging=bool(r.get("log_end") or r.get("log_start")),
                                source_zones=r.get("from_zones", []),
                                destination_zones=r.get("to_zones", []),
                                source_users=r.get("users", []),
                                is_default=False,
                                application=", ".join(r.get("applications", [])) or None,
                                url_category=", ".join(r.get("url_categories", [])) or None,
                                tags=[*r.get("tags", []), *extra_tags],
                                source_refs=ace_refs,
                            )
                        )
            if r.get("is_default"):
                out.append(self._default_rule(r))
            refs.add(ref)

        # PAN-OS always ends with a deny-all when no explicit any-any exists.
        if not any(x.is_default for x in out):
            out.append(
                AccessRule(
                    rule_id="__implicit_deny_any__",
                    position=len(out),
                    source=make_endpoint("any"),
                    destination=make_endpoint("any"),
                    service=PortRange(protocol=Protocol.ANY),
                    action=RuleAction.DENY,
                    is_default=True,
                    tags=["implicit"],
                )
            )
        return AccessList(
            name="security-policy",
            kind="security-policy",
            vendor=self.vendor,
            direction="zoned",
            position=0,
            rules=out,
            source_refs=refs,
        )

    @staticmethod
    def _default_rule(r: dict[str, Any]) -> AccessRule:
        return AccessRule(
            rule_id=r.get("name", "any-any"),
            position=10_000,
            source=make_endpoint("any"),
            destination=make_endpoint("any"),
            service=PortRange(protocol=Protocol.ANY),
            action=RuleAction.DENY if (r.get("action") or "deny") == "deny" else RuleAction.ALLOW,
            is_default=True,
            source_zones=r.get("from_zones", []),
            destination_zones=r.get("to_zones", []),
            source_refs=SourceRefs(refs=[r["ref"]] if r.get("ref") else []),
        )

    @staticmethod
    def _map_action(r: dict[str, Any]) -> RuleAction:
        act = (r.get("action") or "deny").lower()
        if r.get("disabled"):
            return RuleAction.DISABLE
        return {
            "allow": RuleAction.ALLOW,
            "deny": RuleAction.DENY,
            "reject": RuleAction.REJECT,
            "no-packet-drop": RuleAction.DENY,
            "reset-client": RuleAction.REJECT,
            "reset-server": RuleAction.REJECT,
            "reset-both": RuleAction.REJECT,
        }.get(act, RuleAction.DENY)

    @staticmethod
    def _service_to_port(name: str) -> PortRange:
        """Map a PAN-OS service object name onto a port range."""
        n = name.strip().lower()
        table = {
            "ssh": PortRange(protocol=Protocol.TCP, low=22, high=22),
            "telnet": PortRange(protocol=Protocol.TCP, low=23, high=23),
            "http": PortRange(protocol=Protocol.TCP, low=80, high=80),
            "https": PortRange(protocol=Protocol.TCP, low=443, high=443),
            "snmp": PortRange(protocol=Protocol.UDP, low=161, high=161),
            "smtp": PortRange(protocol=Protocol.TCP, low=25, high=25),
            "dns": PortRange(protocol=Protocol.UDP, low=53, high=53),
            "ntp": PortRange(protocol=Protocol.UDP, low=123, high=123),
            "ldap": PortRange(protocol=Protocol.TCP, low=389, high=389),
            "kerberos": PortRange(protocol=Protocol.TCP, low=88, high=88),
            "radius": PortRange(protocol=Protocol.UDP, low=1812, high=1812),
            "syslog": PortRange(protocol=Protocol.UDP, low=514, high=514),
            "any": PortRange(protocol=Protocol.ANY),
            "application-default": PortRange(protocol=Protocol.ANY),
            "service-http": PortRange(protocol=Protocol.TCP, low=80, high=80),
            "service-https": PortRange(protocol=Protocol.TCP, low=443, high=443),
        }
        if n in table:
            return table[n]
        m = re.match(r"^(tcp|udp)-(\d+)(?:-(\d+))?$", n)
        if m:
            return PortRange(
                protocol=Protocol(m.group(1)), low=int(m.group(2)), high=int(m.group(3) or m.group(2))
            )
        m = re.match(r"^custom-(\d+)-(\w+)$", n)
        if m:
            return parse_port_spec(m.group(1), protocol=m.group(2))
        return PortRange(protocol=Protocol.ANY)

    def _norm_services(self, services: dict[str, Any]) -> list[ServiceBinding]:
        out: list[ServiceBinding] = []
        port_map = {
            ManagementService.SSH: (22, Protocol.TCP),
            ManagementService.TELNET: (23, Protocol.TCP),
            ManagementService.HTTP: (80, Protocol.TCP),
            ManagementService.HTTPS: (443, Protocol.TCP),
        }
        for svc_name, data in services.items():
            try:
                svc = ManagementService(svc_name)
            except ValueError:
                continue
            port, proto = port_map.get(svc, (None, Protocol.TCP))
            # PAN-OS keys services as "<svc>:<action>" because the same tag can
            # carry both 'allow' and 'discard' members. The normalizer keys on
            # the bare service, so tolerate the suffix rather than skipping the
            # record (which would silently hide a Telnet finding).
            if port is None:
                port, proto = _port_for(svc)
            out.append(
                ServiceBinding(
                    service=svc,
                    enabled=bool(data.get("enabled")),
                    transport="tcp",
                    port=PortRange(protocol=proto, low=port, high=port),
                    # PAN-OS restricts management via the management profile ACL,
                    # which lives in a different config scope; treated as unrestricted.
                    restricted_to=[],
                    source_refs=SourceRefs(refs=list(data.get("refs", []))),
                )
            )
        return out

    @staticmethod
    def _norm_cred(c: dict[str, Any]) -> CredentialSet:
        role = (c.get("role") or "").lower()
        return CredentialSet(
            username=c.get("username", "unknown"),
            role=role or None,
            auth_method=c.get("auth_method", "local"),
            is_privileged=role in {"superadmin", "netadmin", "admin"},
            has_password_set=True,
            source_refs=SourceRefs(refs=list(c.get("refs", []))),
        )


def _quote(token: str) -> str:
    return token if re.fullmatch(r"[A-Za-z0-9_./:-]+", token or "") else f"'{token}'"
