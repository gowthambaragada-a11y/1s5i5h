"""Fortinet FortiOS normalizer.

FortiGate running configs are a flat sequence of ``config <section>`` blocks
containing ``edit <name>`` / ``set <key> <value>`` / ``next`` / ``end``. We
tokenize into ``{section: {entry_name: {key: value}}}`` which is a faithful
representation of the file and makes the rest of the adapter straightforward.
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
from app.normalize.util import make_endpoint

_SET = re.compile(r"^\s*set\s+(?P<key>[\w\-/]+)\s*(?P<value>.*)$", re.I)
_EDIT = re.compile(r"^\s*edit\s+(?P<name>.+?)\s*$", re.I)
_CONFIG = re.compile(r"^\s*config\s+(?P<section>[\w\-/]+)\s*(?P<rest>.*)$", re.I)

_SERVICE_PORTS: dict[str, tuple[Protocol, int | None, int | None]] = {
    "SSH": (Protocol.TCP, 22, 22),
    "TELNET": (Protocol.TCP, 23, 23),
    "HTTP": (Protocol.TCP, 80, 80),
    "HTTPS": (Protocol.TCP, 443, 443),
    "ALL": (Protocol.ANY, None, None),
    "DNS": (Protocol.UDP, 53, 53),
    "SNMP": (Protocol.UDP, 161, 161),
    "SMTP": (Protocol.TCP, 25, 25),
    "NTP": (Protocol.UDP, 123, 123),
    "SYSLOG": (Protocol.UDP, 514, 514),
    "RDP": (Protocol.TCP, 3389, 3389),
    "MYSQL": (Protocol.TCP, 3306, 3306),
    "MS-SQL": (Protocol.TCP, 1433, 1433),
    "LDAP": (Protocol.TCP, 389, 389),
}


class FortinetFortiOSNormalizer(VendorNormalizer):
    vendor: ClassVar[Vendor] = Vendor.FORTINET_FORTIOS
    rule_pack: ClassVar[str] = "cis_fortinet"

    @classmethod
    def supports(cls, raw_text: str) -> float:
        head = raw_text[:6000].lower()
        score = 0.0
        if "#config-version" in head or "#conf_file_ver" in head:
            score += 0.55
        if "fortinet" in head or "fortigate" in head or "fortios" in head:
            score += 0.3
        if re.search(r"^\s*config\s+(firewall|system|global)\s+", raw_text, re.M | re.I):
            score += 0.3
        if re.search(r"^\s*(edit|set|next|end)\s+", raw_text, re.M | re.I):
            score += 0.15
        return min(score, 1.0)

    @classmethod
    def priority(cls) -> int:
        return 65

    # ------------------------------------------------------------------ #
    def parse(self, raw_text: str) -> dict[str, Any]:
        """Tokenize into ``{section: {entry: {key: value, _refs: [...]}}}``."""
        sections: dict[str, dict[str, dict[str, Any]]] = {}
        warnings: list[str] = []

        section: str | None = None
        entry: str | None = None
        cursor: dict[str, Any] | None = None
        header_line = 1

        for line_no, raw in enumerate(raw_text.splitlines(), start=1):
            line = raw.rstrip()
            if not line.strip() or line.strip().startswith("#"):
                if "config-version" in line.lower() and not sections:
                    warnings.append("FortiOS config-version header present")
                continue

            if m := _CONFIG.match(line):
                section = f"{m.group('section')} {m.group('rest').strip()}".strip()
                sections.setdefault(section, {})
                entry = cursor = None
                header_line = line_no
                continue

            if m := _EDIT.match(line):
                if section is None:
                    warnings.append(f"L{line_no}: 'edit' outside a config block -- ignored")
                    continue
                # FortiGate quotes names containing spaces or slashes.
                entry = m.group("name").strip().strip('"').strip("'")
                cursor = {"_refs": [SourceRef(line_no=line_no, raw=line.strip())]}
                sections[section].setdefault(entry, cursor)
                continue

            body = line.strip()
            if body == "next":
                entry = cursor = None
                continue
            if body == "end":
                section = entry = cursor = None
                continue

            if (m := _SET.match(line)) and cursor is not None:
                value = m.group("value").strip().strip('"')
                key = m.group("key")
                if key in cursor and key != "_refs":
                    cursor[key] = f"{cursor[key]} {value}"
                else:
                    cursor[key] = value
                cursor["_refs"].append(SourceRef(line_no=line_no, raw=line.strip()))
                continue

            if (m := _SET.match(line)) and section is not None and entry is None:
                # Section-level scalar settings (e.g. `config system settings /
                # set admin-ssh-port 22`) live without an `edit` wrapper. Park them
                # under a reserved entry so downstream code can read them uniformly.
                slot = sections[section].setdefault("__section__", {"_refs": []})
                slot[m.group("key")] = m.group("value").strip().strip('"')
                slot["_refs"].append(SourceRef(line_no=line_no, raw=line.strip()))
                continue

            if cursor is not None:
                cursor["_refs"].append(SourceRef(line_no=line_no, raw=line.strip()))
            elif section:
                sections[section].setdefault("__loose__", {"_refs": []})["_refs"].append(
                    SourceRef(line_no=line_no, raw=line.strip())
                )

        return {
            "sections": sections,
            "warnings": warnings,
            "header_line": header_line,
            "_unparsed_ratio": self.count_unparsed(raw_text, {ln.strip() for ln in raw_text.splitlines()}),
        }

    # ------------------------------------------------------------------ #
    def normalize(self, ast: dict[str, Any]) -> NormalizedConfig:
        sections = ast.get("sections", {})
        cfg = NormalizedConfig(device_id="pending", vendor=self.vendor, role=DeviceRole.FIREWALL)
        cfg.unparsed_line_ratio = ast.get("_unparsed_ratio")

        glob = _flat(sections.get("system global", {}))
        global_refs = SourceRefs(refs=_refs(glob))
        cfg.identity = DeviceIdentity(
            hostname=glob.get("hostname"),
            software_version=glob.get("version") or _fortios_version(ast),
            serial=glob.get("serial"),
        )

        cfg.interfaces = self._norm_interfaces(sections.get("system interface", {}))
        cfg.access_lists = [
            self._norm_policy(sections.get("firewall policy", {})),
            self._norm_policy(sections.get("firewall central-policy", {}), name="central-policy"),
        ]
        cfg.services = self._norm_services(sections, global_refs)
        cfg.credentials = self._norm_users(sections.get("system admin", {}))
        cfg.logging = self._norm_logging(sections, ast)
        cfg.routing = RoutingConfig(
            static_routes=len(sections.get("router static", {})),
            default_route_present=_has_default_route(sections),
            dynamic_protocols=list(sections.get("router protocol", {}).keys()),
        )
        ipsec = sections.get("vpn ipsec phase2-interface", {}) or sections.get("vpn ipsec", {})
        cfg.crypto = CryptoConfig(any_ipsec=bool(ipsec))
        cfg.zones = sorted(
            {
                i
                for p in sections.get("firewall policy", {}).values()
                for i in (p.get("srcintf"), p.get("dstintf"))
                if i and i != "any"
            }
        )
        return cfg

    @staticmethod
    def _norm_interfaces(raw: dict[str, Any]) -> list[Interface]:
        out: list[Interface] = []
        for name, data in raw.items():
            if name == "__loose__" or not isinstance(data, dict):
                continue
            ipv4: list[str] = []
            # `set ip <address> <netmask>` arrives as one value with two tokens.
            addr = data.get("ip")
            mask = data.get("netmask")
            if addr and addr != "0.0.0.0":  # noqa: S104 - literal test for an unconfigured address
                addr_parts = _split_list(addr)
                literal = addr_parts[0]
                netmask = mask or (addr_parts[1] if len(addr_parts) > 1 else None)
                ipv4.append(f"{literal}/{_prefix_from_mask(netmask)}" if netmask else literal)

            allow = (data.get("allowaccess") or "").split()
            iface = Interface(
                name=name,
                kind=InterfaceKind(data.get("mode", "routed")),
                admin_state=AdminState("shutdown" if data.get("status") == "down" else "up"),
                description=data.get("description"),
                ipv4=ipv4,
                vrf=data.get("vrf"),
                is_l3=data.get("mode", "routed") == "routed",
                source=SourceRefs(refs=_refs(data)),
            )
            # allowaccess is FortiOS's per-interface management ACL.
            iface.description = iface.description or (f"allowaccess: {' '.join(allow)}" if allow else None)
            out.append(iface)
        return out

    def _norm_policy(self, raw: dict[str, Any], *, name: str = "firewall policy") -> AccessList:
        rules: list[AccessRule] = []
        acl_refs = SourceRefs()
        for key, data in raw.items():
            if key == "__loose__" or not isinstance(data, dict):
                continue
            refs = SourceRefs(refs=_refs(data))
            acl_refs.extend(refs)
            action = (data.get("action") or "deny").lower()
            rule_action = {
                "accept": RuleAction.ALLOW,
                "deny": RuleAction.DENY,
                "reject": RuleAction.REJECT,
            }.get(action, RuleAction.DENY)
            if data.get("schedule") in (None, "", "always"):
                pass  # always-schedule is the FortiGate default and a real finding
            src_zones = [data.get("srcintf")] if data.get("srcintf") else []
            dst_zones = [data.get("dstintf")] if data.get("dstintf") else []
            svc_spec = data.get("service")
            for svc in _split_list(svc_spec if isinstance(svc_spec, str) else "ALL"):
                # 'is_default' means "the adapter synthesised this rule; it is not
                # in the config". It must NOT be set for a real policy that
                # happens to span every interface -- doing so made genuine
                # any-to-any FortiGate policies invisible to every firewall rule,
                # because the rule pack skips is_default entries.
                spans_all_interfaces = data.get("srcintf") == "any" and data.get("dstintf") == "any"
                rules.append(
                    AccessRule(
                        rule_id=data.get("name") or key,
                        position=int(key) if str(key).isdigit() else len(rules),
                        source=self._endpoint(data, "srcaddr"),
                        destination=self._endpoint(data, "dstaddr"),
                        service=self._service(svc),
                        action=rule_action,
                        logging=(data.get("logtraffic") or "all").lower() in {"all", "enable"},
                        source_zones=[z for z in src_zones if z],
                        destination_zones=[z for z in dst_zones if z],
                        is_default=False,
                        tags=["all-interfaces"] if spans_all_interfaces else [],
                        source_refs=refs,
                    )
                )
        # FortiGate always has a final implicit deny-all. Adding it explicitly
        # means "is there a terminal deny?" is a question the rules can answer
        # instead of each adapter inventing its own absence semantics.
        rules.append(
            AccessRule(
                rule_id="__implicit_deny_any__",
                position=len(rules),
                source=make_endpoint("any"),
                destination=make_endpoint("any"),
                service=PortRange(protocol=Protocol.ANY),
                action=RuleAction.DENY,
                is_default=True,
                tags=["implicit"],
            )
        )
        return AccessList(
            name=name,
            kind="security-policy",
            vendor=self.vendor,
            direction="zoned",
            rules=rules,
            source_refs=acl_refs,
        )

    @staticmethod
    def _endpoint(data: dict[str, Any], field: str) -> Endpoint:
        value = data.get(field) or "any"
        tokens = _split_list(value)
        if len(tokens) == 1:
            return make_endpoint(tokens[0])
        # Multiple address objects => treat as a group endpoint.
        return Endpoint(address=f"addrgroup:{value}", is_any="all" in {t.lower() for t in tokens})

    @staticmethod
    def _service(name: str) -> PortRange:
        key = name.strip().upper()
        if key in _SERVICE_PORTS:
            proto, lo, hi = _SERVICE_PORTS[key]
            return PortRange(protocol=proto, low=lo, high=hi)
        m = re.match(r"^([A-Z]+)-(\d+)(?:/(\d+))?$", key)
        if m:
            proto = Protocol.UDP if m.group(1) == "UDP" else Protocol.TCP
            lo = int(m.group(2))
            return PortRange(protocol=proto, low=lo, high=int(m.group(3) or lo))
        return PortRange(protocol=Protocol.ANY)

    @staticmethod
    def _norm_users(raw: dict[str, Any]) -> list[CredentialSet]:
        out: list[CredentialSet] = []
        for name, data in raw.items():
            if not isinstance(data, dict) or name == "__loose__":
                continue
            accprofile = data.get("accprofile") or ""
            out.append(
                CredentialSet(
                    username=name,
                    role=accprofile or None,
                    auth_method=next(
                        (m for m in ("ldap", "radius", "tacacs", "two-factor") if data.get(m) == "enable"),
                        "local",
                    ),
                    is_privileged="super_admin" in accprofile or accprofile == "admin" or name == "admin",
                    has_password_set=bool(data.get("passwd") or data.get("password")),
                    source_refs=SourceRefs(refs=_refs(data)),
                )
            )
        return out

    @staticmethod
    def _norm_services(sections: dict[str, Any], global_refs: SourceRefs) -> list[ServiceBinding]:
        settings = _flat(sections.get("system settings", {}))
        srefs = SourceRefs(refs=_refs(settings) or list(global_refs.refs))
        out: list[ServiceBinding] = []

        def add(svc: ManagementService, port: int, enabled: bool, proto: Protocol = Protocol.TCP) -> None:
            out.append(
                ServiceBinding(
                    service=svc,
                    enabled=enabled,
                    transport="tcp",
                    port=PortRange(protocol=proto, low=port, high=port),
                    # FortiOS restricts admin access via trusted-hosts, not this file
                    # scope; absence of trusted-hosts => world reachable.
                    restricted_to=[],
                    source_refs=SourceRefs(refs=list(srefs.refs)),
                )
            )

        telnet_raw = str(settings.get("admin-telnet-port", "disabled")).strip()
        telnet_on = telnet_raw.lower() != "disabled"
        add(ManagementService.TELNET, int(telnet_raw) if telnet_on else 23, telnet_on)
        ssh_raw = str(settings.get("admin-ssh-port", "22")).strip()
        add(ManagementService.SSH, int(ssh_raw) if ssh_raw.isdigit() else 22, True)
        https_raw = str(settings.get("admin_https_port", "443")).strip()
        add(ManagementService.HTTPS, int(https_raw) if https_raw.isdigit() else 443, True)
        http_raw = str(settings.get("admin_http_port", "0")).strip()
        add(
            ManagementService.HTTP,
            int(http_raw) if http_raw.isdigit() and int(http_raw) else 80,
            http_raw.isdigit() and bool(int(http_raw)),
        )

        snmp = sections.get("system snmp syscommunity", {})
        if snmp:
            out.append(
                ServiceBinding(
                    service=ManagementService.SNMP,
                    enabled=True,
                    version="v2c",
                    transport="udp",
                    port=PortRange(protocol=Protocol.UDP, low=161, high=161),
                    restricted_to=[],
                    credentials=[
                        # FortiOS names SNMP v1/v2c entries after the community
                        # string itself, so classify and discard the value.
                        describe_secret(c.get("name"), kind="community")
                        for c in snmp.values()
                        if isinstance(c, dict)
                    ],
                    source_refs=SourceRefs(refs=_refs(next(iter(snmp.values()), {}))),
                )
            )
        return out

    @staticmethod
    def _norm_logging(sections: dict[str, Any], ast: dict[str, Any]) -> LoggingConfig:
        logsettings = sections.get("log setting", {})
        data = next((d for k, d in logsettings.items() if isinstance(d, dict)), {})
        refs = SourceRefs(
            refs=_refs(data) or [SourceRef(line_no=ast.get("header_line", 1), raw="log setting")]
        )
        return LoggingConfig(
            enabled=bool(data),
            remote_servers=[make_endpoint(data[k]) for k in ("syslogd1", "syslogd2") if data.get(k)],
            severity_level=data.get("fw-console-level"),
            local_buffer=(data.get("buffer") or "no") == "yes",
            rate_limited=(data.get("fwlog-mode") or "").lower() == "rate-limit",
            logs_config_changes=(data.get("event-recorded") or "yes") == "yes",
            source_refs=refs,
        )


# --------------------------------------------------------------------------- #
def _refs(entry: Any) -> list[SourceRef]:
    if isinstance(entry, dict):
        return list(entry.get("_refs", []))
    return []


def _has_default_route(sections: dict[str, Any]) -> bool:
    """True when ``config router static`` contains a 0.0.0.0/0 destination."""
    static = sections.get("router static", {})
    for entry in static.values():
        if not isinstance(entry, dict):
            continue
        values = entry.get("_values")
        if isinstance(values, list) and any("0.0.0.0/0" in str(v) for v in values):
            return True
    return "0.0.0.0/0" in str(static)


def _flat(section: dict[str, Any] | None) -> dict[str, Any]:
    """Merge a section's entries with its section-level ``__section__`` scalars.

    ``config system global`` mixes bare ``set`` lines with ``edit`` blocks, so
    callers want one flat view (e.g. ``hostname`` alongside nothing else).
    """
    if not section:
        return {}
    merged: dict[str, Any] = dict(section.get("__section__", {}) or {})
    merged["_refs"] = list((section.get("__section__") or {}).get("_refs", []))
    return merged


def _split_list(value: str) -> list[str]:
    return [v.strip().strip('"') for v in re.split(r"\s+", str(value)) if v.strip().strip('"')]


def _prefix_from_mask(mask: str | None) -> int:
    if not mask:
        return 32
    try:
        return __import__("ipaddress").IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return 32


def _fortios_version(ast: dict[str, Any]) -> str | None:
    sections = ast.get("sections", {})
    g = sections.get("system global", {})
    return g.get("version") if isinstance(g, dict) else None
