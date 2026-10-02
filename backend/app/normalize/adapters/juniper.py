"""Juniper Junos (SRX / MX / EX) normalizer.

Junos is brace-delimited and Lisp-like, so the adapter tokenizes with
``normalize.util.split_hier_braces`` and then walks the tree it cares about.
Coverage targets the SRX security-policy + system-services surface, which is
where the compliance signal lives.

Evidence note: the brace tokenizer discards line numbers, so findings cite an
*anchor* line -- the first line of the relevant top-level block (e.g.
``security {``) plus a description of the path. That is weaker evidence than a
line-exact citation, so ``AnalysisResult.evidence_precision`` is set to
``"block"`` for Junos and the UI labels it accordingly.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar, Literal

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
)
from app.normalize.util import (
    as_list,
    find,
    make_endpoint,
    pairs_of,
    split_hier_braces,
    strip_junos_comments,
    tokens_of,
)

#: L7 application name -> transport port range. Junos identifies services by
#: application, not port, so this table is how we recover an exposure surface.
_APPLICATION_PORTS: dict[str, PortRange] = {
    "juniper-http": PortRange(protocol=Protocol.TCP, low=80, high=80),
    "juniper-https": PortRange(protocol=Protocol.TCP, low=443, high=443),
    "juniper-ssh": PortRange(protocol=Protocol.TCP, low=22, high=22),
    "juniper-telnet": PortRange(protocol=Protocol.TCP, low=23, high=23),
    "juniper-ftp": PortRange(protocol=Protocol.TCP, low=21, high=21),
    "juniper-snmp": PortRange(protocol=Protocol.UDP, low=161, high=161),
    "juniper-ntp": PortRange(protocol=Protocol.UDP, low=123, high=123),
    "juniper-smtp": PortRange(protocol=Protocol.TCP, low=25, high=25),
    "juniper-ms-sql": PortRange(protocol=Protocol.TCP, low=1433, high=1433),
    "juniper-rdp": PortRange(protocol=Protocol.TCP, low=3389, high=3389),
    "juniper-smb": PortRange(protocol=Protocol.TCP, low=445, high=445),
    "juniper-vnc": PortRange(protocol=Protocol.TCP, low=5900, high=5900),
    "junos-http": PortRange(protocol=Protocol.TCP, low=80, high=80),
    "junos-https": PortRange(protocol=Protocol.TCP, low=443, high=443),
    "any": PortRange(protocol=Protocol.ANY),
    "any-ipv4": PortRange(protocol=Protocol.ANY),
}

_LOG_LEVELS = {
    "emergencies",
    "alerts",
    "critical",
    "errors",
    "warnings",
    "notifications",
    "informational",
    "debug",
}

#: IKE proposal attributes that CIS / NIST consider too weak.
_WEAK_CRYPTO = re.compile(r"\b(3des|des|blowfish|md5|sha-?1|768|1024|modp?1024)\b", re.I)

#: ``policy from-zone <A> to-zone <B>`` header at the top of ``security policies``.
_POLICY_HDR = re.compile(r"^policy\s+from-zone\s+(\S+)\s+to-zone\s+(\S+)$", re.I)


def _zone_names(zones: dict[str, Any]) -> set[str]:
    """``security-zone trust`` block headers -> ``{"trust"}``."""
    return {h.split(" ", 1)[1].strip() for h in zones if h.startswith("security-zone ") and " " in h}


class JuniperJunosNormalizer(VendorNormalizer):
    vendor: ClassVar[Vendor] = Vendor.JUNIPER_JUNOS
    rule_pack: ClassVar[str] = "cis_junos"
    evidence_precision: ClassVar[Literal["line", "block"]] = "block"

    # ------------------------------------------------------------------ #
    @classmethod
    def supports(cls, raw_text: str) -> float:
        head = raw_text[:5000].lower()
        score = 0.0
        if re.search(r"^\s*##\s*last\s+commit", raw_text, re.M):
            score += 0.5
        if re.search(r"^\s*system\s*\{", raw_text, re.M):
            score += 0.3
        if re.search(r"^\s*(interfaces|security|protocols|routing-options)\s*\{", raw_text, re.M):
            score += 0.2
        if "juniper" in head or "junos" in head:
            score += 0.25
        if re.search(r"^\s*version\s+2\d\.", raw_text, re.M):
            score += 0.15
        if re.search(r"^\s*model:\s*\S+;", raw_text, re.M):
            score += 0.1
        return min(score, 1.0)

    @classmethod
    def priority(cls) -> int:
        return 60

    # ------------------------------------------------------------------ #
    def parse(self, raw_text: str) -> dict[str, Any]:
        tree = split_hier_braces(strip_junos_comments(raw_text))
        sys_tree: dict[str, Any] = tree.get("system", {}) or {}
        sec_tree: dict[str, Any] = tree.get("security", {}) or {}

        ast: dict[str, Any] = {
            "identity": {
                "hostname": sys_tree.get("host-name"),
                "software_version": _version_of(raw_text),
                "model": _model_of(raw_text),
            },
            "interfaces": self._parse_interfaces(tree),
            "zones": [],
            "policies": self._parse_policies(sec_tree),
            "address_book": self._parse_address_book(sec_tree),
            "services": self._parse_services(sys_tree),
            "credentials": self._parse_credentials(sys_tree),
            "logging": self._parse_logging(sys_tree),
            "crypto": self._parse_crypto(sec_tree),
            "routing": self._parse_routing(tree),
            "warnings": [],
        }
        ast["zones"] = sorted(
            _zone_names(sec_tree.get("zones", {}) or {})
            | {z for p in ast["policies"] for z in (p["from_zone"], p["to_zone"]) if z}
        )
        ast["_line_anchor"] = _anchor_lines(raw_text)
        ast["_unparsed_ratio"] = 0.0
        return ast

    # -- AST sections -------------------------------------------------- #
    @staticmethod
    def _parse_interfaces(tree: dict[str, Any]) -> list[dict[str, Any]]:
        """``interfaces <ge-0/0/0> { unit 0 { family inet { address A/P; } } }``

        Block headers are stored verbatim, so both ``unit 0`` and ``family inet``
        appear as single keys.
        """
        out: list[dict[str, Any]] = []
        for ifname, ifdata in (tree.get("interfaces", {}) or {}).items():
            if not isinstance(ifdata, dict):
                continue
            for unit, udata in ifdata.items():
                if not unit.startswith("unit") or not isinstance(udata, dict):
                    continue
                families = {k: v for k, v in udata.items() if k.startswith("family") and isinstance(v, dict)}
                v4 = [
                    str(a)
                    for fam, fdata in families.items()
                    if "inet" in fam and "inet6" not in fam
                    for a in as_list((fdata or {}).get("address"))
                ]
                v6 = [
                    str(a)
                    for fam, fdata in families.items()
                    if "inet6" in fam
                    for a in as_list((fdata or {}).get("address"))
                ]
                if not v4 and not v6:
                    continue
                out.append(
                    {
                        "name": f"{ifname}.{unit.split(' ', 1)[-1] if ' ' in unit else unit}",
                        "ipv4": v4,
                        "ipv6": v6,
                        "description": udata.get("description"),
                        "admin_state": "shutdown" if "disable" in set(udata.get("_flags", [])) else "up",
                        "kind": "routed",
                    }
                )
        return out

    @staticmethod
    def _parse_policies(sec_tree: dict[str, Any]) -> list[dict[str, Any]]:
        """``security policies <from> to <to> <policy-name> { ... }``

        Junos keys both levels by the full header, e.g.
        ``policy from-zone trust to-zone untrust`` then ``policy web-allow``.
        """
        out: list[dict[str, Any]] = []
        for from_hdr, to_map in (sec_tree.get("policies", {}) or {}).items():
            m = _POLICY_HDR.match(from_hdr.strip())
            if not m or not isinstance(to_map, dict):
                continue
            fz = m.group(1)
            for pol_hdr, pdata in to_map.items():
                if not isinstance(pdata, dict) or not pol_hdr.startswith("policy "):
                    continue
                out.append(
                    {
                        "name": pol_hdr.split(" ", 1)[1].strip(),
                        "from_zone": fz,
                        "to_zone": m.group(2),
                        "match": pdata.get("match", {}) or {},
                        "then": pdata.get("then", {}) or {},
                        "disabled": bool(set(pdata.get("_flags", [])) & {"inactive", "disabled"}),
                    }
                )
        return out

    @staticmethod
    def _parse_address_book(sec_tree: dict[str, Any]) -> dict[str, Any]:
        ab = sec_tree.get("access-address", {}) or {}
        return {
            "address": pairs_of(ab.get("address")),
            "address-set": pairs_of(ab.get("address-set")),
        }

    @staticmethod
    def _parse_services(sys_tree: dict[str, Any]) -> dict[str, Any]:
        services = sys_tree.get("services", {}) or {}
        out: dict[str, Any] = {}

        ssh = services.get("ssh", {}) or {}
        if ssh:
            out["ssh"] = {
                "enabled": "disable" not in set(ssh.get("_flags", [])),
                "port": _to_int(ssh.get("port"), 22),
                "root_login": ssh.get("root-login", "deny"),
                "version": ssh.get("protocol-version"),
            }
        telnet = services.get("telnet", {}) or {}
        if telnet:
            out["telnet"] = {
                "enabled": "disable" not in set(telnet.get("_flags", [])),
                "port": _to_int(telnet.get("port"), 23),
                "root_login": telnet.get("root-login"),
            }
        web = services.get("web", {}) or {}
        if web and "disable" not in set(web.get("_flags", [])):
            https_only = str(web.get("https-only", "false")).lower() == "true"
            out["http"] = {
                "enabled": not https_only,
                "port": _to_int(web.get("port"), 80),
                "https_only": https_only,
            }
            if https_only:
                out["https"] = {"enabled": True, "port": _to_int(web.get("https-port"), 443)}
        return out

    @staticmethod
    def _parse_credentials(sys_tree: dict[str, Any]) -> list[dict[str, Any]]:
        """``system login user <name> { ... }``"""
        login = sys_tree.get("login", {}) or {}
        out: list[dict[str, Any]] = []
        for header, udata in login.items():
            if not header.startswith("user ") or not isinstance(udata, dict):
                continue
            out.append(
                {
                    "username": header.split(" ", 1)[1].strip(),
                    "user_class": udata.get("user-class"),
                    "full_name": udata.get("full-name"),
                    "auth_method": next(
                        (
                            k
                            for k in ("encrypted-password", "ssh-rsa", "ssh-dsa", "plain-text-password")
                            if k in udata
                        ),
                        None,
                    ),
                }
            )
        return out

    @staticmethod
    def _parse_logging(sys_tree: dict[str, Any]) -> dict[str, Any]:
        """Syslog appears in two places; both count.

        ``system services syslog host <ip> { <severity>; }`` and
        ``system syslog host <name> <severity> <file>;``
        """
        streams: dict[str, str] = {}
        for header, node in (find(sys_tree, "services", "syslog") or {}).items():
            if not header.startswith("host ") or not isinstance(node, dict):
                continue
            target = header.split(" ", 1)[1].strip()
            severity = next(
                (t.split(" ")[-1] for t in tokens_of(node) if t.split(" ")[-1] in _LOG_LEVELS),
                "info",
            )
            streams[severity] = target
        for key, value in pairs_of(sys_tree.get("syslog")).items():
            if key == "host" and value:
                streams.setdefault("global", str(value).split(" ", 1)[0])
        return {"enabled": bool(streams), "streams": streams}

    @staticmethod
    def _parse_crypto(sec_tree: dict[str, Any]) -> dict[str, Any]:
        """IKE/IPsec proposals, keeping weak primitives for the crypto rules.

        Junos keys proposals by ``proposal <name> { ... }``, so the weak-cipher
        test has to look *inside* each proposal, not at its name.
        """
        ike = sec_tree.get("ike", {}) or {}
        weak: list[str] = []
        names: list[str] = []
        for header, node in ike.items():
            if not header.startswith("proposal") or not isinstance(node, dict):
                continue
            name = header.split(" ", 1)[1].strip()
            names.append(name)
            if _WEAK_CRYPTO.search(" ".join(tokens_of(node))):
                weak.append(name)
        ipsec = sec_tree.get("ipsec", {}) or {}
        return {
            "any_ipsec": bool(ike or ipsec),
            "proposals": names,
            "weak_proposals": weak,
            "phase2": list(ipsec),
        }

    @staticmethod
    def _parse_routing(tree: dict[str, Any]) -> dict[str, Any]:
        static = find(tree, "routing-options", "static") or {}
        static_vals = [str(v) for v in as_list(static.get("route"))]
        return {
            "static_count": len(static_vals),
            "default_route": any(v.startswith("0.0.0.0/0") for v in static_vals),
            "protocols": list(find(tree, "routing-options", "protocols") or {}),
        }

    # ------------------------------------------------------------------ #
    def normalize(self, ast: dict[str, Any]) -> NormalizedConfig:
        cfg = NormalizedConfig(device_id="pending", vendor=self.vendor, role=DeviceRole.FIREWALL)
        cfg.identity = DeviceIdentity(
            hostname=ast.get("identity", {}).get("hostname"),
            software_version=ast.get("identity", {}).get("software_version"),
            model=ast.get("identity", {}).get("model"),
        )
        cfg.unparsed_line_ratio = ast.get("_unparsed_ratio")
        cfg.zones = ast.get("zones", [])

        anchors = ast.get("_line_anchor", {})
        for d in ast.get("interfaces", []):
            ref = SourceRef(line_no=anchors.get("interfaces", 1), raw=f"interfaces {{ {d['name']} }}")
            cfg.interfaces.append(
                Interface(
                    name=d["name"],
                    kind=InterfaceKind(d.get("kind", "routed")),
                    admin_state=AdminState(d.get("admin_state", "up")),
                    description=d.get("description"),
                    ipv4=d.get("ipv4", []),
                    ipv6=d.get("ipv6", []),
                    is_l3=True,
                    source=SourceRefs(refs=[ref]),
                )
            )

        cfg.access_lists = [
            self._norm_policies(ast.get("policies", []), ast.get("address_book", {}), anchors)
        ]
        cfg.services = self._norm_services(ast.get("services", {}), anchors)
        cfg.credentials = [
            CredentialSet(
                username=c["username"],
                role=c.get("user_class"),
                auth_method="local" if c.get("auth_method") else "none",
                is_privileged=c.get("user_class") in {"super-user", "superuser"},
                has_password_set=bool(c.get("auth_method")),
                # Junos `root-authentication encrypted-password` is device-global.
                source_refs=SourceRefs(refs=[SourceRef(line_no=anchors.get("system", 1), raw="system {")]),
            )
            for c in ast.get("credentials", [])
        ]

        logging = ast.get("logging", {})
        cfg.logging = LoggingConfig(
            enabled=logging.get("enabled", False),
            severity_level=next(iter(logging.get("streams", {})), None),
            remote_servers=[make_endpoint(h) for h in set(logging.get("streams", {}).values()) if h],
            source_refs=SourceRefs(refs=[SourceRef(line_no=anchors.get("system", 1), raw="system { syslog")]),
        )

        r = ast.get("routing", {})
        routing_refs = SourceRefs()
        if r.get("default_route"):
            # Anchor on the 'routing-options' line so the evidence points at the
            # stanza that actually creates the default route.
            default_line = anchors.get("routing-options", anchors.get("system", 1))
            routing_refs.add(SourceRef(line_no=default_line, raw="routing-options {"))
        cfg.routing = RoutingConfig(
            static_routes=r.get("static_count", 0),
            default_route_present=r.get("default_route", False),
            dynamic_protocols=r.get("protocols", []),
            source_refs=routing_refs,
        )
        c = ast.get("crypto", {})
        crypto_refs = SourceRefs()
        for proposal in c.get("weak_proposals", []):
            anchor = anchors.get(f"proposal:{proposal}")
            if anchor is not None:
                crypto_refs.add(
                    SourceRef(
                        line_no=anchor,
                        raw=f"proposal {proposal} {{",
                        context=["security ike"],
                    )
                )
        cfg.crypto = CryptoConfig(
            any_ipsec=c.get("any_ipsec", False),
            weak_ciphers=c.get("weak_proposals", []),
            source_refs=crypto_refs,
        )
        cfg.role = DeviceRole.FIREWALL if cfg.zones and cfg.access_lists[0].rules else DeviceRole.ROUTER
        return cfg

    def _norm_policies(
        self, policies: list[dict[str, Any]], address_book: dict[str, Any], anchors: dict[str, int]
    ) -> AccessList:
        addresses: dict[str, Any] = address_book.get("address", {})
        address_sets: dict[str, Any] = address_book.get("address-set", {})

        def resolve(token: str) -> Endpoint:
            """Map a Junos address name (or literal) onto a unified Endpoint."""
            if token in addresses:
                raw = addresses[token]
                return make_endpoint(str(raw)) if isinstance(raw, str) else make_endpoint(token)
            if token in address_sets:
                raw_set = address_sets[token]
                members = as_list(raw_set.get("address"))
                # An address-set containing `any` is effectively unrestricted.
                is_any = any(str(m).lower() == "any" for m in members)
                ep = Endpoint(address=f"addrset:{token}", is_any=is_any)
                ep.fqdn = None
                return ep
            return make_endpoint(token)

        ref = SourceRef(line_no=anchors.get("security", 1), raw="security { policies { ... } }")
        rules: list[AccessRule] = []
        for p in policies:
            match, then = p.get("match", {}), p.get("then", {})
            srcs = [str(s) for s in as_list(match.get("source-address"))] or ["any"]
            dsts = [str(d) for d in as_list(match.get("destination-address"))] or ["any"]
            apps = [str(a) for a in as_list(match.get("application"))] or ["any"]
            then_keys = set(then.keys())
            action = (
                RuleAction.ALLOW
                if any(k == "permit" or k.startswith("permit") for k in then_keys)
                else RuleAction.DENY
            )
            if p.get("disabled"):
                action = RuleAction.DISABLE
            for s in srcs:
                for d in dsts:
                    for a in apps:
                        rules.append(
                            AccessRule(
                                rule_id=p["name"],
                                position=len(rules),
                                source=resolve(s),
                                destination=resolve(d),
                                service=_APPLICATION_PORTS.get(a.lower(), PortRange(protocol=Protocol.ANY)),
                                action=action,
                                logging="log" in then_keys,
                                source_zones=[p["from_zone"]],
                                destination_zones=[p["to_zone"]],
                                application=None if a.lower() == "any" else a,
                                source_refs=SourceRefs(refs=[ref]),
                            )
                        )
        rules.append(
            AccessRule(
                rule_id="__implicit_deny_any__",
                position=len(rules),
                source=make_endpoint("any"),
                destination=make_endpoint("any"),
                service=PortRange(protocol=Protocol.ANY),
                action=RuleAction.DENY,
                is_default=True,
                source_refs=SourceRefs(refs=[ref]),
            )
        )
        return AccessList(
            name="security-policies",
            kind="security-policy",
            vendor=self.vendor,
            direction="zoned",
            rules=rules,
            source_refs=SourceRefs(refs=[ref]),
        )

    @staticmethod
    def _norm_services(services: dict[str, Any], anchors: dict[str, int]) -> list[ServiceBinding]:
        ref = SourceRef(line_no=anchors.get("services", 1), raw="system { services { ... } }")
        out: list[ServiceBinding] = []
        mapping = {
            "ssh": (ManagementService.SSH, Protocol.TCP),
            "telnet": (ManagementService.TELNET, Protocol.TCP),
            "http": (ManagementService.HTTP, Protocol.TCP),
            "https": (ManagementService.HTTPS, Protocol.TCP),
        }
        for key, (svc, proto) in mapping.items():
            data = services.get(key)
            if not data:
                continue
            binding = ServiceBinding(
                service=svc,
                enabled=bool(data.get("enabled", True)),
                version=data.get("version"),
                transport="tcp",
                port=PortRange(protocol=proto, low=data.get("port"), high=data.get("port")),
                # Junos restricts management via `access-limit address ...` or a
                # firewall policy; neither is on this code path, so an unparsed
                # restriction must not be assumed to exist.
                restricted_to=[],
                source_refs=SourceRefs(refs=[ref]),
            )
            if svc is ManagementService.SSH:
                binding.version_notes = f"root-login={data.get('root_login')}"
            out.append(binding)
        return out


# --------------------------------------------------------------------------- #
def _to_int(value: Any, default: int) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _version_of(raw: str) -> str | None:
    m = re.search(r"^\s*version\s+([\w.\-]+)\s*;", raw, re.M)
    return m.group(1) if m else None


def _model_of(raw: str) -> str | None:
    m = re.search(r"^\s*model:\s*([^;]+);", raw, re.M)
    return m.group(1).strip() if m else None


def _anchor_lines(raw_text: str) -> dict[str, int]:
    """First line of each top-level block, used as an evidence anchor.

    Also indexes individual ``proposal <name> {`` lines: ``hier_config`` does not
    expose per-node line numbers, so the raw text is the only reliable way to
    point a weak-crypto finding at the exact proposal.
    """
    anchors: dict[str, int] = {}
    for line_no, line in enumerate(raw_text.splitlines(), start=1):
        m = re.match(r"^\s*(interfaces|security|system|routing-options|protocols)\s*\{", line)
        if m and m.group(1) not in anchors:
            anchors[m.group(1)] = line_no
        if "services {" in line and "services" not in anchors:
            anchors["services"] = line_no
        if p := re.match(r"^\s*proposal\s+(\S+)\s*\{", line):
            anchors.setdefault(f"proposal:{p.group(1)}", line_no)
    return anchors
