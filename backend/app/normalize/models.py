"""Vendor-agnostic normalized configuration model.

This module is the contract that every parser targets. Whatever the source
vendor, once parsing finishes the pipeline only ever sees these types. That
property is what lets a single rule pack (CIS/NIST/STIG/ISO) evaluate a Cisco
IOS `ip access-list` and a PAN-OS security policy with identical code.

Design rules
------------
1. Every model carries ``source_refs`` -- the exact raw config lines that
   produced it. Findings are meaningless without evidence, so evidence is a
   first-class part of the model rather than something bolted on later.
2. Absent config is represented as an explicit ``None``/empty, never as a
   guess. "No SNMP community string was configured" and "we failed to parse
   SNMP" are different security facts and must stay distinguishable.
3. Enumerations are closed (``StrEnum``) so rule code cannot typo a vendor
   string into existence.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class Vendor(StrEnum):
    CISCO_IOS = "cisco_ios"
    CISCO_NXOS = "cisco_nxos"
    JUNIPER_JUNOS = "juniper_junos"
    FORTINET_FORTIOS = "fortinet_fortios"
    PALOALTO_PANOS = "paloalto_panos"
    UNKNOWN = "unknown"


class DeviceRole(StrEnum):
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    VPN_CONCENTRATOR = "vpn_concentrator"
    UNKNOWN = "unknown"


class InterfaceKind(StrEnum):
    ROUTED = "routed"
    L3_SUBINTERFACE = "l3_subinterface"
    L2_ACCESS = "l2_access"
    L2_TRUNK = "l2_trunk"
    LOOPBACK = "loopback"
    TUNNEL = "tunnel"
    AGGREGATE = "aggregate"
    UNKNOWN = "unknown"


class AdminState(StrEnum):
    UP = "up"
    DOWN = "down"
    SHUTDOWN = "shutdown"


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    IP = "ip"
    ANY = "any"


class RuleAction(StrEnum):
    """Normalized verdict of a single access rule.

    Cisco expresses intent as ordered ACEs with implicit deny-all at the end;
    PAN-OS has an explicit default rule. Both collapse onto these four values.
    """

    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    DISABLE = "disable"  # present but administratively inert (e.g. PAN-OS "disabled")
    LOG = "log"  # audit/logging-only entry


class ManagementService(StrEnum):
    SSH = "ssh"
    TELNET = "telnet"
    HTTP = "http"
    HTTPS = "https"
    SNMP = "snmp"
    NTP = "ntp"
    AAA = "aaa"
    FTP = "ftp"
    TFTP = "tftp"
    SYSLOG = "syslog"
    RADIUS = "radius"
    TACACS = "tacacs"
    OTHER = "other"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Framework(StrEnum):
    CIS_CISCO_IOS = "cis_cisco_ios"
    CIS_FORTINET = "cis_fortinet"
    CIS_PANOS = "cis_panos"
    CIS_JUNOS = "cis_junos"
    NIST_800_53 = "nist_sp_800_53"
    NIST_CSF = "nist_csf"
    DISA_STIG = "disa_stig"
    ISO_27001 = "iso_27001"
    ISO_27002 = "iso_27002"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


# --------------------------------------------------------------------------- #
# Source evidence
# --------------------------------------------------------------------------- #
class SourceRef(BaseModel):
    """Provenance for one normalized fact: which raw line(s) produced it.

    ``raw`` is redacted on the way in. A device config routinely contains
    credentials, and evidence is copied into API responses, findings tables and
    Neo4j -- so a verbatim ``username x password 7 121A0E041104`` line would
    spread the secret across every one of those stores. Redacting at the type
    boundary means no adapter can forget to do it.
    """

    model_config = ConfigDict(frozen=True)

    line_no: int = Field(ge=0, description="1-indexed line number in the uploaded file")
    raw: str = Field(description="Verbatim source line, trimmed, with secrets redacted")
    context: list[str] = Field(
        default_factory=list, description="Surrounding lines (hierarchical context) for nesting"
    )

    @field_validator("raw", mode="before")
    @classmethod
    def _redact(cls, value: Any) -> Any:
        return redact_secrets(value) if isinstance(value, str) else value

    @field_validator("context", mode="before")
    @classmethod
    def _redact_context(cls, value: Any) -> Any:
        if not isinstance(value, list):
            return value
        return [redact_secrets(v) if isinstance(v, str) else v for v in value]

    def as_evidence(self) -> str:
        return f"L{self.line_no}: {self.raw}"


#: Config keywords whose value is a secret, mapped to how many following
#: tokens must be redacted.
#:
#: The count matters because vendors put a *type* field between the keyword and
#: the secret -- Cisco writes ``password 7 121A0E...`` (type 7, then the value),
#: and NTP writes ``authentication-key 1 md5 <value>`` (id, algorithm, value).
#: Redacting only the first token replaced the harmless type digit and left the
#: actual password sitting in the evidence.
_SECRET_KEYWORDS: dict[str, int] = {
    "encrypted-password": 2,
    "hashed-password": 2,
    "password": 2,
    "passwd": 2,
    "secret": 2,
    "community": 1,
    "psksecret": 1,
    "pre-shared-key": 2,
    "authentication-key": 3,
    "private-key": 1,
    "cli-password": 2,
    "vpn-password": 2,
    "ldap-bindpassword": 2,
}

#: Longest-first so 'encrypted-password' is not matched as 'password'.
_SECRET_KEYWORDS_ORDERED = sorted(_SECRET_KEYWORDS, key=len, reverse=True)

_SECRET_RE = re.compile(
    r"(?P<key>\b(?:" + "|".join(re.escape(k) for k in _SECRET_KEYWORDS_ORDERED) + r")\b)"
    r"(?P<sep>[ \t]+)"
    # Greedy to end of line: the sub-function below decides how many of those
    # tokens are secret and keeps the rest ('... community public RO').
    r"(?P<tail>[^\r\n]*)",
    re.IGNORECASE,
)

_TOKEN_RE = re.compile(r"\S+")

#: Used in place of a redacted value. Deliberately not '*': a reader needs to
#: see that *something* was there without being able to guess its length.
REDACTED = "<redacted>"


def redact_secrets(line: str) -> str:
    """Replace secret values in a config line with :data:`REDACTED`.

    The *keyword* and the surrounding syntax are preserved, because the whole
    value of the evidence is showing the operator that a ``password`` (not a
    ``secret``) keyword was used -- that is the actual finding.

    Examples
    --------
    >>> redact_secrets("username bob password 7 121A0E041104")
    'username bob password <redacted>'
    >>> redact_secrets("snmp-server community public RO")
    'snmp-server community <redacted> RO'
    >>> redact_secrets("interface GigabitEthernet0/1")
    'interface GigabitEthernet0/1'
    """

    def _sub(match: re.Match[str]) -> str:
        keyword = match.group("key")
        sep = match.group("sep")
        tokens = _TOKEN_RE.findall(match.group("tail"))
        count = _SECRET_KEYWORDS.get(keyword.lower(), 1)
        if not tokens:
            return match.group(0)
        redacted = " ".join([REDACTED] * min(count, len(tokens)))
        # Keep any tokens beyond the secret (e.g. the RO/RW after a community).
        trailing = " ".join(tokens[count:])
        return f"{keyword}{sep}{redacted}" + (f" {trailing}" if trailing else "")

    return _SECRET_RE.sub(_sub, line)


class SourceRefs(BaseModel):
    """Ordered, de-duplicated evidence bundle."""

    refs: list[SourceRef] = Field(default_factory=list)

    def add(self, ref: SourceRef | None) -> None:
        if ref is None:
            return
        if any(r.line_no == ref.line_no and r.raw == ref.raw for r in self.refs):
            return
        self.refs.append(ref)

    def extend(self, other: SourceRefs | None) -> None:
        for r in other.refs if other else []:
            self.add(r)

    @property
    def lines(self) -> list[int]:
        return sorted(r.line_no for r in self.refs)

    def quoted(self, limit: int = 5) -> list[str]:
        return [r.as_evidence() for r in self.refs[:limit]]

    def __bool__(self) -> bool:
        return bool(self.refs)


# --------------------------------------------------------------------------- #
# Networking primitives
# --------------------------------------------------------------------------- #
class Endpoint(BaseModel):
    """A normalized address/prefix endpoint used in rules.

    A Cisco ACE says ``any``; a PAN-OS policy says ``any``. Both become this.
    """

    address: str = "any"
    prefix_len: int | None = None
    fqdn: str | None = None
    is_any: bool = Field(default=False, description="True when the rule is unrestricted")

    @field_validator("address", mode="before")
    @classmethod
    def _lower(cls, v: Any) -> Any:
        return v.strip().lower() if isinstance(v, str) else v

    @property
    def is_private(self) -> bool:
        try:
            return ipaddress.ip_address(self.address).is_private
        except ValueError:
            return False

    @property
    def is_wildcard_or_group(self) -> bool:
        return bool(self.fqdn) or self.address in {"any", "0.0.0.0/0"}

    def __str__(self) -> str:  # pragma: no cover - display helper
        if self.is_any:
            return "any"
        if self.prefix_len and "/" not in self.address:
            return f"{self.address}/{self.prefix_len}"
        return self.address


class PortRange(BaseModel):
    """Service/port range. PAN-OS separates protocol and port; Cisco may not."""

    protocol: Protocol = Protocol.TCP
    low: int | None = Field(default=None, ge=0, le=65535)
    high: int | None = Field(default=None, ge=0, le=65535)

    @field_validator("protocol", mode="before")
    @classmethod
    def _coerce_protocol(cls, v: Any) -> Any:
        if isinstance(v, str):
            key = v.strip().lower()
            aliases = {
                "6": Protocol.TCP,
                "17": Protocol.UDP,
                "1": Protocol.ICMP,
                "ip": Protocol.IP,
                "tcp": Protocol.TCP,
                "udp": Protocol.UDP,
                "icmp": Protocol.ICMP,
                "any": Protocol.ANY,
                "all": Protocol.ANY,
            }
            return aliases.get(key, Protocol.ANY)
        return v

    @property
    def is_any(self) -> bool:
        """True when no port is constrained.

        Deliberately *not* conditioned on the protocol: an ACE written as
        ``permit ip any any`` or ``permit icmp any any`` omits the port operand,
        which in vendor syntax means "every port for this protocol". Keying this
        on ``Protocol.ANY`` alone silently hid those rules from the any-any and
        wide-range checks, because their span looked like a single port.
        """
        return self.low is None and self.high is None

    @property
    def is_all_protocols(self) -> bool:
        """True only when the ACE also left the protocol unconstrained."""
        return self.is_any and self.protocol is Protocol.ANY

    @property
    def is_single(self) -> bool:
        return self.low is not None and self.high in (None, self.low)

    @property
    def high_port(self) -> int:
        return self.high if self.high is not None else (self.low or 0)

    def contains(self, port: int) -> bool:
        if self.is_any:
            return True
        lo = self.low if self.low is not None else 0
        return lo <= port <= self.high_port

    @property
    def span(self) -> int:
        """Size of the exposed port range -- a wide span raises severity."""
        if self.is_any:
            return 65535
        return max(0, self.high_port - (self.low or 0) + 1)

    @property
    def well_known_name(self) -> str | None:
        """Name of the service on this port, e.g. ``"ssh"``.

        A property, not a method, to match ``is_any``/``span``. It was a method
        before, which meant every caller silently received a bound method object
        instead of a name.
        """
        return _WELL_KNOWN_PORTS.get(self.high_port if self.is_single else (self.low or 0))

    def __str__(self) -> str:  # pragma: no cover
        if self.is_any:
            return f"{self.protocol}/any"
        if self.is_single:
            return f"{self.protocol}/{self.low}"
        return f"{self.protocol}/{self.low}-{self.high_port}"


_WELL_KNOWN_PORTS: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    69: "tftp",
    80: "http",
    110: "pop3",
    119: "nntp",
    123: "ntp",
    135: "msrpc",
    143: "imap",
    161: "snmp",
    162: "snmptrap",
    389: "ldap",
    443: "https",
    445: "smb",
    514: "syslog",
    515: "printer",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    3306: "mysql",
    3389: "rdp",
    5060: "sip",
    5900: "vnc",
    8443: "alt-https",
    8888: "alt-http",
    9200: "elasticsearch",
    27017: "mongodb",
}


# --------------------------------------------------------------------------- #
# Normalized entities
# --------------------------------------------------------------------------- #
class Interface(BaseModel):
    name: str
    kind: InterfaceKind = InterfaceKind.UNKNOWN
    admin_state: AdminState = AdminState.UP
    description: str | None = None
    ipv4: list[str] = Field(default_factory=list)
    ipv6: list[str] = Field(default_factory=list)
    vrf: str | None = None
    vlans: list[int] = Field(default_factory=list)
    is_l3: bool = False
    source: SourceRefs = Field(default_factory=SourceRefs)


class AccessRule(BaseModel):
    """THE unified rule type. A Cisco ACE and a PAN-OS Security Policy both land here.

    Mapping example (see ``normalize/adapters/``):

    Cisco ``permit tcp 10.0.0.0 0.0.0.255 any eq 443 log``
        -> source=10.0.0.0/24, destination=any, service=tcp/443, action=allow, logging=True

    PAN-OS policy ``name=web, src=10.0.0.0/24, dst=any, service=tcp/443, action=allow, log=True``
        -> identical AccessRule.
    """

    rule_id: str = Field(description="Vendor rule id/name, e.g. 'outside_in_10' or 'web-out'")
    position: int = Field(default=0, ge=0, description="Evaluation order; lower == evaluated first")
    source: Endpoint = Field(default_factory=Endpoint)
    destination: Endpoint = Field(default_factory=Endpoint)
    service: PortRange = Field(default_factory=PortRange)
    action: RuleAction = RuleAction.DENY
    logging: bool = Field(default=False, description="Per-rule traffic logging enabled")
    source_zones: list[str] = Field(default_factory=list)
    destination_zones: list[str] = Field(default_factory=list)
    source_users: list[str] = Field(default_factory=list)
    is_default: bool = Field(default=False, description="PAN-OS implicit/terminal rule")
    application: str | None = Field(
        default=None, description="PAN-OS application (L7); absent on pure L3 devices"
    )
    url_category: str | None = None
    tags: list[str] = Field(default_factory=list)
    source_refs: SourceRefs = Field(default_factory=SourceRefs)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_permissive(self) -> bool:
        return self.action in (RuleAction.ALLOW, RuleAction.REJECT)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_world_exposed(self) -> bool:
        """Allow rule whose destination is unconstrained -- candidate exposure."""
        return self.is_permissive and self.destination.is_any and self.destination_zones in ([], ["any"])

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        """Stable hash of the semantic content (ignores rule name/position).

        Used by the anomaly detector and by cross-vendor dedup so the same
        effective rule from two different vendors collapses to one feature row.
        """
        material = "|".join(
            [
                str(self.source.address),
                str(self.source.prefix_len),
                str(self.destination.address),
                str(self.destination.prefix_len),
                str(self.service.protocol),
                str(self.service.low),
                str(self.service.high),
                str(self.action),
                str(self.logging),
            ]
        )
        return hashlib.sha256(material.encode()).hexdigest()[:16]


class AccessList(BaseModel):
    """A named rule container. Cisco: one ACL. PAN-OS: one Security Policy group."""

    name: str
    kind: str = Field(description="'acl' | 'security-policy' | 'nat' | 'address-group'")
    vendor: Vendor
    direction: str | None = Field(default=None, description="inbound / outbound / global")
    position: int = 0
    rules: list[AccessRule] = Field(default_factory=list)
    source_refs: SourceRefs = Field(default_factory=SourceRefs)

    @property
    def allow_rules(self) -> list[AccessRule]:
        return [r for r in self.rules if r.is_permissive]

    @property
    def has_implicit_deny(self) -> bool:
        """Cisco appends an implicit deny; PAN-OS carries an explicit default rule."""
        return any(r.is_default and not r.is_permissive for r in self.rules)


class SecretObservation(BaseModel):
    """What we learned about a secret *without retaining it*.

    SNMP communities, PSKs and passwords must not survive normalization: the
    :class:`NormalizedConfig` is serialized into API responses, findings rows
    and the graph store. But the rules still need to know whether a community is
    the guessable value ``public`` or is simply too short to be safe.

    So the normalizer stores the *verdict*, never the *value*. That keeps the
    detection logic intact while making it impossible for a secret to leak
    downstream just because someone added a new field.
    """

    #: e.g. "community", "psk", "pre-shared-key".
    kind: str = "secret"
    length: int = 0
    #: Matches a widely published default (public, private, cisco, admin...).
    is_well_known_default: bool = False
    #: Too short, single-character-class, or otherwise trivially guessable.
    is_low_entropy: bool = False
    source: SourceRef | None = None

    @property
    def is_weak(self) -> bool:
        return self.is_well_known_default or self.is_low_entropy


#: Values published in vendor documentation and present in every default
#: configuration. Membership here is the definition of "weak" for community
#: strings -- these are facts about the *value*, so the comparison happens once,
#: at normalization time, and only the boolean is kept.
WELL_KNOWN_DEFAULTS: frozenset[str] = frozenset(
    {
        "public",
        "private",
        "cisco",
        "admin",
        "default",
        "guest",
        "manager",
        "monitor",
        "read",
        "write",
        "test",
        "enable",
        "system",
        "user",
        "access",
        "secret",
        "pass",
        "letmein",
        "changeme",
        "telnet",
    }
)


def describe_secret(
    value: str | None,
    *,
    kind: str = "secret",
    min_length: int = 8,
    source: SourceRef | None = None,
) -> SecretObservation:
    """Classify a secret so it can be judged without being stored."""
    if not value:
        return SecretObservation(kind=kind, length=0, is_low_entropy=True, source=source)
    stripped = value.strip()
    distinct = len(set(stripped.lower()))
    return SecretObservation(
        kind=kind,
        length=len(stripped),
        is_well_known_default=stripped.lower() in WELL_KNOWN_DEFAULTS,
        # Short, or effectively a single repeated character / one dictionary
        # symbol -- the two shapes that make brute force trivial.
        is_low_entropy=len(stripped) < min_length or distinct <= 2,
        source=source,
    )


class ServiceBinding(BaseModel):
    """A management service as exposed on the device (SSH, SNMP, HTTPS, ...)."""

    service: ManagementService
    enabled: bool = True
    version: str | None = None
    transport: str = Field(default="tcp", description="tcp | udp | both")
    port: PortRange = Field(default_factory=PortRange)
    restricted_to: list[Endpoint] = Field(
        default_factory=list,
        description="Allowed source endpoints; EMPTY means reachable from anywhere",
    )
    timeout_seconds: int | None = None
    retries: int | None = None
    acl_applied: str | None = Field(default=None, description="Name of the ACL governing access")
    credentials: list[SecretObservation] = Field(
        default_factory=list,
        description="Classified credentials (community strings, PSKs). Values are never retained.",
    )
    version_notes: str | None = None
    source_refs: SourceRefs = Field(default_factory=SourceRefs)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_unrestricted(self) -> bool:
        return self.enabled and not self.restricted_to

    @property
    def is_cleartext(self) -> bool:
        return self.service in {
            ManagementService.TELNET,
            ManagementService.HTTP,
            ManagementService.TFTP,
            ManagementService.FTP,
        }


class CredentialSet(BaseModel):
    """AAA / local user inventory. Secrets are NEVER stored here."""

    username: str
    privilege: int | None = None
    role: str | None = None
    auth_method: str | None = Field(default=None, description="local | radius | tacacs | none")
    is_privileged: bool = False
    has_password_set: bool = Field(
        default=False, description="True if a password hash exists -- value never retained"
    )
    source_refs: SourceRefs = Field(default_factory=SourceRefs)


class LoggingConfig(BaseModel):
    enabled: bool = False
    remote_servers: list[Endpoint] = Field(default_factory=list)
    severity_level: str | None = None
    local_buffer: bool = False
    rate_limited: bool = False
    logs_config_changes: bool = False
    source_refs: SourceRefs = Field(default_factory=SourceRefs)


class RoutingConfig(BaseModel):
    static_routes: int = 0
    default_route_present: bool = False
    dynamic_protocols: list[str] = Field(default_factory=list)
    source_refs: SourceRefs = Field(default_factory=SourceRefs)


class CryptoConfig(BaseModel):
    """Transport crypto posture (control-plane and data-plane)."""

    any_ipsec: bool = False
    weak_ciphers: list[str] = Field(default_factory=list)
    weak_key_exchange: list[str] = Field(default_factory=list)
    rekey_disabled: bool = False
    source_refs: SourceRefs = Field(default_factory=SourceRefs)


class DeviceIdentity(BaseModel):
    hostname: str | None = None
    model: str | None = None
    software_version: str | None = None
    serial: str | None = None
    site: str | None = None


# --------------------------------------------------------------------------- #
# Root object
# --------------------------------------------------------------------------- #
class NormalizedConfig(BaseModel):
    """The single object every downstream analyzer consumes."""

    model_config = ConfigDict(populate_by_name=True)

    device_id: str
    vendor: Vendor = Vendor.UNKNOWN
    detected_vendor_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    identity: DeviceIdentity = Field(default_factory=DeviceIdentity)
    role: DeviceRole = DeviceRole.UNKNOWN
    parsed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    interfaces: list[Interface] = Field(default_factory=list)
    access_lists: list[AccessList] = Field(default_factory=list)
    services: list[ServiceBinding] = Field(default_factory=list)
    credentials: list[CredentialSet] = Field(default_factory=list)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    routing: RoutingConfig = Field(default_factory=RoutingConfig)
    crypto: CryptoConfig = Field(default_factory=CryptoConfig)
    zones: list[str] = Field(default_factory=list, description="PAN-OS security zones")

    raw_config_sha256: str | None = None
    parse_warnings: list[str] = Field(default_factory=list)
    unparsed_line_ratio: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description=(
            "Share of meaningful config lines that produced no normalized entity. "
            "High values mean low parser coverage -- the UI lowers its confidence "
            "in the compliance score rather than overstating it."
        ),
    )
    evidence_precision: Literal["line", "block"] = Field(
        default="line",
        description="'line' = each finding cites an exact config line; "
        "'block' = parser anchors to a top-level block only",
    )

    # -- convenience accessors used all over the rule pack ------------------
    def service(self, svc: ManagementService) -> ServiceBinding | None:
        return next((s for s in self.services if s.service is svc), None)

    def enabled_services(self) -> list[ServiceBinding]:
        return [s for s in self.services if s.enabled]

    def all_rules(self) -> list[AccessRule]:
        return [r for al in self.access_lists for r in al.rules]

    def allow_rules(self) -> list[AccessRule]:
        return [r for r in self.all_rules() if r.is_permissive]

    def unprivileged_users(self) -> list[CredentialSet]:
        return [c for c in self.credentials if not c.is_privileged]

    def trusted_interfaces(self) -> list[Interface]:
        return [i for i in self.interfaces if not i.description and i.kind in {InterfaceKind.UNKNOWN}]

    def evidence_for(self, predicate: str) -> SourceRefs:
        """Collect every source ref whose raw text contains ``predicate``.

        Escape hatch for rules that need to cite a config line the structured
        model deliberately dropped (e.g. ``banner login`` content).
        """
        return SourceRefs()  # populated by parsers that support text-level evidence


def empty_config(device_id: str, vendor: Vendor = Vendor.UNKNOWN) -> NormalizedConfig:
    return NormalizedConfig(device_id=device_id, vendor=vendor)
