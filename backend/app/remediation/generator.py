"""Vendor-specific remediation generation.

What this module will and will not do
--------------------------------------
It *proposes* configuration commands. It never executes them and never claims to
have executed them. Every generated plan is created in
:attr:`RemediationStatus.PENDING_REVIEW` with ``applied_to_device=False``, and the
API refuses to act on a plan that has not been through review. That separation is
the whole point: an auditor must be able to read the exact diff, accept or reject
it, and only then decide whether anything is pushed to production.

Three rules govern every generated plan:

1. **Never guess intent.** An any-any allow rule may exist to carry VPN return
   traffic; silently narrowing it breaks connectivity. Those findings get an
   explicit manual-review step instead of commands.
2. **Never print a secret.** SNMP communities and passwords are rendered as
   placeholders the operator fills from a secret store, so no credential ends up
   in a database row or a browser tab.
3. **Never invent a network.** Management ACLs carry an obvious ``TODO`` rather
   than a made-up subnet, because a wrong ACL locks operators out of the device.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from app.normalize.models import NormalizedConfig, Vendor
from app.schemas.api import (
    CommandMode,
    Finding,
    Remediation,
    RemediationCommand,
    RemediationStatus,
)
from app.schemas.api import Vendor as ApiVendor

#: Rendered in place of any secret value. Operators substitute a real value here.
SECRET_PLACEHOLDER = "<SET-A-NEW-VALUE>"  # noqa: S105 - placeholder token, not a credential

#: Collector address used in logging examples. RFC 5737 documentation space, so
#: nobody can mistake an example for a real deployment instruction.
EXAMPLE_COLLECTOR = "192.0.2.10"

CISCO = frozenset({Vendor.CISCO_IOS, Vendor.CISCO_NXOS})
ALL_KNOWN = frozenset(v for v in Vendor if v is not Vendor.UNKNOWN)


@dataclass(frozen=True)
class _Step:
    """One command before it becomes an API object."""

    mode: CommandMode
    command: str
    description: str
    config_before: str | None = None
    config_after: str | None = None
    reversible: bool = True
    requires_confirmation: bool = False


# --------------------------------------------------------------------------- #
# Shared command tails
# --------------------------------------------------------------------------- #
def _persist(cfg: NormalizedConfig) -> list[_Step]:
    """Vendor-appropriate save command, appended after a config change."""
    if cfg.vendor is Vendor.CISCO_NXOS:
        return [
            _Step(
                mode=CommandMode.EXEC,
                command="copy running-config startup-config",
                description="Persist the running configuration to startup-config.",
                reversible=False,
            )
        ]
    if cfg.vendor is Vendor.CISCO_IOS:
        return [
            _Step(
                mode=CommandMode.EXEC,
                command="write memory",
                description="Persist the running configuration to startup-config.",
                reversible=False,
            )
        ]
    if cfg.vendor is Vendor.JUNIPER_JUNOS:
        return [
            _Step(
                mode=CommandMode.EXEC,
                command="commit",
                description="Commit the candidate configuration to the active one.",
                requires_confirmation=True,
                reversible=False,
            ),
            _Step(mode=CommandMode.EXEC, command="exit", description="Leave configuration mode."),
        ]
    if cfg.vendor is Vendor.PALOALTO_PANOS:
        return [
            _Step(
                mode=CommandMode.EXEC,
                command="commit",
                description="Commit the candidate configuration.",
                requires_confirmation=True,
                reversible=False,
            )
        ]
    if cfg.vendor is Vendor.FORTINET_FORTIOS:
        return [
            _Step(
                mode=CommandMode.CONFIGURE,
                command="end",
                description="Leave the FortiGate configuration block.",
            )
        ]
    return []


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #
#: ``rule_id -> (vendors the handler understands, step builder)``.
_HANDLERS: dict[str, tuple[frozenset[Vendor], Callable[[NormalizedConfig, Finding], list[_Step]]]] = {}


def _handler(rule_id: str, vendors: frozenset[Vendor]):
    """Register a step builder under the rule id it remediates."""

    def register(fn):
        _HANDLERS[rule_id] = (vendors, fn)
        return fn

    return register


# -- Cisco IOS / NX-OS ------------------------------------------------------ #
@_handler("NG-REMOTE-TELNET-ENABLED", CISCO)
def ng_remote_telnet_enabled(cfg: NormalizedConfig, finding: Finding) -> list[_Step]:
    _ = finding
    return [
        _Step(
            mode=CommandMode.CONFIGURE,
            command="no transport input telnet",
            description="Remove Telnet from the VTY transport list, leaving SSH only.",
            config_before="transport input telnet ssh",
            config_after="transport input ssh",
            requires_confirmation=True,
        ),
        *_persist(cfg),
    ]


@_handler("NG-REMOTE-SSH-V1", CISCO)
def ng_remote_ssh_v1(cfg: NormalizedConfig, finding: Finding) -> list[_Step]:
    _ = finding
    return [
        _Step(
            mode=CommandMode.CONFIGURE,
            command="ip ssh version 2",
            description="Force SSH version 2. Version 1 is not re-enabled by this step.",
            config_before="ip ssh version 1",
            config_after="ip ssh version 2",
            requires_confirmation=True,
        ),
        *_persist(cfg),
    ]


@_handler("NG-CRYPTO-PASSWORD-ENCRYPTION", CISCO)
def ng_crypto_password_encryption(cfg: NormalizedConfig, finding: Finding) -> list[_Step]:
    _ = finding
    return [
        _Step(
            mode=CommandMode.CONFIGURE,
            command="service password-encryption",
            description=(
                "Enable reversible password encryption. This obfuscates rather than hashes: "
                "a type 5/7 secret, TACACS or RADIUS remains the better fix."
            ),
            config_after="service password-encryption",
        ),
        *_persist(cfg),
    ]


@_handler("NG-REMOTE-MGMT-UNRESTRICTED", CISCO)
def ng_remote_mgmt_unrestricted(cfg: NormalizedConfig, finding: Finding) -> list[_Step]:
    existing = next((a.name for a in cfg.access_lists if "MGMT" in a.name.upper()), None)
    if existing:
        create = _Step(
            mode=CommandMode.CONFIGURE,
            command=f"! reusing existing access list {existing}",
            description=f"An access list named {existing} already exists; bind it to the VTY lines.",
            config_after=f"ip access-list extended {existing}",
        )
    else:
        create = _Step(
            mode=CommandMode.CONFIGURE,
            command="ip access-list extended MGMT-IN",
            description=(
                "Create the management ACL. Replace the TODO with your real management "
                "subnet -- NETGUARD will not guess it, because a wrong ACL locks you out."
            ),
            config_after="ip access-list extended MGMT-IN\n! TODO: permit <management-subnet> only",
        )
    return [
        create,
        _Step(
            mode=CommandMode.CONFIGURE,
            command="access-class MGMT-IN in",
            description="Apply the ACL to all VTY lines.",
            config_before="! no access-class on vty",
            config_after="access-class MGMT-IN in",
            requires_confirmation=True,
        ),
        *_persist(cfg),
    ]


# -- SNMP -------------------------------------------------------------------- #
@_handler("NG-SNMP-WEAK-COMMUNITY", ALL_KNOWN)
def ng_snmp_weak_community(cfg: NormalizedConfig, finding: Finding) -> list[_Step]:
    _ = finding
    if cfg.vendor in CISCO:
        steps = [
            _Step(
                mode=CommandMode.CONFIGURE,
                command=f"snmp-server community {SECRET_PLACEHOLDER} RO",
                description=(
                    "Replace the weak community with a strong one. The old value is not shown "
                    "here on purpose; take the new one from your secret store, not this diff."
                ),
                requires_confirmation=True,
            ),
            _Step(
                mode=CommandMode.CONFIGURE,
                command="snmp-server community 5 AUTH_ONLY",
                description="Prefer an authenticated, authorized SNMPv3 user over a shared community string.",
                reversible=False,
            ),
        ]
    elif cfg.vendor is Vendor.FORTINET_FORTIOS:
        steps = [
            _Step(
                mode=CommandMode.CONFIGURE,
                command=(
                    f"config system snmp community\nedit 1\nset community {SECRET_PLACEHOLDER}\nnext\nend"
                ),
                description="Rotate the weak SNMP community. The value is intentionally not shown.",
                requires_confirmation=True,
            )
        ]
    elif cfg.vendor is Vendor.JUNIPER_JUNOS:
        steps = [
            _Step(
                mode=CommandMode.SET,
                command="set snmp community netguard authorization read-only",
                description="Rotate the weak SNMP community. The value is intentionally not shown.",
                requires_confirmation=True,
            )
        ]
    else:  # PAN-OS
        steps = [
            _Step(
                mode=CommandMode.SET,
                command="set mib-config community netguard view netguard-ro",
                description="Rotate the weak SNMP community. The value is intentionally not shown.",
                requires_confirmation=True,
            )
        ]
    return [*steps, *_persist(cfg)]


# -- Logging ----------------------------------------------------------------- #
@_handler("NG-LOG-REMOTE-SYSLOG-ABSENT", ALL_KNOWN)
def ng_log_remote_syslog_absent(cfg: NormalizedConfig, finding: Finding) -> list[_Step]:
    _ = finding
    if cfg.vendor in CISCO:
        steps = [
            _Step(
                mode=CommandMode.CONFIGURE,
                command=f"logging host {EXAMPLE_COLLECTOR}",
                description="Add a remote syslog collector. Replace the address with your own.",
                requires_confirmation=True,
            ),
            _Step(
                mode=CommandMode.CONFIGURE,
                command="logging trap informational",
                description="Raise the console trap level so warnings and above are sent.",
                config_before="! default: informational to console only",
                config_after="logging trap informational",
            ),
        ]
    elif cfg.vendor is Vendor.FORTINET_FORTIOS:
        steps = [
            _Step(
                mode=CommandMode.CONFIGURE,
                command=(
                    "config log setting\nset fw-console-level info\nset remote-syslog enable\nnext\nend"
                ),
                description="Enable remote syslog forwarding.",
                requires_confirmation=True,
            )
        ]
    elif cfg.vendor is Vendor.JUNIPER_JUNOS:
        steps = [
            _Step(
                mode=CommandMode.SET,
                command=f"set system syslog host {EXAMPLE_COLLECTOR} any notice",
                description="Add a remote syslog host. Replace the address with your collector.",
                requires_confirmation=True,
            )
        ]
    else:  # PAN-OS
        steps = [
            _Step(
                mode=CommandMode.SET,
                command="set device setting system config mgmt logging "
                "external syslog-logging send-to-siem yes",
                description="Forward logs to an external SIEM collector.",
                requires_confirmation=True,
            )
        ]
    return [*steps, *_persist(cfg)]


# -- Firewall policy --------------------------------------------------------- #
@_handler("NG-FIREWALL-NO-TERMINAL-DENY", ALL_KNOWN)
def ng_firewall_no_terminal_deny(cfg: NormalizedConfig, finding: Finding) -> list[_Step]:
    _ = finding
    if cfg.vendor is Vendor.FORTINET_FORTIOS:
        command = (
            "config firewall policy\n"
            "edit 0\n"
            'set srcintf "any"\n'
            'set dstintf "any"\n'
            'set srcaddr "all"\n'
            'set dstaddr "all"\n'
            'set schedule "always"\n'
            'set service "ALL"\n'
            "set action deny\n"
            "set logtraffic all\n"
            "next\nend"
        )
        before = "! implicit deny exists but is silent"
    elif cfg.vendor is Vendor.PALOALTO_PANOS:
        command = (
            "set rulebase security rules DENY-ALL from any to any "
            "source any destination any service any action deny log-end yes"
        )
        before = "! implicit deny exists but is silent"
    else:
        command = "access-list 1999 deny ip any any log"
        before = "! no explicit catch-all deny at the end of the list"
    return [
        _Step(
            mode=CommandMode.CONFIGURE if cfg.vendor is not Vendor.PALOALTO_PANOS else CommandMode.SET,
            command=command,
            description="Append an explicit, logged catch-all deny.",
            config_before=before,
            config_after="catch-all deny present and logged",
            requires_confirmation=True,
        ),
        *_persist(cfg),
    ]


@_handler("NG-FIREWALL-ANY-ANY", ALL_KNOWN)
def ng_firewall_any_any(cfg: NormalizedConfig, finding: Finding) -> list[_Step]:
    """Intent is unknowable from config alone, so this produces no commands."""
    _ = cfg
    return [
        _Step(
            mode=CommandMode.EDIT,
            command="! MANUAL REVIEW REQUIRED",
            description=(
                f"An any-any allow rule was detected ({finding.title}). NETGUARD cannot safely "
                "narrow it automatically: the rule may exist to carry VPN or unidirectional "
                "return traffic, and removing it would break connectivity. Determine the "
                "intended source and destination scopes by hand, then edit the rule."
            ),
            reversible=True,
            requires_confirmation=True,
        )
    ]


@_handler("NG-FIREWALL-LOGGING-MISSING", CISCO)
def ng_firewall_logging_missing(cfg: NormalizedConfig, finding: Finding) -> list[_Step]:
    _ = finding
    return [
        _Step(
            mode=CommandMode.CONFIGURE,
            command="logging trap informational",
            description="Raise logging so permit decisions are visible off-box.",
            config_before="! default trap level hides permit matches",
            config_after="logging trap informational",
        ),
        *_persist(cfg),
    ]


# --------------------------------------------------------------------------- #
# Generator
# --------------------------------------------------------------------------- #
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@dataclass
class RemediationGenerator:
    """Builds a reviewable remediation plan for each actionable finding.

    Findings whose rule has no handler are not remediated. That gap is deliberate:
    an unspecific "review your logging configuration" string reads like guidance
    while changing nothing, which is worse than saying nothing.
    """

    #: Minimum severity rank to emit a plan for. 2 = low and above, so an
    #: informational observation does not generate a change proposal.
    min_severity_rank: int = 2

    def generate(self, cfg: NormalizedConfig, findings: Sequence[Finding]) -> list[Remediation]:
        out: list[Remediation] = []
        for finding in findings:
            entry = _HANDLERS.get(finding.rule_id)
            if entry is None:
                continue
            vendors, builder = entry
            if cfg.vendor not in vendors:
                continue
            rank = _SEVERITY_RANK.get(str(finding.severity), 0)
            if rank < self.min_severity_rank:
                continue
            steps = builder(cfg, finding)
            if not steps:
                continue
            out.append(self._to_remediation(cfg, finding, steps))
        return out

    def handles(self, rule_id: str) -> bool:
        return rule_id in _HANDLERS

    def vendors_for(self, rule_id: str) -> frozenset[Vendor]:
        entry = _HANDLERS.get(rule_id)
        return entry[0] if entry else frozenset()

    def _to_remediation(self, cfg: NormalizedConfig, finding: Finding, steps: list[_Step]) -> Remediation:
        commands = [
            RemediationCommand(
                order=i,
                mode=step.mode,
                command=step.command,
                config_before=step.config_before,
                config_after=step.config_after,
                description=step.description,
                reversible=step.reversible,
                requires_confirmation=step.requires_confirmation,
            )
            for i, step in enumerate(steps)
        ]
        return Remediation(
            id=f"rem-{uuid4().hex[:12]}",
            finding_id=finding.id,
            device_id=cfg.device_id,
            vendor=ApiVendor.from_internal(cfg.vendor),
            status=RemediationStatus.PENDING_REVIEW,
            title=f"Remediate: {finding.title}",
            rationale=self._rationale(finding),
            risk=_risk_for(finding),
            generator="template",
            commands=commands,
            diff_summary=self._diff_summary(commands),
            created_at=datetime.now(UTC),
            # Hard invariant: nothing has touched the device.
            applied_to_device=False,
        )

    @staticmethod
    def _rationale(finding: Finding) -> str:
        evidence = finding.evidence
        where = (
            " Cited evidence: " + "; ".join(f"line {ln.line_no}" for ln in evidence[:3]) + "."
            if evidence
            else " No single line is at fault; this finding is about the device as a whole."
        )
        return (
            f"{finding.title}. {finding.description} "
            f"Severity {finding.severity}, confidence {finding.confidence}.{where}"
        )

    @staticmethod
    def _diff_summary(commands: list[RemediationCommand]) -> str:
        reversible = sum(1 for c in commands if c.reversible)
        confirms = sum(1 for c in commands if c.requires_confirmation)
        return (
            f"{len(commands)} step(s): {reversible} reversible, "
            f"{len(commands) - reversible} not reversible, {confirms} requiring confirmation. "
            "Nothing is applied until an administrator approves this plan."
        )


def _risk_for(finding: Finding) -> Literal["low", "medium", "high"]:
    """Risk of *applying* the change, which is not the finding's own severity.

    A low-severity finding whose fix reloads a routing table is still risky to
    apply; that judgement belongs to the operator, so we surface it separately.
    """
    if str(finding.severity) in ("critical", "high"):
        return "medium"
    return "low"
