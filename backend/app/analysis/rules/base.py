"""Rule engine: declarative security checks over a :class:`NormalizedConfig`.

A rule is a small pure function that answers one question about a normalized
device and, if the answer is "bad", produces a :class:`RuleOutcome` carrying
evidence. Rules never touch the database, never do I/O, and never depend on
another rule's result -- which makes them trivially unit-testable and safe to
run in parallel.

Design decisions worth knowing
------------------------------
* **Framework mapping is data, not code.** Each outcome names its controls via
  :data:`CONTROL_CATALOG`, so adding a new framework (STIG, ISO 27002) is a
  data change rather than a new engine.
* **Vendor gating.** A rule declares ``applies_to``; a telnet check simply does
  not run against a PAN-OS config where ``transport input`` does not exist.
* **Not-applicable is a real outcome.** :attr:`OutcomeState.NOT_APPLICABLE` keeps
  a Cisco SSH rule from dragging down a FortiGate's score, because a control
  that does not apply should not count as a failure.
* **No duplicate reporting.** :func:`RuleEngine.execute` dedupes by ``rule_id``
  keeping the highest severity, so a broad rule and a specific one cannot both
  shout about the same line.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, ClassVar
from uuid import uuid4

from app.normalize.models import (
    NormalizedConfig,
    Severity,
    SourceRefs,
    Vendor,
)
from app.schemas.api import ControlRef, Detector, EvidenceLine, Finding, Framework
from app.schemas.api import Severity as ApiSeverity


class OutcomeState(StrEnum):
    PASS = "pass"  # noqa: S105 - enum literal, not a credential
    FAIL = "fail"
    NOT_APPLICABLE = "not_applicable"
    #: Config was too incomplete to judge -- counts against coverage, not score.
    INDETERMINATE = "indeterminate"


@dataclass(slots=True)
class RuleOutcome:
    """What a single rule concluded about one device."""

    state: OutcomeState
    rule_id: str
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: float = 0.9
    evidence: SourceRefs = field(default_factory=SourceRefs)
    affected: list[str] = field(default_factory=list)
    control_ids: list[str] = field(default_factory=list)
    detector: Detector = Detector.RULE
    cvss_score: float | None = None
    #: Free-form extras the pipeline forwards (e.g. rule parameters for remediation).
    params: dict[str, Any] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.state is OutcomeState.FAIL


def fail(
    rule_id: str,
    title: str,
    *,
    description: str = "",
    severity: Severity = Severity.MEDIUM,
    confidence: float = 0.9,
    evidence: SourceRefs | None = None,
    affected: Iterable[str] = (),
    control_ids: Iterable[str] = (),
    cvss_score: float | None = None,
    detector: Detector = Detector.RULE,
    **params: Any,
) -> RuleOutcome:
    """Terse constructor for a failing outcome -- the common case."""
    return RuleOutcome(
        state=OutcomeState.FAIL,
        rule_id=rule_id,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        evidence=evidence or SourceRefs(),
        affected=list(affected),
        control_ids=list(control_ids),
        detector=detector,
        cvss_score=cvss_score,
        params=params,
    )


def passed(rule_id: str, *, control_ids: Iterable[str] = ()) -> RuleOutcome:
    return RuleOutcome(state=OutcomeState.PASS, rule_id=rule_id, control_ids=list(control_ids))


def not_applicable(rule_id: str) -> RuleOutcome:
    return RuleOutcome(state=OutcomeState.NOT_APPLICABLE, rule_id=rule_id)


# --------------------------------------------------------------------------- #
# Control catalogue
# --------------------------------------------------------------------------- #
#: Published control IDs -> (Framework, title, description). Populated from
#: ``db/seed/control_catalog.json`` at import time in the real deployment; kept
#: inline here so the engine runs with zero external dependencies.
CONTROL_CATALOG: dict[str, ControlRef] = {
    "CIS-CISCO-1.1.1": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="1.1.1",
        title="Enable SSH version 2",
        description="SSHv1 is vulnerable to session and key-exchange attacks; CIS requires ip ssh version 2.",
    ),
    "CIS-CISCO-1.1.2": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="1.1.2",
        title="Configure SSH ciphers and MAC algorithms",
    ),
    "CIS-CISCO-1.2.1": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="1.2.1",
        title="Restrict TTY and line vty access / disable Telnet",
    ),
    "CIS-CISCO-1.2.8": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="1.2.8",
        title="Configure login authentication on vty lines",
    ),
    "CIS-CISCO-1.2.10": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="1.2.10",
        title="Set exec-timeout on vty lines",
    ),
    "CIS-CISCO-1.3.1": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="1.3.1",
        title="Enable SNMPv3 (auth+priv) and disable v1/v2c communities",
    ),
    "CIS-CISCO-4.1.1": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="4.1.1",
        title="Enable logging to a remote syslog server",
    ),
    "CIS-CISCO-4.1.2": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="4.1.2",
        title="Enable critical log messages to be logged immediately",
    ),
    "CIS-CISCO-4.2.1": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="4.2.1",
        title="Enable configuration change logging",
    ),
    "CIS-CISCO-4.6.1": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="4.6.1",
        title="Enable service password-encryption",
    ),
    "CIS-CISCO-5.2.1": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="5.2.1",
        title="Do not configure a default route on the device when not required",
    ),
    "CIS-CISCO-5.4.1": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="5.4.1",
        title="Restrict access to sensitive files / privileged users",
    ),
    "CIS-CISCO-6.1.1": ControlRef(
        framework=Framework.CIS_CISCO_IOS,
        control_id="6.1.1",
        title="Create a banner with a legal warning",
    ),
    # ---- NIST SP 800-53 Rev. 5 --------------------------------------- #
    "NIST-AC-2": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="AC-2",
        title="Account Management",
        description="Managers shall establish, document and enforce an account management process.",
    ),
    "NIST-AC-3": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="AC-3",
        title="Access Enforcement",
        description="Enforce approved authorizations for logical access to information and system resources.",
    ),
    "NIST-AC-4": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="AC-4",
        title="Information Flow Enforcement",
        description="Enforce approved authorizations for controlling the flow of information.",
    ),
    "NIST-AC-17": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="AC-17",
        title="Remote Access Control",
    ),
    "NIST-AC-12": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="AC-12",
        title="Session Termination / Automatic Session Lock",
    ),
    "NIST-AU-2": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="AU-2",
        title="Event Logging",
    ),
    "NIST-AU-6": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="AU-6",
        title="Audit Record Review, Analysis and Reporting",
    ),
    "NIST-AU-9": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="AU-9",
        title="Protection of Audit Information",
    ),
    "NIST-CM-6": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="CM-6",
        title="Configuration Settings",
        description="Establish and document configuration settings using security configuration checklists.",
    ),
    "NIST-CM-7": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="CM-7",
        title="Least Functionality",
    ),
    "NIST-IA-2": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="IA-2",
        title="Identification and Authentication (Organizational Users)",
    ),
    "NIST-IA-5": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="IA-5",
        title="Authenticator Management",
    ),
    "NIST-SC-7": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="SC-7",
        title="Boundary Protection",
        description="Monitor and control communications at the external boundary of the system.",
    ),
    "NIST-SC-8": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="SC-8",
        title="Transmission Confidentiality and Integrity",
    ),
    "NIST-SC-13": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="SC-13",
        title="Cryptographic Protection",
    ),
    "NIST-CP-9": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="CP-9",
        title="System Backup",
    ),
    # ---- DISA STIG (Juniper SRX / Network Device STIG) ------------------ #
    "STIG-SRX-1": ControlRef(
        framework=Framework.DISA_STIG,
        control_id="SRX-6-00001",
        title="Ensure the 'SSH Access' service is disabled if not required",
    ),
    "STIG-SRX-2": ControlRef(
        framework=Framework.DISA_STIG,
        control_id="SRX-6-00021",
        title="Ensure 'root login' is disabled for SSH",
    ),
    "STIG-SRX-3": ControlRef(
        framework=Framework.DISA_STIG,
        control_id="SRX-6-00113",
        title="Ensure a firewall filter is applied to all interfaces",
    ),
    "STIG-NET-1": ControlRef(
        framework=Framework.DISA_STIG,
        control_id="NET-00001",
        title="Ensure 'Telnet' service is disabled",
    ),
    "STIG-NET-2": ControlRef(
        framework=Framework.DISA_STIG,
        control_id="NET-00004",
        title="Ensure 'HTTP' service is disabled (use HTTPS)",
    ),
    # ---- ISO 27001:2022 / 27002:2022 ----------------------------------- #
    "ISO-A.5.15": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.5.15",
        title="Access control",
    ),
    "ISO-A.5.17": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.5.17",
        title="Authentication information",
    ),
    "ISO-A.5.18": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.5.18",
        title="Access rights",
    ),
    "ISO-A.5.23": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.5.23",
        title="Information security for use of cloud services",
    ),
    "ISO-A.5.25": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.5.25",
        title="Assessment and decision on information security events",
    ),
    "ISO-A.5.28": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.5.28",
        title="Collection of evidence",
    ),
    "ISO-A.8.2": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.8.2",
        title="Privileged access rights",
    ),
    "ISO-A.8.5": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.8.5",
        title="Secure authentication",
    ),
    "ISO-A.8.9": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.8.9",
        title="Configuration management",
    ),
    "ISO-A.8.12": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.8.12",
        title="Data leakage prevention",
    ),
    "ISO-A.8.15": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.8.15",
        title="Logging",
    ),
    "ISO-A.8.20": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.8.20",
        title="Networks security",
    ),
    "ISO-A.8.22": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.8.22",
        title="Segregation of networks",
    ),
    "ISO-A.8.24": ControlRef(
        framework=Framework.ISO_27001,
        control_id="A.8.24",
        title="Use of cryptography",
    ),
    # ---- Fortinet / PAN-OS CIS ----------------------------------------- #
    "CIS-FGT-1": ControlRef(
        framework=Framework.CIS_FORTINET,
        control_id="6.2.1",
        title="Restrict administrative access to trusted hosts",
    ),
    "CIS-FGT-2": ControlRef(
        framework=Framework.CIS_FORTINET,
        control_id="5.2.5",
        title="Disable Telnet administration",
    ),
    "CIS-FGT-3": ControlRef(
        framework=Framework.CIS_FORTINET,
        control_id="7.1.1",
        title="Enable logging of configuration changes",
    ),
    "CIS-FGT-4": ControlRef(
        framework=Framework.CIS_FORTINET,
        control_id="7.2.1",
        title="Restrict administrative access to a trusted management network",
    ),
    "CIS-FGT-5": ControlRef(
        framework=Framework.CIS_FORTINET,
        control_id="6.1.1",
        title="Disable unused administrative services",
    ),
    "CIS-FGT-6": ControlRef(
        framework=Framework.CIS_FORTINET,
        control_id="14.1.1",
        title="Restrict SNMP v1/v2c communities and use SNMPv3",
    ),
    "CIS-PAN-1": ControlRef(
        framework=Framework.CIS_PANOS,
        control_id="8.1.1",
        title="Do not permit any-as-any security policy rules",
    ),
    "CIS-PAN-2": ControlRef(
        framework=Framework.CIS_PANOS,
        control_id="10.1.1",
        title="Ensure Telnet management access is disabled",
    ),
    "CIS-PAN-3": ControlRef(
        framework=Framework.CIS_PANOS,
        control_id="9.2.1",
        title="Enable logging of traffic and threat sessions",
    ),
    "CIS-PAN-4": ControlRef(
        framework=Framework.CIS_PANOS,
        control_id="10.2.1",
        title="Restrict management access to a trusted zone",
    ),
    "CIS-PAN-5": ControlRef(
        framework=Framework.CIS_PANOS,
        control_id="10.12.1",
        title="Use application-level (L7) policy rather than any/any",
    ),
    "CIS-PAN-6": ControlRef(
        framework=Framework.CIS_PANOS,
        control_id="8.1.7",
        title="Do not use overly permissive service objects in security policy",
    ),
    # ---- Vendor-agnostic boundary / lateral movement -------------------- #
    "NG-FIREWALL-ANY-ANY": ControlRef(
        framework=Framework.NIST_800_53,
        control_id="SC-7",
        title="No any-to-any allow rule",
    ),
}


# --------------------------------------------------------------------------- #
# Rule base
# --------------------------------------------------------------------------- #
class SecurityRule(ABC):
    """One compliance check.

    Subclasses set the class attributes and implement :meth:`evaluate`.
    """

    rule_id: ClassVar[str]
    title: ClassVar[str]
    description: ClassVar[str] = ""
    severity: ClassVar[Severity] = Severity.MEDIUM
    confidence: ClassVar[float] = 0.9
    control_ids: ClassVar[tuple[str, ...]] = ()
    applies_to: ClassVar[frozenset[Vendor]] = frozenset(v for v in Vendor if v is not Vendor.UNKNOWN)
    #: When True the rule also runs against a config we could not attribute to a
    #: vendor, so an unknown device still gets generic hygiene checks.
    run_on_unknown_vendor: ClassVar[bool] = False
    cvss_score: ClassVar[float | None] = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        for required in ("rule_id", "title"):
            if not getattr(cls, required, None):
                raise TypeError(f"{cls.__name__} must define {required!r}")

    @abstractmethod
    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        """Inspect a normalized config.

        Return ``None`` for "nothing to report", otherwise a list -- one entry per
        verdict, because most rules legitimately produce several findings (one per
        exposed service, per violating ACE, per undocumented interface). Always
        wrap even a single outcome in a list so every rule honours one contract.
        """

    # -- helpers available to subclasses --------------------------------
    def controls(self) -> list[ControlRef]:
        out: list[ControlRef] = []
        for cid in self.control_ids:
            ref = CONTROL_CATALOG.get(cid)
            if ref is None:
                # Unknown control IDs must not silently vanish; surface them.
                out.append(ControlRef(framework=Framework.NIST_800_53, control_id=cid, title=self.title))
            else:
                out.append(ref)
        return out

    def supports(self, cfg: NormalizedConfig) -> bool:
        if cfg.vendor is Vendor.UNKNOWN:
            return self.run_on_unknown_vendor
        return cfg.vendor in self.applies_to


RuleFn = Callable[[NormalizedConfig], RuleOutcome | list[RuleOutcome] | None]


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
class RuleEngine:
    """Runs a set of rules and turns outcomes into findings."""

    def __init__(self, rules: Iterable[SecurityRule], *, evidence_limit: int = 6) -> None:
        self._rules = list(rules)
        self.evidence_limit = evidence_limit

    @property
    def rules(self) -> list[SecurityRule]:
        return list(self._rules)

    @property
    def rule_ids(self) -> list[str]:
        return [r.rule_id for r in self._rules]

    def execute(self, cfg: NormalizedConfig, *, analysis_id: str) -> tuple[list[Finding], list[RuleOutcome]]:
        """Evaluate every applicable rule.

        Returns ``(findings, outcomes)``. Outcomes are kept (not just failures)
        because the compliance scorer needs pass/not-applicable counts.
        """
        collected: list[RuleOutcome] = []
        for rule in self._rules:
            if not rule.supports(cfg):
                collected.append(not_applicable(rule.rule_id))
                continue
            try:
                result = rule.evaluate(cfg)
            except Exception as exc:  # noqa: BLE001 - one bad rule must not kill the scan
                collected.append(
                    RuleOutcome(
                        state=OutcomeState.INDETERMINATE,
                        rule_id=rule.rule_id,
                        title=rule.title,
                        confidence=0.0,
                        params={"error": f"{type(exc).__name__}: {exc}"},
                    )
                )
                continue

            if result is None:
                continue
            for outcome in result:
                outcome.control_ids = outcome.control_ids or list(rule.control_ids)
                if not outcome.title:
                    outcome.title = rule.title
                if not outcome.description:
                    outcome.description = rule.description or rule.__doc__ or ""
                if outcome.severity is Severity.INFO:
                    outcome.severity = rule.severity
                if outcome.confidence == 0.9:
                    outcome.confidence = rule.confidence
                if outcome.cvss_score is None:
                    outcome.cvss_score = rule.cvss_score
                collected.append(outcome)

        deduped = _dedupe(collected)
        findings = self.outcomes_to_findings(cfg, deduped, analysis_id=analysis_id)
        return findings, deduped

    def outcomes_to_findings(
        self, cfg: NormalizedConfig, outcomes: Iterable[RuleOutcome], *, analysis_id: str
    ) -> list[Finding]:
        """Convert a complete outcome set into findings, most severe first.

        Separate from :meth:`execute` because the ML stage appends outcomes after
        the rules have run. Without this, anomaly findings would exist in the
        outcome list -- and therefore move the compliance score -- while never
        reaching the dashboard. Ordering lives here so both callers agree.
        """
        failures = [o for o in _dedupe(list(outcomes)) if o.failed]
        # Most severe first, then by rule id for a stable order across runs --
        # the dashboard renders this list directly and must not reshuffle.
        failures.sort(key=lambda o: (-internal_rank(o.severity), o.rule_id))
        return [self.to_finding(o, cfg=cfg, analysis_id=analysis_id) for o in failures]

    def to_finding(self, outcome: RuleOutcome, *, cfg: NormalizedConfig, analysis_id: str) -> Finding:
        return Finding(
            id=f"fnd_{uuid4().hex[:16]}",
            analysis_id=analysis_id,
            device_id=cfg.device_id,
            rule_id=outcome.rule_id,
            title=outcome.title,
            description=outcome.description,
            explanation=explain(outcome, cfg),
            severity=ApiSeverity.from_internal(outcome.severity),
            confidence=round(min(max(outcome.confidence, 0.0), 1.0), 3),
            category=category_for(outcome.rule_id),
            controls=self._resolve_controls(outcome, cfg.vendor),
            evidence=[
                EvidenceLine(line_no=r.line_no, raw=r.raw)
                for r in outcome.evidence.refs[: self.evidence_limit]
            ],
            evidence_precision=cfg.evidence_precision,
            affected_objects=outcome.affected,
            detector=outcome.detector,
            cvss_score=outcome.cvss_score,
            created_at=datetime.now(UTC),
        )

    @staticmethod
    def _resolve_controls(outcome: RuleOutcome, vendor: Vendor) -> list[ControlRef]:
        """Catalogue entries for an outcome, filtered to the device's frameworks.

        Filtering here (not just at scoring time) keeps the finding payload and
        the score in agreement -- a finding must never claim a Fortinet control
        on a Cisco device, and a score must never be dragged by one.
        """
        out: list[ControlRef] = []
        for cid in outcome.control_ids:
            ref = CONTROL_CATALOG.get(cid)
            if ref is None:
                # Unknown control IDs must not silently vanish; surface them.
                out.append(ControlRef(framework=Framework.NIST_800_53, control_id=cid, title=outcome.title))
            elif framework_applies_to(ref.framework, vendor):
                out.append(ref)
        return out


# --------------------------------------------------------------------------- #
# Framework -> vendor relevance
# --------------------------------------------------------------------------- #
#: Which device families each framework can meaningfully be scored against.
#:
#: This exists because one rule legitimately maps to several frameworks at once
#: (``TelnetEnabled`` cites both CIS Cisco 1.2.1 and CIS FortiGate 5.2.5, since
#: they say the same thing about different vendors). Without this map, a Cisco
#: switch was reported as 5.88% compliant with the *Fortinet* benchmark -- a
#: number that is meaningless and, worse, actively misleading to an auditor.
#: Vendor-agnostic frameworks (NIST, ISO, DISA generic) apply everywhere.
ALL_KNOWN_VENDORS: frozenset[Vendor] = frozenset(v for v in Vendor if v is not Vendor.UNKNOWN)
FRAMEWORK_VENDOR_SCOPE: dict[Framework, frozenset[Vendor]] = {
    Framework.CIS_CISCO_IOS: frozenset({Vendor.CISCO_IOS}),
    Framework.CIS_NXOS: frozenset({Vendor.CISCO_NXOS}),
    Framework.CIS_FORTINET: frozenset({Vendor.FORTINET_FORTIOS}),
    Framework.CIS_PANOS: frozenset({Vendor.PALOALTO_PANOS}),
    Framework.CIS_JUNOS: frozenset({Vendor.JUNIPER_JUNOS}),
    Framework.NIST_800_53: ALL_KNOWN_VENDORS,
    Framework.ISO_27001: ALL_KNOWN_VENDORS,
    Framework.DISA_STIG: frozenset({Vendor.JUNIPER_JUNOS, Vendor.CISCO_IOS, Vendor.CISCO_NXOS}),
}


def framework_applies_to(framework: Framework, vendor: Vendor) -> bool:
    """True when ``framework`` can be scored against a ``vendor`` device."""
    scope = FRAMEWORK_VENDOR_SCOPE.get(framework)
    if scope is None:
        return True  # Unknown/new framework: stay permissive, never silently drop.
    return vendor in scope


def applicable_frameworks(vendor: Vendor) -> list[Framework]:
    """Frameworks worth showing for this device, in a stable display order."""
    return [f for f in Framework if framework_applies_to(f, vendor)]


def _dedupe(outcomes: list[RuleOutcome]) -> list[RuleOutcome]:
    """Collapse outcomes that report the same rule, keeping the strongest.

    Without this, ``NG-FIREWALL-ANY-ANY`` (which emits one outcome per any-any
    rule) and a more specific rule would both fire on the same config line.
    """
    best: dict[str, RuleOutcome] = {}
    order: list[str] = []
    for o in outcomes:
        current = best.get(o.rule_id)
        if current is None:
            best[o.rule_id] = o
            order.append(o.rule_id)
            continue
        if internal_rank(o.severity) > internal_rank(current.severity):
            best[o.rule_id] = o
    return [best[rid] for rid in order]


def internal_rank(sev: Severity) -> int:
    from app.normalize.models import SEVERITY_ORDER

    return SEVERITY_ORDER.get(sev, 0)


_CATEGORY_BY_PREFIX = {
    "NG-REMOTE": "Remote Access",
    "NG-CRED": "Credential Management",
    "NG-LOG": "Logging & Audit",
    "NG-FIREWALL": "Firewall Policy",
    "NG-CRYPTO": "Cryptography",
    "NG-INFRA": "Network Infrastructure",
    "NG-SNMP": "SNMP",
    "CIS-": "Benchmark Compliance",
    "STIG-": "STIG Compliance",
    "NIST-": "NIST Compliance",
    "ISO-": "ISO Compliance",
}


def category_for(rule_id: str) -> str:
    for prefix, label in _CATEGORY_BY_PREFIX.items():
        if rule_id.startswith(prefix):
            return label
    return "General"


# --------------------------------------------------------------------------- #
# Plain-language explanations
# --------------------------------------------------------------------------- #
_IMPACT_LIBRARY: dict[str, str] = {
    "NG-REMOTE-TELNET-ENABLED": (
        "Telnet sends your login and password in clear text over the network. Anyone on the same "
        "segment -- or any router in between -- can capture them and take over this device. "
        "Replacing it with SSH encrypts the session so credentials cannot be read or replayed."
    ),
    "NG-REMOTE-SSH-V1": (
        "This device still negotiates SSH version 1, whose key exchange and session integrity are "
        "cryptographically broken. An attacker on the path can decrypt or tamper with an admin "
        "session. SSH version 2 removes that exposure."
    ),
    "NG-REMOTE-MGMT-UNRESTRICTED": (
        "The administrative service is reachable from any source address, so the whole internet can "
        "attempt logins. Restricting it to a management or jump-host network shrinks the attack "
        "surface to a handful of hosts you control."
    ),
    "NG-CRED-WEAK-PASSWORD-TYPE": (
        "Some local accounts use reversible or plaintext password storage. If the config file is ever "
        "copied, backed up or disclosed, these passwords can be recovered immediately. Use the "
        "irreversible 'secret' keyword instead."
    ),
    "NG-CRED-PRIVILEGE-15-SHARED": (
        "A single account holds full administrative privilege. Any compromise of that one account "
        "gives complete control of the device with no separation of duties and no way to attribute "
        "the change to a specific engineer."
    ),
    "NG-SNMP-WEAK-COMMUNITY": (
        "SNMP is using a well-known or guessable community string over SNMPv1/v2c. Those strings are "
        "effectively a shared password sent in clear text, so anyone who captures one packet can "
        "reconfigure or map the device. SNMPv3 with authentication and privacy avoids this."
    ),
    "NG-LOG-REMOTE-SYSLOG-ABSENT": (
        "Logs stay on the device. If it is compromised or fails, the evidence is gone with it. "
        "Forwarding to a remote syslog server puts the audit trail somewhere an attacker does not "
        "control."
    ),
    "NG-FIREWALL-ANY-ANY": (
        "This rule permits all traffic from any source to any destination. It effectively disables "
        "segmentation, so a single compromised host can reach every other host and the internet. "
        "Replace it with rules that name the specific zones, addresses and services that are needed."
    ),
    "NG-FIREWALL-WIDE-PORT-RANGE": (
        "A broad low-numbered port range is permitted through the firewall. Ports below 1024 include "
        "many legacy services with known flaws, so this widens the exploitable surface considerably "
        "for what is usually a small number of intended services."
    ),
    "NG-CRYPTO-WEAK-IKE": (
        "The IPsec proposal uses deprecated cryptography. These primitives are broken or "
        "impractical to brute force, so a determined attacker can decrypt captured VPN traffic. "
        "Move to AES-256 with a modern authentication hash and Diffie-Hellman group 14 or higher."
    ),
    "NG-CRYPTO-PASSWORD-ENCRYPTION": (
        "The device is not encrypting stored passwords. Plaintext 'password' entries are readable by "
        "anyone who obtains the config file, unlike 'secret' entries which are hashed."
    ),
}


def explain(outcome: RuleOutcome, cfg: NormalizedConfig) -> str:
    """Produce a plain-language impact statement for a finding.

    Rules may supply their own ``description``; otherwise we fall back to a
    library keyed by rule id, then to a generic-but-honest sentence. We never
    fabricate a rationale we do not have.
    """
    if outcome.params.get("explanation"):
        return str(outcome.params["explanation"])
    if outcome.rule_id in _IMPACT_LIBRARY:
        return _IMPACT_LIBRARY[outcome.rule_id]
    if outcome.description:
        return outcome.description
    objects = ", ".join(outcome.affected[:3]) or "the device"
    return (
        f"{outcome.title} was detected on {objects} "
        f"({cfg.identity.hostname or cfg.device_id}, {cfg.vendor.value}). "
        "Refer to the linked control for the required configuration."
    )
