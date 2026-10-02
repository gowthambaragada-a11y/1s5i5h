"""Firewall and access-rule policy rules.

This is where the unified model pays off: a Cisco ``ip access-list`` and a
PAN-OS Security Policy are compared with the same code, because both arrive as
``list[AccessRule]`` with the same semantics (ordered, implicit/terminal deny).
"""

from __future__ import annotations

from app.analysis.rules.base import RuleOutcome, SecurityRule, fail, passed
from app.normalize.models import (
    AccessRule,
    NormalizedConfig,
    PortRange,
    RuleAction,
    Severity,
    SourceRefs,
    Vendor,
)


def _rules_of(cfg: NormalizedConfig) -> list[AccessRule]:
    """All rules across all access lists, excluding terminal/implicit denies."""
    return [r for r in cfg.all_rules() if not r.is_default]


class AnyAnyAllow(SecurityRule):
    """The single most important network security control after patching."""

    rule_id = "NG-FIREWALL-ANY-ANY"
    title = "Rule permits all traffic from any source to any destination"
    description = (
        "An any-to-any allow rule disables segmentation. CIS PAN-OS 8.1.1, NIST SC-7 and "
        "ISO A.8.22 all require traffic to be authorized by zone, address and service."
    )
    severity = Severity.CRITICAL
    confidence = 0.96
    cvss_score = 9.4
    control_ids = ("CIS-PAN-1", "NIST-SC-7", "NIST-AC-4", "ISO-A.8.22", "ISO-A.8.20")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        offenders = [
            r
            for r in _rules_of(cfg)
            if r.action is RuleAction.ALLOW
            and r.source.is_any
            and r.destination.is_any
            and (r.service.is_any or r.service.span > 1000)
        ]
        if not offenders:
            return [passed(self.rule_id, control_ids=self.control_ids)]

        worst = offenders[0]
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                cvss_score=self.cvss_score,
                evidence=_merge_refs(offenders),
                affected=[f"rule:{r.rule_id}" for r in offenders[:10]],
                control_ids=self.control_ids,
                rule_names=[r.rule_id for r in offenders[:10]],
                service=worst.service.well_known_name or str(worst.service),
            )
        ]


class UnrestrictedInterfaceExposure(SecurityRule):
    """An allow rule whose destination is unconstrained is candidate exposure."""

    rule_id = "NG-FIREWALL-UNRESTRICTED-DESTINATION"
    title = "Permit rule leaves the destination unconstrained"
    description = (
        "Destination any with an allow action publishes whichever services happen to be listening "
        "on the protected segment, now and in future."
    )
    severity = Severity.HIGH
    confidence = 0.7
    cvss_score = 7.5
    control_ids = ("NIST-SC-7", "CIS-PAN-5", "ISO-A.8.22")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        offenders = [
            r
            for r in _rules_of(cfg)
            if r.action is RuleAction.ALLOW
            and r.destination.is_any
            and not (r.source.is_any and r.destination.is_any)
        ]
        if not offenders:
            return [passed(self.rule_id, control_ids=self.control_ids)]
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                evidence=_merge_refs(offenders),
                affected=[f"rule:{r.rule_id}" for r in offenders[:10]],
                control_ids=self.control_ids,
                rule_names=[r.rule_id for r in offenders[:10]],
            )
        ]


class WidePortRange(SecurityRule):
    """Allowing all of TCP/1-1024 is far broader than any real requirement."""

    rule_id = "NG-FIREWALL-WIDE-PORT-RANGE"
    title = "Rule permits an entire low-numbered port range"
    description = (
        "Ports 1-1024 include many legacy and weakly-protected services. A requirement is almost "
        "always for a handful of named services, not the entire range."
    )
    severity = Severity.HIGH
    confidence = 0.9
    cvss_score = 7.3
    control_ids = ("CIS-PAN-6", "NIST-CM-7", "NIST-SC-7", "ISO-A.8.20")

    #: A range spanning more than this many ports is treated as "wide".
    WIDE_SPAN = 200

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        offenders = [
            r
            for r in _rules_of(cfg)
            if r.action is RuleAction.ALLOW and not r.service.is_any and r.service.span > self.WIDE_SPAN
        ]
        if not offenders:
            return [passed(self.rule_id, control_ids=self.control_ids)]
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                evidence=_merge_refs(offenders),
                affected=[f"rule:{r.rule_id}" for r in offenders[:10]],
                control_ids=self.control_ids,
                rule_names=[r.rule_id for r in offenders[:10]],
                ranges=[str(r.service) for r in offenders[:10]],
            )
        ]


class RemoteAdminServicesExposed(SecurityRule):
    """RDP/SMB/database ports opened from anywhere are near-universal findings."""

    rule_id = "NG-FIREWALL-REMOTE-ADMIN-EXPOSED"
    title = "Remote administration service is permitted from any source"
    description = (
        "Management protocols such as RDP, SMB, WinRM and database ports must never be reachable "
        "from untrusted zones; CIS and NIST AC-17 require them behind a bastion."
    )
    severity = Severity.CRITICAL
    confidence = 0.93
    cvss_score = 9.1
    control_ids = ("NIST-AC-17", "NIST-SC-7", "ISO-A.5.15")

    EXPOSED_PORTS: dict[int, str] = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        5900: "VNC",
        1433: "MSSQL",
        3306: "MySQL",
        5432: "PostgreSQL",
        27017: "MongoDB",
        445: "SMB",
        139: "NetBIOS",
        5985: "WinRM",
        5986: "WinRM-TLS",
        1521: "Oracle",
        9200: "Elasticsearch",
        6379: "Redis",
    }

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome]:
        out: list[RuleOutcome] = []
        for r in _rules_of(cfg):
            if r.action is not RuleAction.ALLOW or not r.service.is_single:
                continue
            service_name = self.EXPOSED_PORTS.get(r.service.low or -1)
            if not service_name:
                continue
            # Destination may be scoped while the source is fully open; both are
            # risky, but "any source AND any destination" is reported by the
            # any-any rule, so skip the exact duplicate here.
            if r.source.is_any and r.destination.is_any:
                continue
            out.append(
                fail(
                    self.rule_id,
                    f"{service_name} is permitted to {r.destination}",
                    description=self.description,
                    severity=self.severity,
                    confidence=self.confidence,
                    evidence=_merge_refs([r]),
                    affected=[f"rule:{r.rule_id}"],
                    control_ids=self.control_ids,
                    service=service_name,
                    port=r.service.low,
                    source=str(r.source),
                    destination=str(r.destination),
                    rule_name=r.rule_id,
                )
            )
        return out


class DenyAllMissing(SecurityRule):
    """Without a terminal deny, traffic falls off the end of the rule list."""

    rule_id = "NG-FIREWALL-NO-TERMINAL-DENY"
    title = "Access list has no terminal deny rule"
    description = (
        "A Cisco ACL denies implicitly, but a PAN-OS/FortiOS policy set without an explicit "
        "any-any deny may fall through to a default action you did not intend."
    )
    severity = Severity.MEDIUM
    confidence = 0.65
    control_ids = ("CIS-PAN-1", "NIST-SC-7", "ISO-A.8.22")
    applies_to = frozenset({Vendor.PALOALTO_PANOS, Vendor.FORTINET_FORTIOS, Vendor.JUNIPER_JUNOS})

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome]:
        out: list[RuleOutcome] = []
        for acl in cfg.access_lists:
            if not acl.rules or acl.has_implicit_deny:
                continue
            out.append(
                fail(
                    self.rule_id,
                    f"Access list '{acl.name}' has no terminal deny",
                    description=self.description,
                    severity=self.severity,
                    confidence=self.confidence,
                    evidence=acl.source_refs,
                    affected=[f"acl:{acl.name}"],
                    control_ids=self.control_ids,
                    acl_name=acl.name,
                )
            )
        return out


class DeadRule(SecurityRule):
    """A permit rule completely shadowed by an earlier permit is dead weight.

    Dead rules are not vulnerabilities, but they inflate apparent coverage and
    hide the rules that actually matter -- which is exactly how a real ACL goes
    unmaintained. CIS 8.1.x and NIST CM-6 both require reviewing rule intent.
    """

    rule_id = "NG-FIREWALL-SHADOWED-RULE"
    title = "Rule is unreachable because an earlier rule already matches it"
    description = (
        "An earlier permit covers this rule's source, destination and service, so this rule can "
        "never be evaluated. Editors changing it get a false sense of effect."
    )
    severity = Severity.LOW
    confidence = 0.55
    control_ids = ("NIST-CM-6", "NIST-CM-7", "CIS-PAN-1", "ISO-A.8.9")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome]:
        out: list[RuleOutcome] = []
        for acl in cfg.access_lists:
            seen: list[AccessRule] = []
            for rule in acl.rules:
                if rule.is_default or rule.action is not RuleAction.ALLOW:
                    continue
                if any(_covers(prev, rule) for prev in seen):
                    out.append(
                        fail(
                            self.rule_id,
                            f"Rule '{rule.rule_id}' is shadowed by an earlier permit",
                            description=self.description,
                            severity=self.severity,
                            confidence=self.confidence,
                            evidence=_merge_refs([rule]),
                            affected=[f"rule:{rule.rule_id}"],
                            control_ids=self.control_ids,
                            rule_name=rule.rule_id,
                            acl_name=acl.name,
                        )
                    )
                else:
                    seen.append(rule)
        return out


class LoggingDisabledOnPermit(SecurityRule):
    rule_id = "NG-FIREWALL-LOGGING-MISSING"
    title = "Permit rule does not log matching traffic"
    description = (
        "CIS requires session logging for allowed traffic so that data-exfiltration paths are "
        "reconstructable during an investigation."
    )
    severity = Severity.MEDIUM
    confidence = 0.8
    control_ids = ("CIS-PAN-3", "NIST-AU-2", "NIST-AU-6", "ISO-A.8.15")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome] | None:
        permits = [r for r in _rules_of(cfg) if r.action is RuleAction.ALLOW]
        if not permits:
            return None
        unlogged = [r for r in permits if not r.logging]
        if not unlogged:
            return [passed(self.rule_id, control_ids=self.control_ids)]
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                # A single unlogged rule among many is lower severity than a blanket gap.
                confidence=self.confidence,
                evidence=_merge_refs(unlogged),
                affected=[f"rule:{r.rule_id}" for r in unlogged[:10]],
                control_ids=self.control_ids,
                rule_names=[r.rule_id for r in unlogged[:10]],
                unlogged_count=len(unlogged),
                total_permits=len(permits),
            )
        ]


class DisabledRuleWithAllowAction(SecurityRule):
    """A disabled allow rule is fine; a *disabled deny* is a silent gap."""

    rule_id = "NG-FIREWALL-DISABLED-RULE"
    title = "Disabled policy rule leaves an unintended gap in enforcement"
    description = (
        "A rule disabled for troubleshooting but never re-enabled silently reverts to the default "
        "action. STIG and NIST CM-6 require disabled rules be tracked and reviewed."
    )
    severity = Severity.MEDIUM
    confidence = 0.6
    control_ids = ("NIST-CM-6", "CIS-PAN-1", "ISO-A.8.9")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome]:
        out: list[RuleOutcome] = []
        for r in cfg.all_rules():
            if r.action is RuleAction.DISABLE:
                out.append(
                    fail(
                        self.rule_id,
                        f"Rule '{r.rule_id}' is disabled",
                        description=self.description,
                        severity=self.severity,
                        confidence=self.confidence,
                        evidence=_merge_refs([r]),
                        affected=[f"rule:{r.rule_id}"],
                        control_ids=self.control_ids,
                        rule_name=r.rule_id,
                    )
                )
        return out


class UnusedInterfaceAddressing(SecurityRule):
    """Interfaces with an address but no description are an audit-trail gap."""

    rule_id = "NG-INFRA-UNDOCUMENTED-INTERFACE"
    title = "Active interface has no description"
    description = (
        "Undocumented interfaces make incident triage and change review slow, and are a CIS "
        "recommendation across switching and routing baselines."
    )
    severity = Severity.INFO
    confidence = 0.9
    control_ids = ("CIS-CISCO-6.1.1", "NIST-CM-6", "ISO-A.8.9")

    def evaluate(self, cfg: NormalizedConfig) -> list[RuleOutcome]:
        from app.normalize.models import AdminState, InterfaceKind

        undocumented = [
            i
            for i in cfg.interfaces
            if i.admin_state is AdminState.UP
            and i.kind not in {InterfaceKind.LOOPBACK}
            and not (i.description or "").strip()
        ]
        if not undocumented:
            return [passed(self.rule_id, control_ids=self.control_ids)]
        return [
            fail(
                self.rule_id,
                self.title,
                description=self.description,
                severity=self.severity,
                confidence=self.confidence,
                evidence=_merge_iface_refs(undocumented),
                affected=[f"interface:{i.name}" for i in undocumented[:20]],
                control_ids=self.control_ids,
                interface_names=[i.name for i in undocumented[:20]],
            )
        ]


# --------------------------------------------------------------------------- #
def _covers(outer: AccessRule, inner: AccessRule) -> bool:
    """True when ``outer`` already matches everything ``inner`` would.

    Only handles the safe cases (outer broader than inner). Deliberately
    conservative: a false "not covered" costs one redundant finding, a false
    "covered" hides a live rule.
    """
    if outer.action is not inner.action:
        return False
    if not (_addr_covers(outer.source, inner.source) and _addr_covers(outer.destination, inner.destination)):
        return False
    return _service_covers(outer.service, inner.service)


def _addr_covers(outer, inner) -> bool:

    if outer.is_any:
        return True
    if inner.is_any:
        return False
    if outer.address != inner.address:
        # Named groups (fog, addrset, addrgroup) cannot be compared precisely.
        return False
    outer_len = outer.prefix_len or 32
    inner_len = inner.prefix_len or 32
    return outer_len <= inner_len


def _service_covers(outer: PortRange, inner: PortRange) -> bool:
    if outer.is_any:
        return True
    if inner.is_any:
        return False
    if outer.protocol is not inner.protocol:
        # `any` on either side is the only cross-protocol case we can trust.
        return False
    if outer.low is None:
        return True
    if inner.low is None:
        return False
    return outer.low <= inner.low and outer.high_port >= inner.high_port


def _merge_refs(rules: list[AccessRule]) -> SourceRefs:
    refs = SourceRefs()
    for r in rules:
        refs.extend(r.source_refs)
    return refs


def _merge_iface_refs(interfaces: list) -> SourceRefs:
    refs = SourceRefs()
    for i in interfaces:
        refs.extend(i.source)
    return refs
