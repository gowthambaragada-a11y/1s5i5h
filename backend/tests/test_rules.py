"""Rule engine and compliance scoring tests.

Two invariants are load-bearing and asserted throughout:

1. **No rule raises.** A rule that throws is recorded as INDETERMINATE, which is
   easy to miss because the scan still "succeeds". Silent degradation is worse
   than a visible failure in a security tool.
2. **Every finding is cited.** A finding with no evidence is unfalsifiable and
   unusable by an operator, so the UI has to be able to hide or flag it.
"""

from __future__ import annotations

import pytest

from app.analysis.rule_packs import ALL_RULES, control_index, rules_for_vendor
from app.analysis.rules.base import CONTROL_CATALOG, OutcomeState, category_for, framework_applies_to
from app.normalize.models import Severity, Vendor

pytestmark = pytest.mark.usefixtures("configs")


# --------------------------------------------------------------------------- #
# Engine mechanics
# --------------------------------------------------------------------------- #
class TestEngineMechanics:
    def test_no_rule_raises_on_any_sample(self, any_config, run_rules):
        """A rule that raises would silently vanish from the report."""
        findings, outcomes = run_rules(any_config)
        indeterminate = [o for o in outcomes if o.state is OutcomeState.INDETERMINATE]
        assert not indeterminate, f"{any_config.vendor}: rules raised -> " + ", ".join(
            f"{o.rule_id} ({o.params.get('error')})" for o in indeterminate
        )

    def test_every_finding_carries_evidence(self, any_config, run_rules):
        findings, _ = run_rules(any_config)
        for f in findings:
            assert f.evidence, f"{f.rule_id} produced a finding with no evidence"

    def test_evidence_lines_are_cited_and_valid(self, any_config, run_rules):
        """Evidence line numbers must exist and fall inside the uploaded file.

        ``line_no`` is a 1-based index into the real file, so a value of 0 means
        "we never resolved the anchor" and must fail here rather than in the UI.
        """
        _, outcomes = run_rules(any_config)
        for o in outcomes:
            for ref in o.evidence.refs:
                assert ref.line_no > 0, f"{o.rule_id} cited line 0: {ref.raw!r}"

    def test_findings_are_sorted_by_severity(self, any_config, run_rules):
        from app.schemas.api import Severity as ApiSeverity

        order = {
            ApiSeverity.CRITICAL: 0,
            ApiSeverity.HIGH: 1,
            ApiSeverity.MEDIUM: 2,
            ApiSeverity.LOW: 3,
            ApiSeverity.INFO: 4,
        }
        findings, _ = run_rules(any_config)
        ranks = [order[f.severity] for f in findings]
        assert ranks == sorted(ranks), "findings must be ordered most-severe first"

    def test_rule_ids_are_unique(self):
        ids = [r.rule_id for r in ALL_RULES]
        dupes = {i for i in ids if ids.count(i) > 1}
        assert not dupes, f"duplicate rule ids: {dupes}"

    def test_every_rule_declares_known_controls(self):
        for cls in ALL_RULES:
            for cid in cls.control_ids:
                assert cid in CONTROL_CATALOG, f"{cls.rule_id} cites unknown control {cid}"

    def test_every_rule_declares_at_least_one_control(self):
        """A finding with no control cannot be tracked to a compliance gap."""
        for cls in ALL_RULES:
            assert cls.control_ids, f"{cls.rule_id} declares no control_ids"

    def test_every_rule_has_a_category(self):
        for cls in ALL_RULES:
            assert category_for(cls.rule_id) != "General", f"{cls.rule_id} has no category"

    def test_engine_deduplicates_by_rule_id(self, any_config, run_rules):
        _, outcomes = run_rules(any_config)
        ids = [o.rule_id for o in outcomes]
        assert len(ids) == len(set(ids)), "duplicate outcomes for one rule"

    def test_execute_is_deterministic(self, any_config, engine):
        first, _ = engine.execute(any_config, analysis_id="an-1")
        second, _ = engine.execute(any_config, analysis_id="an-1")
        assert {f.rule_id for f in first} == {f.rule_id for f in second}


# --------------------------------------------------------------------------- #
# Vendor gating
# --------------------------------------------------------------------------- #
class TestVendorGating:
    def test_inapplicable_rules_are_marked_not_applicable(self, panos, run_rules):
        _, outcomes = run_rules(panos)
        na = {o.rule_id for o in outcomes if o.state is OutcomeState.NOT_APPLICABLE}
        assert "NG-REMOTE-NO-EXEC-TIMEOUT" in na, "an IOS exec-timeout rule ran against PAN-OS"

    def test_not_applicable_rules_do_not_produce_findings(self, panos, run_rules):
        findings, outcomes = run_rules(panos)
        na = {o.rule_id for o in outcomes if o.state is OutcomeState.NOT_APPLICABLE}
        assert not (na & {f.rule_id for f in findings}), "a not-applicable rule also reported a finding"

    def test_rules_for_vendor_respects_applies_to(self):
        cisco_ids = {r.rule_id for r in rules_for_vendor(Vendor.CISCO_IOS)}
        panos_ids = {r.rule_id for r in rules_for_vendor(Vendor.PALOALTO_PANOS)}
        assert cisco_ids != panos_ids, "vendor scoping has no effect"
        assert "NG-REMOTE-NO-EXEC-TIMEOUT" in cisco_ids
        assert "NG-REMOTE-NO-EXEC-TIMEOUT" not in panos_ids


# --------------------------------------------------------------------------- #
# Specific rule behaviour
# --------------------------------------------------------------------------- #
class TestManagementRules:
    def test_telnet_is_flagged_where_enabled(self, any_config, run_rules):
        from app.normalize.models import ManagementService

        telnet = any_config.service(ManagementService.TELNET)
        findings, _ = run_rules(any_config)
        ids = {f.rule_id for f in findings}
        if telnet is not None and telnet.enabled:
            assert "NG-REMOTE-TELNET-ENABLED" in ids, f"{any_config.vendor} missed its own Telnet"
        else:
            assert "NG-REMOTE-TELNET-ENABLED" not in ids

    def test_ssh_v1_only_applies_to_cisco(self, panos, run_rules):
        """PAN-OS has no configurable SSH version.

        Reporting 'SSH version unspecified' as a high-severity failure on every
        PAN-OS device would be a false positive that erodes trust in the report.
        """
        findings, outcomes = run_rules(panos)
        assert "NG-REMOTE-SSH-V1" not in {f.rule_id for f in findings}
        state = next(o.state for o in outcomes if o.rule_id == "NG-REMOTE-SSH-V1")
        assert state in {OutcomeState.NOT_APPLICABLE, OutcomeState.PASS}

    def test_ssh_v2_passes_on_cisco(self, cisco, run_rules):
        _, outcomes = run_rules(cisco)
        state = next(o.state for o in outcomes if o.rule_id == "NG-REMOTE-SSH-V1")
        assert state is OutcomeState.PASS, "config says 'ip ssh version 2' but the rule failed"

    def test_weak_community_is_detected_without_leaking_it(self, cisco, run_rules):
        findings, _ = run_rules(cisco)
        snmp = next((f for f in findings if f.rule_id == "NG-SNMP-WEAK-COMMUNITY"), None)
        assert snmp is not None, "the sample uses community 'public' and must be flagged"
        assert snmp.severity is not None
        blob = str(snmp.model_dump())
        assert "public" not in blob.lower().replace("publicly", ""), "community value leaked into the finding"

    def test_exec_timeout_is_read_from_the_vty_block(self, cisco, run_rules):
        """The sample sets 'exec-timeout 5 0' under 'line vty'."""
        _, outcomes = run_rules(cisco)
        state = next(o.state for o in outcomes if o.rule_id == "NG-REMOTE-NO-EXEC-TIMEOUT")
        assert state is OutcomeState.PASS

    def test_default_route_finding_cites_the_route(self, cisco, run_rules):
        findings, _ = run_rules(cisco)
        route = next((f for f in findings if f.rule_id == "NG-INFRA-DEFAULT-ROUTE"), None)
        assert route is not None
        assert any("0.0.0.0" in e.raw for e in route.evidence)  # noqa: S104 - default-route citation


class TestFirewallRules:
    def test_any_any_is_detected_on_cisco(self, cisco, run_rules):
        findings, _ = run_rules(cisco)
        match = next((f for f in findings if f.rule_id == "NG-FIREWALL-ANY-ANY"), None)
        assert match is not None, "'permit ip any any' was not detected"
        assert match.severity in {Severity.CRITICAL, Severity.HIGH}

    def test_any_any_evidence_shows_the_actual_line(self, cisco, run_rules):
        findings, _ = run_rules(cisco)
        match = next(f for f in findings if f.rule_id == "NG-FIREWALL-ANY-ANY")
        assert any("any any" in e.raw for e in match.evidence)

    def test_any_any_is_flagged_on_panos(self, panos, run_rules):
        findings, _ = run_rules(panos)
        assert "NG-FIREWALL-ANY-ANY" in {f.rule_id for f in findings}

    def test_any_any_detection_matches_the_rule_definition(self, any_config, run_rules):
        """The detector must agree with the model about what 'any-any' means.

        Deliberately mirrors the rule's own predicate, including the service
        clause: an any-to-any rule permitting only HTTPS is still a segmentation
        weakness, but it is caught by NG-FIREWALL-UNRESTRICTED-DESTINATION, not
        by the full any-any rule. Asserting the looser definition here would
        have forced the rule to cry wolf on every restricted-service policy.
        """
        full_any_any = [
            r
            for acl in any_config.access_lists
            for r in acl.rules
            if r.is_permissive
            and r.source.is_any
            and r.destination.is_any
            and (r.service.is_any or r.service.span > 1000)
        ]
        findings, _ = run_rules(any_config)
        found = "NG-FIREWALL-ANY-ANY" in {f.rule_id for f in findings}
        assert found == bool(full_any_any), (
            f"{any_config.vendor}: {len(full_any_any)} full any-any rules but detector said {found}"
        )

    def test_permit_logging_gap_is_reported(self, cisco, run_rules):
        findings, _ = run_rules(cisco)
        assert "NG-FIREWALL-LOGGING-MISSING" in {f.rule_id for f in findings}


# --------------------------------------------------------------------------- #
# Control / framework resolution
# --------------------------------------------------------------------------- #
class TestControlResolution:
    def test_findings_only_cite_applicable_frameworks(self, any_config, run_rules):
        """A Cisco device must never be failed against the Fortinet benchmark."""
        findings, _ = run_rules(any_config)
        for f in findings:
            for control in f.controls:
                assert framework_applies_to(control.framework, any_config.vendor), (
                    f"{f.rule_id} cited {control.framework.value} on a {any_config.vendor.value} device"
                )

    def test_vendor_specific_frameworks_are_excluded(self, cisco, run_rules):
        from app.schemas.api import Framework

        findings, _ = run_rules(cisco)
        frameworks = {c.framework for f in findings for c in f.controls}
        assert Framework.CIS_FORTINET not in frameworks
        assert Framework.CIS_PANOS not in frameworks

    def test_every_finding_has_at_least_one_control(self, any_config, run_rules):
        findings, _ = run_rules(any_config)
        for f in findings:
            assert f.controls, f"{f.rule_id} has no resolvable control"

    def test_control_index_is_populated(self):
        index = control_index()
        assert len(index) > 20
        assert all(isinstance(v, str) for v in index.values())


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #
class TestScoring:
    def test_a_device_with_no_failures_scores_100(self, scorer):
        """All-pass is the only configuration that may score a perfect 100."""
        from app.analysis.rules.base import OutcomeState, RuleOutcome
        from app.normalize.models import NormalizedConfig

        cfg = NormalizedConfig(device_id="clean", vendor=Vendor.CISCO_IOS)
        outcomes = [
            RuleOutcome(state=OutcomeState.PASS, rule_id="R1", severity=Severity.MEDIUM),
            RuleOutcome(state=OutcomeState.PASS, rule_id="R2", severity=Severity.HIGH),
        ]
        score, counts = scorer.overall_score(outcomes, cfg)
        assert score == 100.0
        assert sum(counts.values()) == 0

    def test_all_pass_except_one_critical_scores_worse_than_one_low(self, scorer):
        """Direct test of the weighting formula, independent of any config."""
        from app.analysis.rules.base import OutcomeState, RuleOutcome
        from app.normalize.models import NormalizedConfig

        cfg = NormalizedConfig(device_id="x", vendor=Vendor.CISCO_IOS)
        base = [
            RuleOutcome(state=OutcomeState.PASS, rule_id=f"P{i}", severity=Severity.MEDIUM) for i in range(9)
        ]

        def with_fail(sev: Severity) -> float:
            outcomes = base + [RuleOutcome(state=OutcomeState.FAIL, rule_id="F", severity=sev)]
            return scorer.overall_score(outcomes, cfg)[0]

        assert with_fail(Severity.CRITICAL) < with_fail(Severity.LOW)

    def test_not_applicable_controls_do_not_reduce_the_score(self, scorer):
        """You cannot fail a control that does not apply to the device."""
        from app.analysis.rules.base import OutcomeState, RuleOutcome
        from app.normalize.models import NormalizedConfig

        cfg = NormalizedConfig(device_id="x", vendor=Vendor.CISCO_IOS)
        passing = [RuleOutcome(state=OutcomeState.PASS, rule_id="P", severity=Severity.HIGH)]
        na = [RuleOutcome(state=OutcomeState.NOT_APPLICABLE, rule_id="N1", severity=Severity.CRITICAL)]
        na += [
            RuleOutcome(state=OutcomeState.NOT_APPLICABLE, rule_id=f"N{i}", severity=Severity.CRITICAL)
            for i in range(2, 20)
        ]
        assert scorer.overall_score(passing + na, cfg)[0] == 100.0

    def test_score_is_bounded(self, any_config, run_rules, scorer):
        _, outcomes = run_rules(any_config)
        score, _ = scorer.overall_score(outcomes, any_config)
        assert 0.0 <= score <= 100.0

    def test_critical_findings_cost_more_than_low(self, scorer):
        """The weight model must reflect risk, not defect count."""
        assert (
            scorer.CONTROL_WEIGHT[Severity.CRITICAL]
            > scorer.CONTROL_WEIGHT[Severity.HIGH]
            > scorer.CONTROL_WEIGHT[Severity.MEDIUM]
            > scorer.CONTROL_WEIGHT[Severity.LOW]
            > scorer.CONTROL_WEIGHT[Severity.INFO]
        )

    def test_unevaluable_config_reports_neutral_not_perfect(self, scorer):
        """Nothing assessed must not read as '100% compliant'."""
        from app.normalize.models import NormalizedConfig

        cfg = NormalizedConfig(device_id="empty", vendor=Vendor.UNKNOWN)
        score, _ = scorer.overall_score([], cfg)
        assert score == 50.0

    def test_framework_scores_only_cover_applicable_frameworks(self, any_config, run_rules, scorer):
        _, outcomes = run_rules(any_config)
        scores = scorer.framework_scores(outcomes, vendor=any_config.vendor)
        for s in scores:
            assert framework_applies_to(s.framework, any_config.vendor)

    def test_thin_frameworks_are_flagged_as_insufficient(self, any_config, run_rules, scorer):
        """A 0.00% score derived from two controls must not look authoritative.

        Only a handful of DISA STIG controls are mapped today, so a STIG score
        can legitimately be 0.00 out of two assessments. That is arithmetically
        correct but wildly overstated as a "compliance percentage", so the
        scorer has to admit when the evidence is too thin.
        """
        _, outcomes = run_rules(any_config)
        scores = scorer.framework_scores(outcomes, vendor=any_config.vendor)
        for s in scores:
            assessed = s.passed + s.failed
            assert s.sufficient_evidence == (assessed >= scorer.min_framework_controls), (
                f"{s.framework.value}: assessed {assessed} controls but "
                f"sufficient_evidence={s.sufficient_evidence}"
            )

    def test_well_covered_frameworks_are_not_flagged(self, cisco, run_rules, scorer):
        _, outcomes = run_rules(cisco)
        scores = {s.framework: s for s in scorer.framework_scores(outcomes, vendor=cisco.vendor)}
        from app.schemas.api import Framework

        # The Cisco sample maps far more than the minimum for its own benchmark.
        assert scores[Framework.CIS_CISCO_IOS].sufficient_evidence

    def test_scorer_reports_indeterminate_count(self, any_config, run_rules, scorer):
        _, outcomes = run_rules(any_config)
        assert scorer.indeterminate_count(outcomes) == 0

    def test_assessable_weight_is_positive_for_parsed_devices(self, any_config, run_rules, scorer):
        _, outcomes = run_rules(any_config)
        assert scorer.assessable_weight(outcomes) > 0
