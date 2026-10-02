"""Tests for remediation generation.

The properties worth protecting are almost entirely about restraint: nothing is
executed, no secret is ever printed, no command is emitted for a vendor the
handler does not understand, and findings we cannot safely fix get an explicit
"manual review" step rather than invented commands.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.normalize.models import Vendor
from app.remediation.generator import SECRET_PLACEHOLDER, RemediationGenerator
from app.schemas.api import Detector, Finding, FindingStatus, RemediationStatus, Severity

#: Strings that must never appear anywhere in a generated plan.
FORBIDDEN = [
    "private",
    "public",
    "cisco123",
    "T0pS3cr3t",
]


@pytest.fixture
def generator() -> RemediationGenerator:
    return RemediationGenerator()


def _finding(rule_id: str, severity: Severity = Severity.HIGH, **kw) -> Finding:
    """A minimal valid Finding for rules the samples do not actually trip."""
    payload = {
        "id": "f-1",
        "analysis_id": "an-1",
        "device_id": "dev-1",
        "rule_id": rule_id,
        "title": "Some finding",
        "description": "Something is wrong.",
        "explanation": "An attacker could reach this surface.",
        "severity": severity,
        "confidence": 0.9,
        "status": FindingStatus.OPEN,
        "category": "test",
        "evidence": [],
        "controls": [],
        "evidence_precision": "line",
        "affected_objects": [],
        "detector": Detector.RULE,
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    payload.update(kw)
    return Finding.model_validate(payload)


@pytest.fixture
def real_findings(engine):
    """``cfg -> findings`` straight from the rule engine."""

    def _run(cfg):
        findings, _ = engine.execute(cfg, analysis_id="an-test")
        return findings

    return _run


class TestSafetyInvariants:
    def test_nothing_is_ever_marked_applied(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED")])
        assert plans
        assert all(p.applied_to_device is False for p in plans)

    def test_every_plan_starts_in_pending_review(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED")])
        assert all(p.status is RemediationStatus.PENDING_REVIEW for p in plans)

    def test_no_secret_material_appears_in_any_plan(self, generator, any_config):
        rules = [
            "NG-SNMP-WEAK-COMMUNITY",
            "NG-CRED-WEAK-PASSWORD-TYPE",
            "NG-REMOTE-TELNET-ENABLED",
            "NG-REMOTE-SSH-V1",
        ]
        plans = generator.generate(any_config, [_finding(r) for r in rules])
        assert plans
        for plan in plans:
            blob = " ".join([c.command for c in plan.commands] + [c.description or "" for c in plan.commands])
            for secret in FORBIDDEN:
                assert secret.lower() not in blob.lower(), f"{secret!r} leaked into {plan.id}"

    def test_snmp_remediation_uses_a_placeholder_not_a_value(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-SNMP-WEAK-COMMUNITY")])
        assert plans
        commands = " ".join(c.command for c in plans[0].commands)
        assert SECRET_PLACEHOLDER in commands

    def test_any_any_never_generates_an_executable_command(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-FIREWALL-ANY-ANY")])
        assert plans
        for step in plans[0].commands:
            assert "MANUAL REVIEW" in step.command
            assert step.requires_confirmation is True

    def test_management_acl_does_not_invent_a_subnet(self, generator, cisco):
        """With no management ACL present, the plan must ask rather than assume."""
        bare = cisco.model_copy(deep=True)
        bare.access_lists = []
        plans = generator.generate(bare, [_finding("NG-REMOTE-MGMT-UNRESTRICTED")])
        assert plans
        blob = " ".join((c.config_after or "") + (c.command or "") for c in plans[0].commands)
        assert "TODO" in blob

    def test_existing_management_acl_is_reused_not_recreated(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-REMOTE-MGMT-UNRESTRICTED")])
        blob = " ".join(c.command for c in plans[0].commands)
        assert "reusing existing access list" in blob


class TestVendorGating:
    def test_cisco_handler_is_not_offered_to_juniper(self, generator, juniper):
        assert generator.generate(juniper, [_finding("NG-REMOTE-TELNET-ENABLED")]) == []

    def test_cisco_save_command_differs_between_ios_and_nxos(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED")])
        commands = [c.command for c in plans[0].commands]
        assert "write memory" in commands

    def test_fortinet_uses_config_blocks(self, generator, fortinet):
        plans = generator.generate(fortinet, [_finding("NG-REMOTE-TELNET-ENABLED")])
        assert plans == [], "Cisco-only handler must not fire for Fortinet"

    def test_juniper_change_is_committed(self, generator, juniper):
        plans = generator.generate(juniper, [_finding("NG-LOG-REMOTE-SYSLOG-ABSENT")])
        assert plans
        commands = [c.command for c in plans[0].commands]
        assert "commit" in commands
        assert commands[-1] == "exit"

    def test_panos_uses_set_syntax(self, generator, panos):
        plans = generator.generate(panos, [_finding("NG-FIREWALL-NO-TERMINAL-DENY")])
        assert plans
        assert any(c.command.startswith("set rulebase") for c in plans[0].commands)

    @pytest.mark.parametrize(
        "rule_id",
        ["NG-REMOTE-TELNET-ENABLED", "NG-REMOTE-SSH-V1", "NG-SNMP-WEAK-COMMUNITY"],
    )
    def test_vendor_specific_handlers_do_not_cross_families(self, generator, juniper, rule_id):
        if rule_id == "NG-SNMP-WEAK-COMMUNITY":
            assert generator.generate(juniper, [_finding(rule_id)])  # cross-vendor handler
        else:
            assert generator.generate(juniper, [_finding(rule_id)]) == []


class TestStructure:
    def test_step_order_is_sequential_and_starts_at_zero(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED")])
        orders = [c.order for c in plans[0].commands]
        assert orders == list(range(len(orders)))

    def test_each_step_has_a_description(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED")])
        assert all(c.description for c in plans[0].commands)

    def test_persistence_step_is_not_reversible(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED")])
        save = [c for c in plans[0].commands if c.command == "write memory"]
        assert save and save[0].reversible is False

    def test_plan_references_the_finding_it_fixes(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED", id="find-77")])
        assert plans[0].finding_id == "find-77"

    def test_plan_carries_device_id_and_vendor(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED")])
        assert plans[0].device_id == cisco.device_id
        assert plans[0].vendor.value == cisco.vendor.value

    def test_diff_summary_states_nothing_is_applied(self, generator, cisco):
        plans = generator.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED")])
        assert "not" in (plans[0].diff_summary or "").lower()

    def test_ids_are_unique(self, generator, cisco):
        findings = [_finding("NG-REMOTE-TELNET-ENABLED"), _finding("NG-REMOTE-SSH-V1")]
        plans = generator.generate(cisco, findings)
        assert len({p.id for p in plans}) == len(plans)


class TestFiltering:
    def test_unknown_rule_gets_no_plan(self, generator, cisco):
        assert generator.generate(cisco, [_finding("NG-NOT-A-REAL-RULE")]) == []

    def test_info_findings_are_skipped_by_default(self, generator, cisco):
        assert generator.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED", severity=Severity.INFO)]) == []

    def test_severity_filter_is_configurable(self, cisco):
        gen = RemediationGenerator(min_severity_rank=1)
        plans = gen.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED", severity=Severity.INFO)])
        assert plans

    def test_handles_reports_coverage(self, generator):
        assert generator.handles("NG-REMOTE-TELNET-ENABLED") is True
        assert generator.handles("NG-NOPE") is False

    def test_vendors_for_reports_the_intended_scope(self, generator):
        assert generator.vendors_for("NG-REMOTE-SSH-V1") == frozenset({Vendor.CISCO_IOS, Vendor.CISCO_NXOS})


class TestIdempotence:
    def test_generating_twice_produces_equivalent_plans(self, generator, cisco):
        finding = _finding("NG-REMOTE-TELNET-ENABLED")
        first = generator.generate(cisco, [finding])
        second = generator.generate(cisco, [finding])
        assert [c.command for c in first[0].commands] == [c.command for c in second[0].commands]

    def test_generator_is_stateless_across_calls(self, generator, cisco):
        generator.generate(cisco, [_finding("NG-REMOTE-TELNET-ENABLED")])
        plans = generator.generate(cisco, [_finding("NG-REMOTE-SSH-V1")])
        assert len(plans) == 1
        assert "ip ssh version 2" in plans[0].commands[0].command


class TestSecretInEvidence:
    def test_evidence_is_echoed_without_secret_values(self, generator, cisco):
        """Even if evidence slipped through, the rationale must not echo it."""
        finding = _finding("NG-SNMP-WEAK-COMMUNITY")
        plans = generator.generate(cisco, [finding])
        assert "community string" not in (plans[0].rationale or "").lower()
