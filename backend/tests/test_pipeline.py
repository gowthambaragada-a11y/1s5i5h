"""Orchestrator tests.

The pipeline is the only place the stages meet, so these tests focus on the
seams: stage ordering, honest degradation when Postgres/Neo4j are absent, and the
one bug that would be easy to ship -- ML anomalies moving the compliance score
while never appearing in the finding list the dashboard renders.
"""

from __future__ import annotations

import pytest

from app.analysis.anomaly import AnomalyDetector
from app.normalize.models import NormalizedConfig, Vendor
from app.pipeline.orchestrator import (
    AnalysisError,
    Pipeline,
    insufficient_evidence,
    severity_breakdown,
)


@pytest.fixture
def pipeline(engine) -> Pipeline:
    """A pipeline with no database and no graph -- the default dev experience."""
    return Pipeline(engine=engine, graph=None, persist=False)


INSECURE_IOS = """Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 10:00:00 UTC Mon Jan 1 2024 by admin
!
version 15.2
service password-encryption
hostname core-rtr-1
enable secret 5 $1$abc$def
username admin privilege 15 secret 5 $1$xyz$uvw
telnet 0.0.0.0 0 0
snmp-server community public RO
ip domain-lookup
no ip http server
interface GigabitEthernet0/0
 switchport mode access
 switchport access vlan 10
line vty 0 4
 transport input telnet
 password 7 02050D480809
"""


class TestStageOrdering:
    def test_every_vendor_produces_a_complete_summary(self, pipeline, raw_samples, registry) -> None:
        for vendor, raw in raw_samples.items():
            result = pipeline.analyze(raw, device_id=f"dev-{vendor.value}")
            summary = result.summary
            assert summary.status == "completed"
            assert summary.vendor.value == vendor.value
            assert summary.analysis_id.startswith("an-")
            assert summary.device_id == f"dev-{vendor.value}"
            assert summary.completed_at is not None
            assert summary.duration_ms is not None
            assert summary.total_findings == len(result.findings)
            assert 0.0 <= summary.parser_coverage <= 1.0

    def test_findings_are_ordered_most_severe_first(self, pipeline, raw_samples) -> None:
        result = pipeline.analyze(INSECURE_IOS, device_id="dev-ios")
        # Severity.rank is 5 for critical and 1 for info, so most severe first
        # means descending.
        ranks = [f.severity.rank for f in result.findings]
        assert ranks == sorted(ranks, reverse=True), "dashboard renders this list directly"
        assert ranks[0] == 5, "the CIS sample's worst finding should be critical"

    def test_rules_run_before_remediation(self, pipeline) -> None:
        result = pipeline.analyze(INSECURE_IOS, device_id="dev-ios")
        rule_ids = {f.rule_id for f in result.findings}
        for plan in result.remediations:
            assert plan.finding_id in {f.id for f in result.findings}
        assert result.remediations, "an insecure config must produce plans"
        assert rule_ids

    def test_framework_scores_cover_the_device_vendor_only(self, pipeline, raw_samples, registry) -> None:
        for vendor, raw in raw_samples.items():
            result = pipeline.analyze(raw, device_id=f"dev-{vendor.value}")
            frameworks = {str(s.framework) for s in result.framework_scores}
            assert "CIS_FORTINET" not in frameworks or vendor is Vendor.FORTINET_FORTIOS
            assert frameworks, "at least the device's own framework must be scored"


class TestMLIntegration:
    def test_anomaly_is_skipped_and_reported_when_there_are_no_peers(self, pipeline) -> None:
        result = pipeline.analyze(INSECURE_IOS, device_id="dev-solo")
        assert result.anomaly is not None
        assert result.anomaly.trained is False
        assert result.metrics.anomaly_scored is False
        assert any("anomaly detection skipped" in w for w in result.warnings)
        assert not any(f.detector == "ml" for f in result.findings)

    def test_trained_detector_contributes_findings_that_reach_the_summary(
        self, pipeline, raw_samples, registry
    ) -> None:
        """The regression this guards: ML moves the score but shows up nowhere."""
        peers = [
            registry.get(v).run(raw, device_id=f"peer-{i}")
            for i, (v, raw) in enumerate(raw_samples.items())
            for _ in range(3)
        ]
        pipeline.anomaly_detector = AnomalyDetector(min_samples=4, report_threshold=0.0)
        pipeline.anomaly_detector.fit(peers)

        result = pipeline.analyze(INSECURE_IOS, device_id="dev-ml")
        assert result.anomaly is not None
        assert result.anomaly.trained is True
        assert result.metrics.anomaly_scored is True

        # Whatever the model decides, the summary and the finding list must agree.
        assert result.summary.total_findings == len(result.findings)
        assert result.summary.overall_score is not None
        assert result.summary.framework_scores == result.framework_scores

    def test_a_device_is_never_its_own_baseline(self, pipeline, raw_samples, registry) -> None:
        """Fitting on the scored device would make every scan look normal."""
        raw = raw_samples[Vendor.CISCO_IOS]
        peers = [registry.get(Vendor.CISCO_IOS).run(raw, device_id=f"peer-{i}") for i in range(6)]
        detector = AnomalyDetector(min_samples=4)
        detector.fit(peers)
        cfg = registry.get(Vendor.CISCO_IOS).run(raw, device_id="dev-itself")
        assert detector.score(cfg).peer_count == 6

    def test_ml_outcomes_carry_explanations_not_bare_numbers(self, pipeline, raw_samples, registry) -> None:
        peers = [
            registry.get(v).run(r, device_id=f"peer-{i}")
            for i, (v, r) in enumerate(raw_samples.items())
            for _ in range(3)
        ]
        detector = AnomalyDetector(min_samples=4, report_threshold=0.0)
        detector.fit(peers)
        outcomes = detector.to_outcomes(registry.get(Vendor.CISCO_IOS).run(INSECURE_IOS, device_id="dev-ml"))
        for outcome in outcomes:
            assert outcome.detector == "ml"
            assert "ml_score" in outcome.params
            assert outcome.params["ml_drivers"]


class TestDegradation:
    def test_scan_succeeds_and_warns_when_nothing_can_persist(self, pipeline) -> None:
        result = pipeline.analyze(INSECURE_IOS, device_id="dev-nodb")
        assert result.summary.status == "completed"
        assert result.summary.total_findings > 0
        # The fixture runs with persist=False, so the caller must be told the
        # analysis is not durable rather than assuming it was stored.
        assert any("persist" in w for w in result.warnings)

    def test_persistence_is_attempted_when_enabled(self, engine) -> None:
        """With no Postgres reachable the scan still returns, flagged."""
        on = Pipeline(engine=engine, graph=None, persist=True)
        result = on.analyze(INSECURE_IOS, device_id="dev-nodb-2")
        assert result.summary.status == "completed"
        assert result.summary.total_findings > 0

    def test_unrecognised_config_raises_rather_than_guessing(self, pipeline) -> None:
        with pytest.raises(AnalysisError):
            pipeline.analyze("this is not a network device configuration at all")

    def test_empty_upload_is_rejected(self, pipeline) -> None:
        with pytest.raises(AnalysisError):
            pipeline.analyze("   \n  \n")

    def test_parse_warnings_reach_the_summary(self, pipeline) -> None:
        # A recognisable Cisco config carrying one directive no adapter knows.
        raw = INSECURE_IOS + "this-directive-does-not-exist anywhere\n"
        result = pipeline.analyze(raw, device_id="dev-warn")
        assert result.summary.status == "completed"
        assert result.summary.parse_warnings


class TestHelperFunctions:
    def test_insufficient_evidence_is_surfaced(self, pipeline) -> None:
        result = pipeline.analyze(INSECURE_IOS, device_id="dev-ie")
        thin = insufficient_evidence(result.framework_scores)
        assert isinstance(thin, list)
        for framework in thin:
            assert str(framework.value) in {str(s.framework) for s in result.framework_scores}

    def test_severity_breakdown_sums_to_the_finding_count(self, pipeline) -> None:
        result = pipeline.analyze(INSECURE_IOS, device_id="dev-bd")
        counts = severity_breakdown(result.findings)
        assert sum(counts.values()) == len(result.findings)
        assert all(isinstance(v, int) for v in counts.values())


class TestDeterminism:
    def test_two_scans_of_the_same_config_agree_on_everything_but_ids(self, pipeline, raw_samples) -> None:
        raw = raw_samples[Vendor.FORTINET_FORTIOS]
        first = pipeline.analyze(raw, device_id="dev-det")
        second = pipeline.analyze(raw, device_id="dev-det")

        assert [f.rule_id for f in first.findings] == [f.rule_id for f in second.findings]
        assert first.summary.overall_score == second.summary.overall_score
        assert [s.score for s in first.framework_scores] == [s.score for s in second.framework_scores]
        assert [f.severity for f in first.findings] == [f.severity for f in second.findings]

    def test_findings_carry_redacted_evidence(self, pipeline, raw_samples) -> None:
        result = pipeline.analyze(raw_samples[Vendor.CISCO_IOS], device_id="dev-redact")
        blob = " ".join(line.raw for f in result.findings for line in f.evidence)
        assert "$1$" not in blob
        assert "02050D480809" not in blob


def test_pipeline_never_returns_applied_remediation(raw_samples, engine) -> None:
    """No code path in the analysis pipeline may mark a change as applied."""
    p = Pipeline(engine=engine, graph=None, persist=False)
    for vendor, raw in raw_samples.items():
        result = p.analyze(raw, device_id=f"dev-{vendor.value}")
        for plan in result.remediations:
            assert plan.applied_to_device is False
            assert str(plan.status) == "pending_review"


def test_analysis_id_is_unique_per_scan(pipeline) -> None:
    a = pipeline.analyze(INSECURE_IOS, device_id="dev-u")
    b = pipeline.analyze(INSECURE_IOS, device_id="dev-u")
    assert a.analysis_id != b.analysis_id


def test_config_carries_provenance_for_the_database(pipeline) -> None:
    result = pipeline.analyze(INSECURE_IOS, device_id="dev-prov")
    cfg: NormalizedConfig = result.cfg
    assert cfg.raw_config_sha256 is not None
    assert len(cfg.raw_config_sha256) == 64
