"""Tests for the unsupervised anomaly detector.

The behaviour these lock down is mostly about *restraint*: the detector must stay
silent without peers, must not report a peer as anomalous against itself, and
must never claim high confidence.
"""

from __future__ import annotations

import pytest

from app.analysis.anomaly import (
    FEATURE_NAMES,
    AnomalyDetector,
    extract_features,
    feature_vector,
)
from app.normalize.models import NormalizedConfig, Severity, Vendor


def _peer(**overrides) -> NormalizedConfig:
    """A minimal, boring, homogeneous config used as a stand-in peer."""
    cfg = NormalizedConfig(device_id="peer", vendor=Vendor.CISCO_IOS)
    cfg.access_lists = []
    cfg.interfaces = []
    cfg.services = []
    cfg.credentials = []
    cfg.unparsed_line_ratio = 0.0
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


def _peer_group(count: int = 6) -> list[NormalizedConfig]:
    return [_peer() for _ in range(count)]


class TestFeatureExtraction:
    def test_features_cover_every_declared_name(self, any_config):
        features = extract_features(any_config)
        assert set(features) == set(FEATURE_NAMES)

    def test_vector_length_matches_feature_count(self, any_config):
        assert len(feature_vector(extract_features(any_config))) == len(FEATURE_NAMES)

    def test_every_value_is_finite_number(self, any_config):
        for name, value in extract_features(any_config).items():
            assert isinstance(value, float), name
            assert value == value, f"{name} is NaN"

    def test_empty_config_yields_zeros_not_errors(self):
        assert all(v == 0.0 for v in extract_features(_peer()).values())

    def test_features_are_not_secret_bearing(self, any_config):
        """The fingerprint must not leak configuration content."""
        blob = " ".join(f"{k}={v}" for k, v in extract_features(any_config).items())
        hostname = any_config.identity.hostname
        if hostname:
            assert hostname not in blob


class TestUntrainedDetector:
    def test_refuses_to_score_without_peers(self):
        detector = AnomalyDetector().fit([])
        assert detector.is_fitted is False

    def test_refuses_to_score_with_too_few_peers(self):
        detector = AnomalyDetector().fit(_peer_group(2))
        assert detector.is_fitted is False

    def test_verdict_is_none_and_flagged_untrained(self):
        detector = AnomalyDetector().fit(_peer_group(2))
        verdict = detector.score(_peer())
        assert verdict.score is None
        assert verdict.trained is False

    def test_emits_no_outcomes_when_untrained(self):
        detector = AnomalyDetector().fit(_peer_group(2))
        assert detector.to_outcomes(_peer()) == []

    def test_reports_peer_count_even_when_untrained(self):
        detector = AnomalyDetector().fit(_peer_group(3))
        assert detector.score(_peer()).peer_count == 3


class TestTrainedDetector:
    def test_fits_enough_peers(self):
        assert AnomalyDetector().fit(_peer_group(6)).is_fitted is True

    def test_does_not_flag_a_device_that_matches_its_peers(self):
        detector = AnomalyDetector().fit(_peer_group(8))
        verdict = detector.score(_peer())
        assert verdict.score is not None
        assert verdict.score < detector.report_threshold
        assert detector.to_outcomes(_peer()) == []

    def test_flags_a_device_far_outside_the_baseline(self):
        odd = _peer()
        # 40 weak ciphers against an all-zero peer baseline: a real, single,
        # extreme feature deviation rather than noise across many dimensions.
        odd.crypto.weak_ciphers = ["des"] * 40
        detector = AnomalyDetector(report_threshold=0.0).fit(_peer_group(8))
        verdict = detector.score(odd)
        assert verdict.score is not None
        assert verdict.score > 0.0

    def test_flags_a_device_at_the_default_threshold(self):
        odd = _peer()
        odd.crypto.weak_ciphers = ["des"] * 40
        detector = AnomalyDetector().fit(_peer_group(8))
        outcomes = detector.to_outcomes(odd)
        assert len(outcomes) == 1
        assert outcomes[0].rule_id == "NG-ML-001"

    def test_odd_device_is_more_anomalous_than_a_peer(self):
        odd = _peer()
        odd.crypto.weak_ciphers = ["des"] * 40
        detector = AnomalyDetector().fit(_peer_group(8))
        assert (detector.score(odd).score or 0) > (detector.score(_peer()).score or 0)

    def test_outcomes_carry_detector_provenance(self):
        from app.schemas.api import Detector

        detector = AnomalyDetector(report_threshold=0.0).fit(_peer_group(8))
        outcomes = detector.to_outcomes(_peer())
        assert outcomes
        assert all(o.detector is Detector.ML for o in outcomes)
        assert all(o.rule_id == "NG-ML-001" for o in outcomes)

    def test_outcome_confidence_never_exceeds_the_cap(self):
        detector = AnomalyDetector(report_threshold=0.0).fit(_peer_group(8))
        for outcome in detector.to_outcomes(_peer()):
            assert 0.0 < outcome.confidence <= 0.75

    def test_score_is_bounded(self):
        detector = AnomalyDetector().fit(_peer_group(8))
        score = detector.score(_peer()).score
        assert score is not None
        assert 0.0 <= score <= 1.0

    def test_scoring_is_deterministic(self):
        detector = AnomalyDetector().fit(_peer_group(6))
        first = detector.score(_peer()).score
        second = detector.score(_peer()).score
        assert first == second

    def test_reports_at_most_one_finding_per_device(self):
        """One aggregate finding, not one per odd feature."""
        detector = AnomalyDetector(report_threshold=0.0).fit(_peer_group(8))
        assert len(detector.to_outcomes(_peer())) == 1


class TestDrivers:
    def test_no_drivers_when_nothing_deviates(self):
        detector = AnomalyDetector().fit(_peer_group(8))
        assert detector.score(_peer()).drivers == ()

    def test_drivers_are_ordered_by_magnitude(self):
        detector = AnomalyDetector().fit(_peer_group(8))
        deviations = [abs(d.deviation) for d in detector.score(_peer()).drivers]
        assert deviations == sorted(deviations, reverse=True)

    def test_driver_count_is_capped(self):
        detector = AnomalyDetector(max_drivers=1).fit(_peer_group(8))
        assert len(detector.score(_peer()).drivers) <= 1

    def test_driver_descriptions_name_the_feature(self):
        detector = AnomalyDetector().fit(_peer_group(8))
        for driver in detector.score(_peer()).drivers:
            assert driver.name in FEATURE_NAMES
            assert driver.name in driver.describe()


class TestFitInput:
    def test_ignores_nothing_but_keeps_every_peer(self):
        detector = AnomalyDetector().fit(_peer_group(7))
        assert detector.score(_peer()).peer_count == 7

    def test_records_peer_vendors(self, any_config):
        detector = AnomalyDetector().fit([any_config, *_peer_group(6)])
        assert any_config.vendor in detector.score(any_config).peer_vendors

    @pytest.mark.parametrize("count", [0, 1, 3])
    def test_refits_cleanly_from_untrained_state(self, count):
        detector = AnomalyDetector().fit(_peer_group(count))
        assert detector.is_fitted is False
        detector.fit(_peer_group(6))
        assert detector.is_fitted is True
        assert detector.score(_peer()).score is not None


class TestOutcomeIntegration:
    def test_severity_is_not_informational_for_a_strong_signal(self, any_config):
        """A high score must not be silently downgraded to 'info'."""
        detector = AnomalyDetector(report_threshold=0.0).fit(_peer_group(8))
        outcomes = detector.to_outcomes(any_config)
        if outcomes and outcomes[0].severity is Severity.INFO:
            pytest.fail("anomaly reported at info severity")

    def test_evidence_is_not_fabricated(self, any_config):
        """A statistical finding has no single guilty line, so it cites nothing."""
        detector = AnomalyDetector(report_threshold=0.0).fit(_peer_group(8))
        for outcome in detector.to_outcomes(any_config):
            assert outcome.evidence.refs == []

    def test_params_expose_the_score_for_the_dashboard(self, any_config):
        detector = AnomalyDetector(report_threshold=0.0).fit(_peer_group(8))
        for outcome in detector.to_outcomes(any_config):
            assert "ml_score" in outcome.params
            assert outcome.params["ml_peer_count"] >= 6
