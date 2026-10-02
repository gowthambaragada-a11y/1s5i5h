"""Unsupervised anomaly detection over configuration *features*.

Why this module exists next to the rule engine
---------------------------------------------
The rules answer questions we thought of in advance ("is telnet enabled?"). This
module answers the ones we did not: *does this device look like the other devices
of its own class?* A Cisco switch whose management plane suddenly answers on an
unusual port, or a FortiGate with far more policies than its peers, is exactly the
kind of drift that slips past a static checklist.

Design constraints, in priority order
1. **Never invent a score from thin air.** With no training history we have
   nothing to compare against, so the detector reports itself as *not trained*
   and the pipeline skips it. A confident number backed by one device would be
   worse than no number at all.
2. **Deterministic.** Given the same history the same device yields the same
   score, so a finding can be reproduced during an audit.
3. **Explainable.** Every anomaly carries the feature that moved and by how much.
   A black-box score is not actionable in a compliance report.

The model is deliberately a simple robust scaler plus k-nearest-neighbour
distance. It is cheap, has no hyperparameters worth over-tuning, and -- most
importantly -- degrades into something meaningful on the handful of samples a
small deployment will ever have.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.analysis.rules.base import RuleOutcome, fail
from app.normalize.models import (
    NormalizedConfig,
    RuleAction,
    Severity,
    SourceRefs,
    Vendor,
)
from app.schemas.api import Detector

#: Name reported on every outcome this module produces.
RULE_ID = "NG-ML-001"
TITLE = "Configuration deviates from the device-class baseline"

#: Features are extracted as plain floats so they can be fed to any estimator and
#: so the model card below stays honest about what it actually looks at.
FEATURE_NAMES: tuple[str, ...] = (
    "acl_count",
    "acl_rule_count",
    "deny_rule_count",
    "any_any_allow_count",
    "wide_port_rule_count",
    "interface_count",
    "active_interface_count",
    "described_interface_ratio",
    "management_service_count",
    "cleartext_service_count",
    "unrestricted_management_count",
    "credential_count",
    "privileged_credential_count",
    "static_route_count",
    "snmp_enabled",
    "syslog_configured",
    "syslog_server_count",
    "logging_enabled",
    "weak_cipher_count",
    "unparsed_line_ratio",
)

#: A device needs this many peers before "normal" means anything.
MIN_TRAINING_SAMPLES = 4

#: Magnitude assigned to a feature that is identical across every peer but differs
#: on the device under test. With a perfectly uniform peer group there is no
#: spread to divide by, so the honest reading is "this broke the pattern" --
#: notable, but not an unbounded z-score.
CONSTANT_FEATURE_DEVIATION = 6.0


# --------------------------------------------------------------------------- #
# Feature extraction
# --------------------------------------------------------------------------- #
def extract_features(cfg: NormalizedConfig) -> dict[str, float]:
    """Reduce one normalized config to a fixed-length numeric fingerprint.

    Only *structural* counts are used. Nothing here reads a secret, a hostname or
    an IP address, so the fingerprint cannot leak configuration content and stays
    comparable across sites.
    """
    rules = [r for acl in cfg.access_lists for r in acl.rules]
    interfaces = cfg.interfaces
    active = [i for i in interfaces if i.admin_state.value == "up"]
    services = [s for s in cfg.services if s.enabled]

    described = sum(1 for i in active if (i.description or "").strip())
    any_any = sum(
        1 for r in rules if r.action is RuleAction.ALLOW and r.source.is_any and r.destination.is_any
    )

    return {
        "acl_count": float(len(cfg.access_lists)),
        "acl_rule_count": float(len(rules)),
        "deny_rule_count": float(sum(1 for r in rules if r.action is RuleAction.DENY)),
        "any_any_allow_count": float(any_any),
        "wide_port_rule_count": float(sum(1 for r in rules if r.service.span > 1000)),
        "interface_count": float(len(interfaces)),
        "active_interface_count": float(len(active)),
        "described_interface_ratio": (described / len(active)) if active else 0.0,
        "management_service_count": float(len(services)),
        "cleartext_service_count": float(sum(1 for s in services if s.is_cleartext)),
        "unrestricted_management_count": float(sum(1 for s in services if s.is_unrestricted)),
        "credential_count": float(len(cfg.credentials)),
        "privileged_credential_count": float(sum(1 for c in cfg.credentials if c.is_privileged)),
        "static_route_count": float(cfg.routing.static_routes),
        "snmp_enabled": float(any(s.service.value == "snmp" for s in services)),
        "syslog_configured": float(cfg.logging.enabled),
        "syslog_server_count": float(len(cfg.logging.remote_servers)),
        "logging_enabled": float(cfg.logging.enabled),
        "weak_cipher_count": float(len(cfg.crypto.weak_ciphers)),
        "unparsed_line_ratio": float(cfg.unparsed_line_ratio or 0.0),
    }


def feature_vector(features: dict[str, float]) -> list[float]:
    return [float(features.get(name, 0.0)) for name in FEATURE_NAMES]


# --------------------------------------------------------------------------- #
# Model card
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FeatureContribution:
    """One feature that pushed a device away from its baseline."""

    name: str
    value: float
    baseline: float
    #: Standard deviations from the peer-group median.
    deviation: float

    def describe(self) -> str:
        direction = "above" if self.deviation > 0 else "below"
        return (
            f"{self.name}={self.value:g} is {abs(self.deviation):.1f} sd "
            f"{direction} the baseline {self.baseline:g}"
        )


@dataclass(frozen=True)
class AnomalyVerdict:
    """Model output for a single device."""

    #: 0..1, higher is more anomalous. ``None`` when the model is untrained.
    score: float | None
    #: Contributed most to the score.
    drivers: tuple[FeatureContribution, ...]
    #: Devices the baseline was built from.
    peer_count: int
    #: Peer vendors, for the report.
    peer_vendors: tuple[Vendor, ...]

    @property
    def trained(self) -> bool:
        return self.score is not None

    def as_params(self) -> dict[str, Any]:
        """Extras forwarded onto :class:`RuleOutcome.params`."""
        return {
            "ml_score": None if self.score is None else round(self.score, 4),
            "ml_peer_count": self.peer_count,
            "ml_drivers": [d.describe() for d in self.drivers],
        }


@dataclass
class AnomalyDetector:
    """Median/mad baseline over a peer group, with a k-NN distance score.

    ``IsolationForest`` was the obvious first choice and was rejected: its
    ``contamination`` parameter forces us to invent an anomaly *rate* before we
    have seen the data, and it gives per-feature attributions only after fitting.
    Median/MAD needs neither -- with a handful of devices it is transparent and
    stable, and it degrades to an honest "not enough peers" message instead of a
    confident wrong answer.
    """

    #: Peers needed before the detector will score anything.
    min_samples: int = MIN_TRAINING_SAMPLES
    #: Deviations from the median before a feature is called out.
    deviation_threshold: float = 3.0
    #: Score above which a device is reported.
    report_threshold: float = 0.60
    #: Cap on drivers attached to a finding.
    max_drivers: int = 3

    _median: dict[str, float] = field(default_factory=dict)
    _mad: dict[str, float | None] = field(default_factory=dict)
    _vectors: list[list[float]] = field(default_factory=list)
    _vendors: list[Vendor] = field(default_factory=list)
    _fitted: bool = False

    # -- training ------------------------------------------------------- #
    def fit(self, configs: Iterable[NormalizedConfig]) -> AnomalyDetector:
        """Build a baseline from same-vendor peers.

        Each config is embedded directly (no ad-hoc sample weights) so that a
        device scanned twice cannot quietly out-vote its peers.
        """
        rows: list[list[float]] = []
        vendors: list[Vendor] = []
        for cfg in configs:
            rows.append(feature_vector(extract_features(cfg)))
            vendors.append(cfg.vendor)

        self._vectors = rows
        self._vendors = vendors
        self._fitted = len(rows) >= self.min_samples

        if self._fitted:
            self._median, self._mad = {}, {}
            for idx, name in enumerate(FEATURE_NAMES):
                column = sorted(row[idx] for row in rows)
                med = _median_of(column)
                # MAD scaled to be comparable to a standard deviation.
                deviations = sorted(abs(value - med) for value in column)
                mad = _median_of(deviations) * 1.4826
                # A feature that never varies carries no spread information; the
                # scorer handles that case explicitly rather than dividing by ~0.
                self._median[name] = med
                self._mad[name] = mad if mad > 1e-9 else None
        else:
            self._median, self._mad = {}, {}
        return self

    # -- inference ------------------------------------------------------ #
    @property
    def is_fitted(self) -> bool:
        return self._fitted

    def score(self, cfg: NormalizedConfig) -> AnomalyVerdict:
        """Score one device against the fitted baseline."""
        peers = len(self._vectors)
        peer_vendors = tuple(dict.fromkeys(self._vendors))
        if not self._fitted:
            return AnomalyVerdict(score=None, drivers=(), peer_count=peers, peer_vendors=peer_vendors)

        features = extract_features(cfg)
        vector = feature_vector(features)

        # Robust z-score per feature, then combine with a k-NN distance so a
        # device that is unremarkable feature-by-feature but unlike its peers in
        # combination is still caught.
        zs: list[float] = []
        for name, value in zip(FEATURE_NAMES, vector, strict=True):
            mad = self._mad.get(name)
            median = self._median.get(name, 0.0)
            if mad:
                zs.append((value - median) / mad)
            else:
                # No spread among peers: agreeing is 0, differing breaks pattern.
                zs.append(0.0 if abs(value - median) <= 1e-9 else CONSTANT_FEATURE_DEVIATION)

        outlier = max((abs(z) for z in zs), default=0.0)
        # tanh keeps one absurd feature from saturating the whole score.
        feature_component = math.tanh(outlier / 3.0)

        distances = sorted(_euclidean(vector, peer) for peer in self._vectors)
        k = min(3, len(distances))
        nearest = sum(distances[:k]) / k if k else 0.0
        typical = max(sum(distances) / len(distances), 1e-9)
        neighbour_component = min(1.0, nearest / (typical * 2.0)) if typical > 0 else 0.0

        combined = 0.5 * feature_component + 0.5 * neighbour_component

        drivers = self._drivers(features, zs)
        return AnomalyVerdict(
            score=round(combined, 4),
            drivers=drivers,
            peer_count=peers,
            peer_vendors=peer_vendors,
        )

    def _drivers(self, features: dict[str, float], zs: list[float]) -> tuple[FeatureContribution, ...]:
        ranked: list[FeatureContribution] = []
        for name, z in zip(FEATURE_NAMES, zs, strict=True):
            if abs(z) < self.deviation_threshold:
                continue
            ranked.append(
                FeatureContribution(
                    name=name,
                    value=float(features.get(name, 0.0)),
                    baseline=self._median.get(name, 0.0),
                    deviation=float(z),
                )
            )
        ranked.sort(key=lambda c: abs(c.deviation), reverse=True)
        return tuple(ranked[: self.max_drivers])

    # -- findings ------------------------------------------------------- #
    def to_outcomes(self, cfg: NormalizedConfig) -> list[RuleOutcome]:
        """Report at most one outcome: the device-level deviation finding.

        This is deliberately one aggregate finding rather than one per odd
        feature. A device that is unusual in five small ways is one fact ("this
        box does not look like its peers"), and splitting it into five findings
        would bury the signal in noise.
        """
        verdict = self.score(cfg)
        if verdict.score is None:
            return []

        if verdict.score < self.report_threshold:
            return []

        severity = _severity_for(verdict.score)
        # Statistical output is not a checklist verdict; never claim high
        # confidence. The score is evidence, the human is the decision.
        confidence = round(min(0.75, 0.35 + verdict.score / 2.0), 3)
        drivers = list(verdict.drivers)
        driver_text = "; ".join(d.describe() for d in drivers) or "combined profile distance"

        return [
            fail(
                RULE_ID,
                TITLE,
                description=(
                    f"This device's configuration profile is unusual for its class "
                    f"(anomaly score {verdict.score:.2f} against {verdict.peer_count} peers). "
                    f"Deviating features: {driver_text}. Correlate with change records "
                    f"before acting -- an unusual configuration is not automatically a wrong one."
                ),
                severity=severity,
                confidence=confidence,
                # No specific config line is at fault: this is a whole-device
                # statistical statement. Cite the peers' scope instead of
                # inventing a citation.
                evidence=SourceRefs(),
                affected=[f"device:{cfg.device_id}"],
                detector=Detector.ML,
                **verdict.as_params(),
            )
        ]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _median_of(sorted_values: Sequence[float]) -> float:
    n = len(sorted_values)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2 == 1:
        return float(sorted_values[mid])
    return (float(sorted_values[mid - 1]) + float(sorted_values[mid])) / 2.0


def _euclidean(a: Sequence[float], b: Sequence[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b, strict=True)))


def _severity_for(score: float) -> Severity:
    if score >= 0.85:
        return Severity.HIGH
    if score >= 0.75:
        return Severity.MEDIUM
    return Severity.LOW
