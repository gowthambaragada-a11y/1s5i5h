"""Compliance scoring.

How a score is computed, and why
--------------------------------
A naive "100 - failures" is misleading: it cannot distinguish "we checked ten
controls and eight passed" from "we checked ten thousand and eight passed", and
it cannot say *which* failures matter. NETGUARD uses a **severity-weighted pass
rate** instead::

    weight(control) = {critical: 10, high: 5, medium: 2, low: 1, info: 0.5}
    score           = 100 * sum(weight of PASSED) / sum(weight of EVALUATED)

Consequences worth stating plainly:

* A missed critical control costs five times a missed low one, so the score
  tracks risk rather than defect count.
* Rules that return ``NOT_APPLICABLE`` are excluded from the denominator. You
  cannot fail a control that does not apply to the device, and counting it
  would unfairly penalise, say, a firewall for lacking an IOS ``vty`` timeout.
* ``INDETERMINATE`` outcomes (a rule that raised) are also excluded and reported
  separately, so a bug in one rule never silently moves a customer's score.

Parser coverage and mean confidence are reported as **separate fields**, not
folded into the score. A compliance number should not move because we had an
unusual number of comments in the file -- that belongs in its own column where
an auditor can see it and decide.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from app.analysis.rules.base import OutcomeState, RuleOutcome, framework_applies_to
from app.normalize.models import SEVERITY_ORDER, NormalizedConfig, Severity, Vendor
from app.schemas.api import Framework, FrameworkScore
from app.schemas.api import Severity as ApiSeverity


@dataclass
class _Bucket:
    """Running per-framework tally.

    Counts stay ``int`` while the weighted terms stay ``float`` -- mixing them in
    one untyped dict is what let ``total_controls`` silently become a float and
    serialise as ``7.0`` in the API.
    """

    earned: float = 0.0
    available: float = 0.0
    pass_count: int = 0
    fail_count: int = 0
    na_count: int = 0
    seen: int = 0

    def add(self, state_key: str) -> None:
        match state_key:
            case "pass":
                self.pass_count += 1
            case "fail":
                self.fail_count += 1
            case _:
                self.na_count += 1


class ComplianceScorer:
    """Turns rule outcomes into per-framework and overall scores."""

    #: Importance of a control by severity. Ratio matters, absolute values do not
    #: (they cancel in the pass-rate formula).
    CONTROL_WEIGHT: dict[Severity, float] = {
        Severity.CRITICAL: 10.0,
        Severity.HIGH: 5.0,
        Severity.MEDIUM: 2.0,
        Severity.LOW: 1.0,
        Severity.INFO: 0.5,
    }

    def __init__(
        self,
        *,
        min_evaluable_weight: float = 1.0,
        min_framework_controls: int = 5,
    ) -> None:
        self.min_evaluable_weight = min_evaluable_weight
        #: Below this many assessed controls, a framework score is reported but
        #: flagged as insufficient. We currently map only a handful of DISA
        #: STIG controls, so a STIG score can legitimately be 0.00 out of two
        #: controls -- numerically correct, but presenting that as "0.00%
        #: STIG compliant" to an auditor overstates the coverage enormously.
        self.min_framework_controls = min_framework_controls

    def has_sufficient_evidence(self, frame_score: FrameworkScore) -> bool:
        return (frame_score.passed + frame_score.failed) >= self.min_framework_controls

    def insufficient_evidence_frameworks(self, scores: list[FrameworkScore]) -> list[Framework]:
        return [s.framework for s in scores if not self.has_sufficient_evidence(s)]

    # ------------------------------------------------------------------ #
    def overall_score(
        self, outcomes: list[RuleOutcome], cfg: NormalizedConfig
    ) -> tuple[float, dict[Severity, int]]:
        """Severity-weighted pass rate for a device, 0-100."""
        counts = self.severity_counts(outcomes)
        earned = 0.0
        available = 0.0
        for o in outcomes:
            if o.state not in {OutcomeState.PASS, OutcomeState.FAIL}:
                continue
            weight = self.CONTROL_WEIGHT.get(o.severity, 1.0)
            available += weight
            if o.state is OutcomeState.PASS:
                earned += weight

        if available < self.min_evaluable_weight:
            # Nothing meaningful could be judged. Report a neutral 50 and let the
            # caller surface "insufficient evidence" rather than claiming a pass.
            return 50.0, counts
        return round(100.0 * earned / available, 2), counts

    def framework_scores(
        self,
        outcomes: list[RuleOutcome],
        *,
        vendor: Vendor | None = None,
        frameworks: list[Framework] | None = None,
    ) -> list[FrameworkScore]:
        """Per-framework rollup.

        A control counts once per framework it belongs to, so a single finding
        mapped to both CIS and NIST reduces both scores -- which is the honest
        representation of "you violated both benchmarks here".

        ``vendor`` restricts the rollup to frameworks that actually apply to the
        device. Without it a Cisco switch also gets a "CIS Fortinet" score, which
        is not merely useless but actively misleading in an audit.
        """
        wanted = set(frameworks) if frameworks else None

        buckets: defaultdict[Framework, _Bucket] = defaultdict(_Bucket)

        for outcome in outcomes:
            if outcome.state is OutcomeState.INDETERMINATE:
                continue
            state_key = {
                OutcomeState.PASS: "pass",
                OutcomeState.FAIL: "fail",
                OutcomeState.NOT_APPLICABLE: "na",
            }[outcome.state]
            for ctrl in _controls_for(outcome):
                if wanted and ctrl.framework not in wanted:
                    continue
                if vendor is not None and not framework_applies_to(ctrl.framework, vendor):
                    continue
                bucket = buckets[ctrl.framework]
                bucket.seen += 1
                bucket.add(state_key)
                if state_key == "na":
                    continue
                weight = self.CONTROL_WEIGHT.get(outcome.severity, 1.0)
                bucket.available += weight
                if state_key == "pass":
                    bucket.earned += weight

        scores: list[FrameworkScore] = []
        for framework, b in buckets.items():
            applicable = b.pass_count + b.fail_count
            score = 100.0 if b.available == 0 else round(100.0 * b.earned / b.available, 2)
            scores.append(
                FrameworkScore(
                    framework=framework,
                    score=score,
                    passed=b.pass_count,
                    failed=b.fail_count,
                    not_applicable=b.na_count,
                    total_controls=applicable or b.seen,
                    sufficient_evidence=applicable >= self.min_framework_controls,
                )
            )
        return sorted(scores, key=lambda s: s.framework.value)

    # ------------------------------------------------------------------ #
    @staticmethod
    def severity_counts(outcomes: list[RuleOutcome]) -> dict[Severity, int]:
        counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for o in outcomes:
            if o.state is OutcomeState.FAIL:
                counts[o.severity] = counts.get(o.severity, 0) + 1
        return counts

    @staticmethod
    def api_severity_counts(outcomes: list[RuleOutcome]) -> dict[ApiSeverity, int]:
        return {
            ApiSeverity.from_internal(k): v
            for k, v in ComplianceScorer.severity_counts(outcomes).items()
            if v > 0
        }

    def highest_severity(self, outcomes: list[RuleOutcome]) -> Severity | None:
        failures = [o for o in outcomes if o.state is OutcomeState.FAIL]
        if not failures:
            return None
        return max((o.severity for o in failures), key=lambda s: SEVERITY_ORDER[s])

    # -- internals ----------------------------------------------------- #
    def assessable_weight(self, outcomes: list[RuleOutcome]) -> float:
        """Total control weight the engine was actually able to judge.

        Callers use this to warn about thin evidence: a "92.0" score derived
        from four controls is not the same claim as one derived from four
        hundred.
        """
        return sum(
            self.CONTROL_WEIGHT.get(o.severity, 1.0)
            for o in outcomes
            if o.state in {OutcomeState.PASS, OutcomeState.FAIL}
        )

    def indeterminate_count(self, outcomes: list[RuleOutcome]) -> int:
        return sum(1 for o in outcomes if o.state is OutcomeState.INDETERMINATE)


def _controls_for(outcome: RuleOutcome) -> list:
    from app.analysis.rules.base import CONTROL_CATALOG

    out: list = []
    for cid in outcome.control_ids:
        ref = CONTROL_CATALOG.get(cid)
        if ref is not None:
            out.append(ref)
    return out
