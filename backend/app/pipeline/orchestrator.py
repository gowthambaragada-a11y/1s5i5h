"""The scan pipeline: one function that turns a config upload into a report.

Stage order is a correctness requirement, not a preference:

1. **detect + normalize** -- everything downstream reads a ``NormalizedConfig``,
   so this must happen first and its warnings must reach the caller.
2. **rules** -- deterministic, evidence-backed findings.
3. **anomaly** -- optional, *additive*. It needs a peer group, so a single-device
   scan legitimately has nothing to compare against and must say so rather than
   manufacture a baseline from one sample.
4. **compliance** -- scored from rule outcomes, so it must run after rules and
   after anomaly (whose outcomes carry real control ids).
5. **remediation** -- reads the final finding list, so it runs last.
6. **persist + graph** -- side effects. A failure here never invalidates the
   analysis; it downgrades it to "computed but not stored", which the summary
   reports explicitly.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.analysis.anomaly import AnomalyDetector, AnomalyVerdict
from app.analysis.compliance import ComplianceScorer
from app.analysis.rules.base import RuleEngine
from app.db.graph import GraphEnrichment, SecurityGraph
from app.db.repository import AnalysisMetrics, persist_analysis
from app.db.session import session_scope
from app.normalize.models import NormalizedConfig, Vendor
from app.normalize.registry import get_registry
from app.remediation.generator import RemediationGenerator
from app.schemas.api import (
    AnalysisSummary,
    Finding,
    Framework,
    FrameworkScore,
    Remediation,
    Severity,
)
from app.schemas.api import Vendor as ApiVendor

logger = logging.getLogger(__name__)


class AnalysisError(RuntimeError):
    """Raised when a scan cannot proceed at all (e.g. no vendor recognised)."""


@dataclass
class PipelineResult:
    """Full output of one scan, richer than the wire ``AnalysisSummary``."""

    summary: AnalysisSummary
    cfg: NormalizedConfig
    findings: list[Finding]
    framework_scores: list[FrameworkScore]
    remediations: list[Remediation]
    anomaly: AnomalyVerdict | None
    graph: GraphEnrichment | None
    metrics: AnalysisMetrics
    #: Non-fatal degradations: "graph off", "postgres unavailable".
    warnings: list[str] = field(default_factory=list)

    @property
    def analysis_id(self) -> str:
        return self.summary.analysis_id


@dataclass
class Pipeline:
    """Wires the stages together. Constructed once per process."""

    engine: RuleEngine
    scorer: ComplianceScorer = field(default_factory=ComplianceScorer)
    generator: RemediationGenerator = field(default_factory=RemediationGenerator)
    anomaly_detector: AnomalyDetector = field(default_factory=AnomalyDetector)
    graph: SecurityGraph | None = None
    persist: bool = True

    @classmethod
    def build(
        cls, *, vendor: Vendor | None = None, peer_configs: Sequence[NormalizedConfig] | None = None
    ) -> Pipeline:
        from app.analysis.rule_packs import get_engine

        pipeline = cls(engine=get_engine(vendor=vendor), graph=SecurityGraph.from_settings())
        if peer_configs:
            pipeline.anomaly_detector.fit(peer_configs)
        return pipeline

    # ------------------------------------------------------------------ #
    def analyze(
        self,
        raw_text: str,
        *,
        device_id: str | None = None,
        analysis_id: str | None = None,
        peer_configs: Sequence[NormalizedConfig] | None = None,
    ) -> PipelineResult:
        """Run every stage over one uploaded config."""
        started = datetime.now(UTC)
        clock = time.perf_counter()
        analysis_id = analysis_id or f"an-{uuid.uuid4().hex[:16]}"
        warnings: list[str] = []

        cfg = self._normalize(raw_text, device_id=device_id, analysis_id=analysis_id)

        # ---- Stage 2: deterministic rules -------------------------------- #
        findings, outcomes = self.engine.execute(cfg, analysis_id=analysis_id)

        # ---- Stage 3: optional anomaly scoring ---------------------------- #
        # Trained on the caller's peer group, or whatever the detector already
        # holds. Never fitted on the device being scored: a device is always its
        # own single nearest neighbour, which would make every scan look normal.
        if peer_configs is not None:
            self.anomaly_detector.fit(peer_configs)
        verdict = self.anomaly_detector.score(cfg)
        if verdict.trained:
            outcomes.extend(self.anomaly_detector.to_outcomes(cfg))
        else:
            warnings.append(
                "anomaly detection skipped: "
                f"{verdict.peer_count} peer device(s) available, "
                f"{self.anomaly_detector.min_samples} required"
            )

        # ---- Stage 4: compliance ----------------------------------------- #
        scores = self.scorer.framework_scores(outcomes, vendor=cfg.vendor)
        overall, _ = self.scorer.overall_score(outcomes, cfg)
        # Recompute findings so ML-sourced outcomes are present in the list the
        # remediation generator and the UI will actually see.
        findings, outcomes = self._finalize_findings(cfg, outcomes, analysis_id)

        # ---- Stage 5: remediation ---------------------------------------- #
        remediations = self.generator.generate(cfg, findings)

        # ---- Stage 6: persistence and graph ------------------------------ #
        metrics = AnalysisMetrics(
            overall_score=overall,
            assessable_weight=self.scorer.assessable_weight(outcomes),
            mean_confidence=(sum(f.confidence for f in findings) / len(findings) if findings else 0.0),
            indeterminate_count=self.scorer.indeterminate_count(outcomes),
            anomaly_scored=verdict.trained,
            duration_ms=int((time.perf_counter() - clock) * 1000),
        )

        graph_result = self._ingest_graph(cfg, findings, analysis_id, warnings)

        if self.persist:
            stored = self._persist(
                analysis_id=analysis_id,
                cfg=cfg,
                findings=findings,
                scores=scores,
                remediations=remediations,
                metrics=metrics,
                warnings=warnings,
            )
            if not stored:
                warnings.append("results were computed but not persisted: postgres unavailable")
        else:
            warnings.append("persistence disabled for this scan")

        summary = AnalysisSummary(
            analysis_id=analysis_id,
            device_id=cfg.device_id,
            status="completed",
            vendor=ApiVendor.from_internal(cfg.vendor),
            vendor_confidence=cfg.detected_vendor_confidence or 0.0,
            started_at=started,
            completed_at=datetime.now(UTC),
            overall_score=overall,
            framework_scores=scores,
            findings=findings,
            remediations=remediations,
            total_findings=len(findings),
            duration_ms=metrics.duration_ms,
            parse_warnings=list(cfg.parse_warnings),
            evidence_precision=cfg.evidence_precision,
            parser_coverage=1.0 - (cfg.unparsed_line_ratio or 0.0),
        )
        return PipelineResult(
            summary=summary,
            cfg=cfg,
            findings=findings,
            framework_scores=scores,
            remediations=remediations,
            anomaly=verdict,
            graph=graph_result,
            metrics=metrics,
            warnings=warnings,
        )

    # ------------------------------------------------------------------ #
    def _normalize(self, raw_text: str, *, device_id: str | None, analysis_id: str) -> NormalizedConfig:
        if not raw_text.strip():
            raise AnalysisError("uploaded configuration is empty")
        registry = get_registry()
        adapter, confidence, _ = registry.detect(raw_text)
        if adapter is None:
            raise AnalysisError(
                "could not identify the device vendor; expected Cisco IOS/NX-OS, "
                "Juniper Junos, Fortinet FortiOS or Palo Alto PAN-OS"
            )
        resolved_id = device_id or f"dev-{uuid.uuid4().hex[:12]}"
        cfg = adapter.run(raw_text, device_id=resolved_id)
        cfg.detected_vendor_confidence = confidence
        _ = analysis_id
        return cfg

    def _finalize_findings(self, cfg, outcomes, analysis_id) -> tuple[list[Finding], list]:
        """Rebuild the finding list from the final outcome set.

        ``RuleEngine.execute`` produces findings from rules only. The anomaly
        stage appends outcomes afterwards, so the finding list has to be
        regenerated or ML anomalies would silently never reach the dashboard.
        """
        return self.engine.outcomes_to_findings(cfg, outcomes, analysis_id=analysis_id), outcomes

    def _ingest_graph(
        self, cfg: NormalizedConfig, findings: list[Finding], analysis_id: str, warnings: list[str]
    ) -> GraphEnrichment | None:
        graph = self.graph
        if graph is None:
            return None
        if not graph.available:
            reason = graph.availability().reason or "graph unavailable"
            logger.info("skipping graph ingest: %s", reason)
            warnings.append(f"security graph not updated: {reason}")
            return None
        try:
            return graph.ingest(cfg, findings, analysis_id=analysis_id)
        except Exception as exc:  # noqa: BLE001 - graph enrichment must never fail a scan
            logger.warning("graph ingest failed: %s", exc)
            warnings.append(f"security graph not updated: {type(exc).__name__}")
            return None

    def _persist(
        self,
        *,
        analysis_id: str,
        cfg: NormalizedConfig,
        findings: list[Finding],
        scores: list[FrameworkScore],
        remediations: list[Remediation],
        metrics: AnalysisMetrics,
        warnings: list[str],
    ) -> bool:
        try:
            with session_scope() as session:
                if session is None:
                    return False
                persist_analysis(
                    session,
                    analysis_id=analysis_id,
                    cfg=cfg,
                    findings=findings,
                    framework_scores=scores,
                    remediations=remediations,
                    metrics=metrics,
                )
        except Exception as exc:  # noqa: BLE001 - report, do not lose the analysis
            logger.warning("persistence failed: %s", exc)
            warnings.append(f"results were not persisted: {type(exc).__name__}")
            return False
        return True


def insufficient_evidence(scores: list[FrameworkScore]) -> list[Framework]:
    """Frameworks whose score is too thin to act on. Surfaced, never hidden."""
    return [Framework(s.framework) for s in scores if not s.sufficient_evidence]


def severity_breakdown(findings: Sequence[Finding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
    for finding in findings:
        counts[Severity(finding.severity)] += 1
    return counts
