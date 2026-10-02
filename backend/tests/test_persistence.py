"""Persistence tests.

These run against **SQLite in memory**, not Postgres. Two reasons: the schema
here is deliberately portable (no Postgres-only column types), and a test suite
that needs a running database server is a test suite nobody runs before
committing. Postgres-specific behaviour is covered by the Docker integration
test in ``tests/integration/``.

Everything is driven through the real entry points -- ``engine.execute``,
``ComplianceScorer``, ``RemediationGenerator`` -- so this test breaks when the
pipeline changes shape, which is the point.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.analysis.compliance import ComplianceScorer
from app.db import repository
from app.db.models import (
    AnalysisRow,
    Base,
    DeviceRow,
    EvidenceRow,
    FindingControlRow,
    FindingRow,
    FrameworkScoreRow,
    RemediationRow,
)
from app.db.repository import AnalysisMetrics, persist_analysis
from app.normalize.models import NormalizedConfig, Vendor
from app.remediation.generator import RemediationGenerator
from app.schemas.api import Framework, Severity


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    with factory() as db:
        yield db
    engine.dispose()


@pytest.fixture(scope="module")
def scorer() -> ComplianceScorer:
    return ComplianceScorer()


@pytest.fixture(scope="module")
def generator() -> RemediationGenerator:
    return RemediationGenerator()


class _Scan:
    """Everything one full pipeline pass produces, plus the metrics to persist."""

    def __init__(self, cfg: NormalizedConfig, findings, outcomes, scores, plans, metrics) -> None:
        self.cfg = cfg
        self.findings = findings
        self.outcomes = outcomes
        self.scores = scores
        self.plans = plans
        self.metrics = metrics


@pytest.fixture
def scan(engine, scorer, generator) -> Iterator[object]:
    """Run the real pipeline over every vendor sample. Yields a callable."""

    def _run(cfg: NormalizedConfig, analysis_id: str) -> _Scan:
        findings, outcomes = engine.execute(cfg, analysis_id=analysis_id)
        scores = scorer.framework_scores(outcomes, vendor=cfg.vendor)
        plans = generator.generate(cfg, findings)
        overall, _ = scorer.overall_score(outcomes, cfg)
        metrics = AnalysisMetrics(
            overall_score=overall,
            assessable_weight=scorer.assessable_weight(outcomes),
            mean_confidence=(sum(f.confidence for f in findings) / len(findings) if findings else 0.0),
            indeterminate_count=scorer.indeterminate_count(outcomes),
            anomaly_scored=False,
            duration_ms=42,
        )
        return _Scan(cfg, findings, outcomes, scores, plans, metrics)

    yield _run


class TestPersistenceRoundTrip:
    def test_every_vendor_sample_persists_completely(self, session, scan, configs) -> None:
        for vendor, cfg in configs.items():
            result = scan(cfg, f"an-{vendor.value}")
            persist_analysis(
                session,
                analysis_id=f"an-{vendor.value}",
                cfg=cfg,
                findings=result.findings,
                framework_scores=result.scores,
                remediations=result.plans,
                metrics=result.metrics,
            )
        session.commit()

        assert len(session.scalars(select(DeviceRow)).all()) == len(configs)
        assert len(session.scalars(select(AnalysisRow)).all()) == len(configs)

        for vendor, cfg in configs.items():
            device = session.get(DeviceRow, cfg.device_id)
            assert device is not None, vendor
            assert device.vendor == str(vendor)
            assert device.config_sha256 is not None
            assert device.role == str(cfg.role)

    def test_findings_evidence_and_controls_survive_the_round_trip(self, session, scan, cisco) -> None:
        result = scan(cisco, "an-cisco")
        assert result.findings, "the CIS sample must produce at least one finding"
        persist_analysis(
            session,
            analysis_id="an-cisco",
            cfg=cisco,
            findings=result.findings,
            framework_scores=result.scores,
            remediations=result.plans,
            metrics=result.metrics,
        )
        session.commit()

        stored = {f.rule_id: f for f in session.scalars(select(FindingRow))}
        assert set(stored) == {f.rule_id for f in result.findings}

        for original in result.findings:
            row = stored[original.rule_id]
            assert row.severity == str(original.severity)
            assert row.confidence == pytest.approx(original.confidence)
            assert row.title == original.title

            evidence = session.scalars(select(EvidenceRow).where(EvidenceRow.finding_id == row.id)).all()
            assert [e.raw for e in evidence] == [line.raw for line in original.evidence]
            assert [e.line_no for e in evidence] == [line.line_no for line in original.evidence]

            controls = session.scalars(
                select(FindingControlRow).where(FindingControlRow.finding_id == row.id)
            ).all()
            assert {c.control_id for c in controls} == {
                f"{c.framework}:{c.control_id}" for c in original.controls
            } or {c.control_id for c in controls} == {c.control_id for c in original.controls}

    def test_framework_scores_match_the_scorer(self, session, scan, juniper) -> None:
        result = scan(juniper, "an-juniper")
        persist_analysis(
            session,
            analysis_id="an-juniper",
            cfg=juniper,
            findings=result.findings,
            framework_scores=result.scores,
            remediations=result.plans,
            metrics=result.metrics,
        )
        session.commit()

        rows = {r.framework: r for r in session.scalars(select(FrameworkScoreRow))}
        assert len(rows) == len(result.scores)
        for score in result.scores:
            row = rows[str(score.framework)]
            assert row.score == pytest.approx(score.score)
            assert row.failed == score.failed
            assert row.sufficient_evidence == score.sufficient_evidence


class TestSecurityInvariants:
    def test_persisted_evidence_is_already_redacted(self, session, scan, cisco) -> None:
        """The DB must never become the place a secret leaked to."""
        result = scan(cisco, "an-redact")
        persist_analysis(
            session,
            analysis_id="an-redact",
            cfg=cisco,
            findings=result.findings,
            framework_scores=result.scores,
            remediations=result.plans,
            metrics=result.metrics,
        )
        session.commit()

        blob = " ".join(
            [e.raw for e in session.scalars(select(EvidenceRow))]
            + [r.commands for r in session.scalars(select(RemediationRow))]
        ).lower()
        # The sample's secrets must appear only as redaction sentinels.
        assert "$1$" not in blob
        assert "cisco123" not in blob

    def test_no_plan_is_persisted_as_applied(self, session, scan, configs) -> None:
        for vendor, cfg in configs.items():
            result = scan(cfg, f"an-{vendor.value}")
            persist_analysis(
                session,
                analysis_id=f"an-{vendor.value}",
                cfg=cfg,
                findings=result.findings,
                framework_scores=result.scores,
                remediations=result.plans,
                metrics=result.metrics,
            )
        session.commit()

        plans = session.scalars(select(RemediationRow)).all()
        assert plans, "the samples are insecure on purpose, so plans must exist"
        for plan in plans:
            assert plan.applied_to_device is False
            assert plan.status == "pending_review"
            assert plan.reviewed_by is None
            assert plan.reviewed_at is None
            assert plan.applied_at is None

    def test_each_plan_links_back_to_its_finding(self, session, scan, cisco) -> None:
        result = scan(cisco, "an-link")
        persist_analysis(
            session,
            analysis_id="an-link",
            cfg=cisco,
            findings=result.findings,
            framework_scores=result.scores,
            remediations=result.plans,
            metrics=result.metrics,
        )
        session.commit()

        plans = session.scalars(select(RemediationRow)).all()
        linked = session.scalars(select(FindingRow).where(FindingRow.remediation_id.is_not(None))).all()
        assert len(linked) == len(plans)
        for finding in linked:
            plan = session.get(RemediationRow, finding.remediation_id)
            assert plan is not None
            assert plan.finding_id == finding.id

    def test_reupload_creates_a_new_analysis_not_an_overwrite(self, session, scan, cisco) -> None:
        for analysis_id in ("an-first", "an-second"):
            result = scan(cisco, analysis_id)
            persist_analysis(
                session,
                analysis_id=analysis_id,
                cfg=cisco,
                findings=result.findings,
                framework_scores=result.scores,
                remediations=result.plans,
                metrics=result.metrics,
            )
        session.commit()

        assert len(session.scalars(select(DeviceRow)).all()) == 1
        assert len(session.scalars(select(AnalysisRow)).all()) == 2

    def test_two_devices_of_the_same_vendor_stay_separate(self, session, scan, registry) -> None:
        raw = "hostname sw-{tag}\ntelnet 0.0.0.0 0 0\nservice password-encryption\n"
        cfgs = [
            registry.get(Vendor.CISCO_IOS).run(raw.format(tag=tag), device_id=f"dev-{tag}")
            for tag in ("a", "b")
        ]
        for cfg in cfgs:
            result = scan(cfg, f"an-{cfg.device_id}")
            persist_analysis(
                session,
                analysis_id=f"an-{cfg.device_id}",
                cfg=cfg,
                findings=result.findings,
                framework_scores=result.scores,
                remediations=result.plans,
                metrics=result.metrics,
            )
        session.commit()
        assert {d.id for d in session.scalars(select(DeviceRow))} == {"dev-a", "dev-b"}


class TestReadHelpers:
    def test_open_finding_counts_group_by_severity(self, session, scan, cisco) -> None:
        result = scan(cisco, "an-counts")
        persist_analysis(
            session,
            analysis_id="an-counts",
            cfg=cisco,
            findings=result.findings,
            framework_scores=result.scores,
            remediations=result.plans,
            metrics=result.metrics,
        )
        session.commit()

        expected: dict[str, int] = {}
        for finding in result.findings:
            key = str(finding.severity)
            expected[key] = expected.get(key, 0) + 1
        assert repository.open_finding_counts(session, cisco.device_id) == expected

    def test_counts_can_be_scoped_to_one_device(self, session, scan, registry) -> None:
        raw = "hostname sw-{tag}\ntelnet 0.0.0.0 0 0\nservice password-encryption\n"
        adapter = registry.get(Vendor.CISCO_IOS)
        insecure = adapter.run(raw.format(tag="a"), device_id="dev-a")
        baseline = adapter.run(
            "hostname sw-b\nservice password-encryption\nno ip domain-lookup\nlogging host 10.0.0.5\n",
            device_id="dev-b",
        )
        for cfg in (insecure, baseline):
            result = scan(cfg, f"an-{cfg.device_id}")
            persist_analysis(
                session,
                analysis_id=f"an-{cfg.device_id}",
                cfg=cfg,
                findings=result.findings,
                framework_scores=result.scores,
                remediations=result.plans,
                metrics=result.metrics,
            )
        session.commit()

        noisy = repository.open_finding_counts(session, "dev-a")
        baseline_counts = repository.open_finding_counts(session, "dev-b")
        # Scoping must return each device's own numbers, never a fleet total.
        assert sum(noisy.values()) > 0
        assert sum(baseline_counts.values()) < sum(noisy.values())
        assert noisy != baseline_counts

    def test_pending_count_tracks_the_review_workflow(self, session, scan, cisco) -> None:
        result = scan(cisco, "an-pending")
        persist_analysis(
            session,
            analysis_id="an-pending",
            cfg=cisco,
            findings=result.findings,
            framework_scores=result.scores,
            remediations=result.plans,
            metrics=result.metrics,
        )
        session.commit()

        pending = repository.pending_remediation_count(session)
        assert pending == len(result.plans)

        first = session.scalars(select(RemediationRow)).first()
        assert first is not None
        first.status = "approved"
        first.reviewed_by = "analyst@netguard.local"
        session.commit()
        assert repository.pending_remediation_count(session) == pending - 1


class TestSchemaGuards:
    def test_evidence_is_unique_per_finding_and_position(self, session, scan, cisco) -> None:
        """The unique constraint is what stops a retry duplicating evidence."""
        from sqlalchemy.exc import IntegrityError

        result = scan(cisco, "an-dup")
        persist_analysis(
            session,
            analysis_id="an-dup",
            cfg=cisco,
            findings=result.findings,
            framework_scores=result.scores,
            remediations=result.plans,
            metrics=result.metrics,
        )
        session.commit()

        existing = session.scalars(select(EvidenceRow)).first()
        assert existing is not None
        session.add(
            EvidenceRow(
                finding_id=existing.finding_id,
                position=existing.position,
                line_no=1,
                raw="duplicated",
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()

    def test_plan_is_one_per_finding(self, session, scan, cisco) -> None:
        from sqlalchemy.exc import IntegrityError

        result = scan(cisco, "an-unique")
        persist_analysis(
            session,
            analysis_id="an-unique",
            cfg=cisco,
            findings=result.findings,
            framework_scores=result.scores,
            remediations=result.plans,
            metrics=result.metrics,
        )
        session.commit()

        existing = session.scalars(select(RemediationRow)).first()
        assert existing is not None
        session.add(
            RemediationRow(
                id="duplicate-plan",
                finding_id=existing.finding_id,
                device_id=existing.device_id,
                title="second plan for the same finding",
            )
        )
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()


class TestFindingsQuery:
    """The /findings filters, exercised against the real query builder.

    These call the endpoint's own function with a SQLite session, because the
    filtering and pagination logic is what matters here; the HTTP layer above it
    is covered in test_api.py.
    """

    @pytest.fixture
    def populated(self, session, scan, configs) -> Session:
        for vendor, cfg in configs.items():
            result = scan(cfg, f"an-{vendor.value}")
            persist_analysis(
                session,
                analysis_id=f"an-{vendor.value}",
                cfg=cfg,
                findings=result.findings,
                framework_scores=result.scores,
                remediations=result.plans,
                metrics=result.metrics,
            )
        session.commit()
        return session

    @staticmethod
    def _call(session: Session, **kwargs: object):
        from app.api.v1.endpoints.dashboard import _query_findings

        # Unset filters must be None; the route's own defaults are irrelevant
        # here because this is the query half of the endpoint.
        defaults: dict[str, object] = {
            "severity": None,
            "status_filter": None,
            "device_id": None,
            "framework": None,
            "limit": 500,
            "offset": 0,
        }
        defaults.update(kwargs)
        return _query_findings(session, **defaults)

    def test_total_covers_every_match_not_just_the_page(self, populated) -> None:
        from app.db.models import FindingRow

        expected = populated.query(FindingRow).count()
        page = self._call(populated, limit=5, offset=0)
        assert page.total == expected
        assert len(page.items) == min(5, expected)

    def test_severity_filter_narrows_the_result(self, populated) -> None:
        from app.db.models import FindingRow

        target = populated.query(FindingRow).first()
        if target is None:
            pytest.skip("samples produced no findings")
        page = self._call(populated, severity=Severity(target.severity))
        assert page.total >= 1
        assert all(item.severity == target.severity for item in page.items)

    def test_device_filter_scopes_to_one_device(self, populated) -> None:
        from app.db.models import FindingRow

        target = populated.query(FindingRow).first()
        if target is None:
            pytest.skip("samples produced no findings")
        page = self._call(populated, device_id=target.device_id)
        assert page.total >= 1
        assert {item.device_id for item in page.items} == {target.device_id}

    def test_framework_filter_does_not_duplicate_findings(self, populated) -> None:
        """A finding can map to several controls of the same framework.

        The join must therefore be deduplicated, or both the total and the page
        would be inflated by the number of matching controls per finding.
        """
        from app.db.models import FindingRow

        linked = populated.query(FindingRow).join(FindingControlRow).first()
        if linked is None:
            pytest.skip("no findings are linked to a published control")
        framework = Framework(linked.controls[0].framework)

        page = self._call(populated, framework=framework)
        ids = [item.id for item in page.items]
        assert len(ids) == len(set(ids)), "the framework join duplicated findings"
        assert page.total == len(ids)

    def test_pagination_walks_the_set_without_overlapping(self, populated) -> None:
        from app.db.models import FindingRow

        if populated.query(FindingRow).count() < 4:
            pytest.skip("not enough findings to page through")

        first = self._call(populated, limit=2, offset=0)
        second = self._call(populated, limit=2, offset=2)
        assert len(first.items) == 2
        assert len(second.items) == 2
        assert {item.id for item in first.items}.isdisjoint({item.id for item in second.items})

    def test_each_finding_carries_its_remediation_id(self, populated) -> None:
        """The UI links a finding to its generated CLI through this field."""
        page = self._call(populated)
        with_plan = [item for item in page.items if item.remediation_id is not None]
        assert with_plan, "samples should generate at least one remediation"
        assert all(item.remediation_id for item in with_plan)
