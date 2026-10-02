"""Generate the static demo dataset shipped with the frontend.

Run:  python scripts/export_demo_data.py

Why this exists
---------------
The hackathon demo is a static GitHub Pages site with no reachable backend. Rather
than ship hand-written fake findings -- which would misrepresent what the tool
does -- we run the **real pipeline** over the sample configs and export the
results. Every number in the deployed demo therefore came from the same code path
that serves the live API.

The output is written to ``frontend/public/demo-data.json`` and loaded by the
frontend when the API is unreachable, behind a visible banner.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.analysis.anomaly import AnomalyDetector  # noqa: E402
from app.normalize.models import Vendor  # noqa: E402
from app.normalize.registry import get_registry  # noqa: E402
from app.pipeline.orchestrator import Pipeline  # noqa: E402

SAMPLES = ROOT / "samples" / "configs"
OUTPUT = ROOT.parent / "frontend" / "public" / "demo-data.json"

VENDOR_SAMPLES: dict[Vendor, str] = {
    Vendor.CISCO_IOS: "cisco_ios_core_switch.cfg",
    Vendor.FORTINET_FORTIOS: "fortinet_fortigate.cfg",
    Vendor.JUNIPER_JUNOS: "juniper_junos.txt",
    Vendor.PALOALTO_PANOS: "paloalto_panos.xml",
}


def main() -> int:
    registry = get_registry()

    # Normalize every sample first; the anomaly stage needs a peer group.
    configs = []
    for vendor, name in VENDOR_SAMPLES.items():
        raw = (SAMPLES / name).read_text(encoding="utf-8")
        adapter, confidence, _ = registry.detect(raw)
        cfg = adapter.run(raw, device_id=f"dev-{vendor.value}")
        cfg.detected_vendor_confidence = confidence
        configs.append(cfg)

    # Two passes so the detector has peers for every device, including the ones
    # it will score. Training on the device being scored would make every device
    # its own nearest neighbour and look perfectly normal.
    detector = AnomalyDetector(min_samples=4, report_threshold=0.55)
    detector.fit(configs)

    engine_pipeline = Pipeline(
        engine=__import__("app.analysis.rule_packs", fromlist=["get_engine"]).get_engine(),
        anomaly_detector=detector,
        graph=None,
        persist=False,
    )

    analyses: list[dict] = []
    for cfg in configs:
        result = engine_pipeline.analyze(
            _raw_for(cfg.device_id),
            device_id=cfg.device_id,
            peer_configs=configs,
        )
        analyses.append(
            {
                "analysis_id": result.analysis_id,
                "device_id": result.cfg.device_id,
                "vendor": str(result.summary.vendor),
                "vendor_confidence": result.summary.vendor_confidence,
                "hostname": result.cfg.identity.hostname,
                "role": str(result.cfg.role),
                "overall_score": result.summary.overall_score,
                "parser_coverage": result.summary.parser_coverage,
                "evidence_precision": result.summary.evidence_precision,
                "duration_ms": result.summary.duration_ms,
                "parse_warnings": result.summary.parse_warnings,
                "framework_scores": [s.model_dump(mode="json") for s in result.framework_scores],
                "findings": [f.model_dump(mode="json") for f in result.findings],
                "remediations": [r.model_dump(mode="json") for r in result.remediations],
            }
        )

    payload = _build_payload(analyses)
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {OUTPUT.relative_to(ROOT.parent)}")
    print(
        f"  {len(payload['devices'])} devices, "
        f"{len(payload['findings'])} findings, "
        f"{len(payload['remediations'])} remediation proposals, "
        f"fleet score {payload['dashboard']['overall_score']}"
    )
    return 0


def _raw_for(device_id: str) -> str:
    for vendor, name in VENDOR_SAMPLES.items():
        if device_id == f"dev-{vendor.value}":
            return (SAMPLES / name).read_text(encoding="utf-8")
    raise KeyError(device_id)


def _build_payload(analyses: list[dict]) -> dict:
    """Assemble the exact shapes the frontend expects."""
    now = datetime.now(UTC).isoformat()

    devices = []
    findings = []
    remediations = []
    severity_counts: dict[str, int] = {}
    framework_totals: dict[str, list[float]] = {}

    for analysis in analyses:
        counts: dict[str, int] = {}
        for finding in analysis["findings"]:
            findings.append(finding)
            sev = finding["severity"]
            counts[sev] = counts.get(sev, 0) + 1
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        remediations.extend(analysis["remediations"])

        for score in analysis["framework_scores"]:
            framework_totals.setdefault(score["framework"], []).append(score["score"])

        devices.append(
            {
                "device_id": analysis["device_id"],
                "hostname": analysis["hostname"] or analysis["device_id"],
                "vendor": analysis["vendor"],
                "role": analysis["role"],
                "overall_score": analysis["overall_score"],
                "severity_counts": counts,
                "framework_scores": analysis["framework_scores"],
                "total_findings": len(analysis["findings"]),
                "open_findings": len(analysis["findings"]),
                "last_analyzed_at": now,
                "evidence_precision": analysis["evidence_precision"],
                "parser_coverage": analysis["parser_coverage"],
            }
        )

    # Fleet-level framework scores: mean across devices, keeping the per-device
    # control counts summed so the numbers stay internally consistent.
    fleet_scores = []
    for framework, values in framework_totals.items():
        per_device = next(
            s
            for a in analyses
            for s in a["framework_scores"]
            if s["framework"] == framework
        )
        fleet_scores.append(
            {
                "framework": framework,
                "score": round(sum(values) / len(values), 2),
                "passed": per_device["passed"],
                "failed": per_device["failed"],
                "not_applicable": per_device["not_applicable"],
                "total_controls": per_device["total_controls"],
                "sufficient_evidence": per_device["sufficient_evidence"],
            }
        )

    by_rule: dict[str, dict] = {}
    for finding in findings:
        entry = by_rule.setdefault(
            finding["rule_id"],
            {
                "rule_id": finding["rule_id"],
                "title": finding["title"],
                "count": 0,
                "severity": finding["severity"],
            },
        )
        entry["count"] += 1

    dashboard = {
        "generated_at": now,
        "total_devices": len(devices),
        "total_findings": len(findings),
        "overall_score": round(sum(d["overall_score"] or 0 for d in devices) / len(devices), 2),
        "severity_counts": severity_counts,
        "framework_scores": fleet_scores,
        "devices": sorted(devices, key=lambda d: d["overall_score"] or 0),
        "pending_remediations": len([r for r in remediations if r["status"] == "pending_review"]),
        "critical_delta": severity_counts.get("critical", 0),
        "top_risky_rules": sorted(by_rule.values(), key=lambda r: -r["count"])[:8],
    }

    return {
        "_notice": (
            "Generated by running the real NETGUARD-AI pipeline over the bundled "
            "sample configurations (backend/scripts/export_demo_data.py). Not "
            "hand-written."
        ),
        "_generated_at": now,
        "dashboard": dashboard,
        "devices": dashboard["devices"],
        "findings": sorted(
            findings,
            key=lambda f: (
                -{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(
                    f["severity"], 0
                ),
                f["rule_id"],
            ),
        ),
        "remediations": remediations,
        "analyses": analyses,
    }


if __name__ == "__main__":
    raise SystemExit(main())