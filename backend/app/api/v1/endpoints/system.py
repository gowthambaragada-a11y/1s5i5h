"""System endpoints: health and readiness.

``/healthz`` is a liveness check that must never touch a dependency, so a
database outage cannot take the service out of a load balancer's rotation.
``/readyz`` is the one that reports what is actually degraded -- the orchestrator
pipeline must be up, while Postgres and Neo4j are reported but not required.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter

from app.db.graph import SecurityGraph
from app.db.session import is_available, unavailable_reason

router = APIRouter(tags=["system"])


@router.get("/healthz")
def healthz() -> dict[str, Any]:
    """Liveness. No dependency checks -- that is /readyz's job."""
    return {"status": "ok", "service": "netguard-ai", "time": datetime.now(UTC)}


@router.get("/readyz")
def readyz() -> dict[str, Any]:
    """Readiness with an honest account of what is switched off."""
    from app.pipeline.orchestrator import Pipeline

    pipeline_ok = True
    pipeline_error: str | None = None
    try:
        Pipeline.build()
    except Exception as exc:  # noqa: BLE001 - report, do not crash the probe
        pipeline_ok = False
        pipeline_error = f"{type(exc).__name__}: {exc}"

    graph = SecurityGraph.from_settings()
    graph_status = graph.availability().as_dict()
    graph.close()

    postgres_ok = is_available()
    return {
        # Only the pipeline is required. Without Postgres the tool still scans;
        # it just cannot keep history.
        "status": "ready" if pipeline_ok else "degraded",
        "pipeline": {"ready": pipeline_ok, "error": pipeline_error},
        "postgres": {
            "available": postgres_ok,
            "reason": None if postgres_ok else (unavailable_reason() or "unreachable"),
        },
        "neo4j": graph_status,
        "time": datetime.now(UTC),
    }
