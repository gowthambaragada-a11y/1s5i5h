"""ASGI application factory.

Notes on the middleware stack
-----------------------------
* **CORS** is restricted to the configured origins with credentials enabled,
  because the dashboard is a separate dev server. A wildcard origin plus
  credentials would be rejected by browsers anyway, so the failure would be
  silent rather than obvious -- better to fail loudly at startup.
* **Security headers** are set on every response. This is an API that displays
  configuration lines an attacker may have crafted, so the CSP is deliberately
  strict and framing is denied outright.
* **Request IDs** are attached so a UI error can be tied to a log line.
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)
logger = logging.getLogger(__name__)

DESCRIPTION = """
NETGUARD-AI -- network device configuration analysis.

Uploads a Cisco IOS/NX-OS, Juniper Junos, Fortinet FortiOS or Palo Alto PAN-OS
configuration and returns evidence-backed findings, framework compliance scores
and human-reviewable remediation proposals.

**This service assesses and proposes. It never applies changes to a device.**
""".strip()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    logger.info("starting NETGUARD-AI API (graph_enabled=%s)", settings.graph_enabled)
    try:
        yield
    finally:
        from app.api.deps import reset_pipeline
        from app.db.session import dispose

        reset_pipeline()
        dispose()
        logger.info("NETGUARD-AI API stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="NETGUARD-AI",
        description=DESCRIPTION,
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Token", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )
    app.middleware("http")(security_headers)
    app.middleware("http")(request_context)

    from app.api.v1 import api_router

    app.include_router(api_router, prefix=settings.api_v1_prefix)

    @app.get("/", include_in_schema=False)
    def root() -> dict[str, str]:
        return {
            "service": "NETGUARD-AI",
            "version": "0.1.0",
            "docs": "/docs",
            "api": settings.api_v1_prefix,
        }

    return app


async def request_context(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    """Attach a request id and log the outcome. Never leaks internals."""
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]
    request.state.request_id = request_id
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        elapsed = (time.perf_counter() - started) * 1000
        logger.exception(
            "%s %s failed after %.1fms [req:%s]", request.method, request.url.path, elapsed, request_id
        )
        # A stack trace is for the log; the client gets a correlation id.
        return JSONResponse(
            status_code=500,
            content={"detail": "internal error", "request_id": request_id},
            headers={"X-Request-ID": request_id},
        )
    elapsed = (time.perf_counter() - started) * 1000
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "%s %s -> %s in %.1fms [req:%s]",
        request.method,
        request.url.path,
        response.status_code,
        elapsed,
        request_id,
    )
    return response


async def security_headers(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    """Response hardening. Findings contain attacker-influenceable text."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    # The API serves JSON only; nothing here should ever be framed or scripted
    # into another origin.
    response.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
    if request.url.path.endswith(("/docs", "/openapi.json")) or "docs" in request.url.path:
        # Swagger UI needs inline styles and its own bundle.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "frame-ancestors 'none'"
        )
    response.headers.setdefault("Cache-Control", "no-store")
    return response


app = create_app()
