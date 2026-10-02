"""v1 router: composes every endpoint module under one prefix."""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints import analysis, auth, dashboard, remediation, system

api_router = APIRouter()
api_router.include_router(system.router)
api_router.include_router(auth.router)
api_router.include_router(analysis.router)
api_router.include_router(dashboard.router)
api_router.include_router(remediation.router)

__all__ = ["api_router"]
