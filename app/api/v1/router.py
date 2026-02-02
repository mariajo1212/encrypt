"""
Main API router aggregator for v1 endpoints.

This module combines all endpoint routers into a single APIRouter
that can be included in the FastAPI application.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import auth, health, keys, crypto, audit


# Create main API v1 router
api_router = APIRouter()


# Include all endpoint routers
api_router.include_router(auth.router)
api_router.include_router(health.router)
api_router.include_router(keys.router)
api_router.include_router(crypto.router)
api_router.include_router(audit.router)
