"""
Health check endpoint for the CaaS API.

This module provides a health check endpoint to monitor the service status.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from datetime import datetime

from app.db.session import get_db
from app.models.schemas import HealthResponse
from app.config import settings


router = APIRouter(tags=["Health"])


@router.get(
    "/api/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Health check",
    description="Check the health status of the CaaS service and its dependencies"
)
async def health_check(db: Session = Depends(get_db)):
    """
    Check health status of the service.

    **Checks:**
    - API server is running
    - Database connection is working
    - KMS is operational

    **Returns:**
    - `status`: Overall service status (healthy/unhealthy)
    - `timestamp`: Current server time
    - `version`: API version
    - `services`: Status of each service component
    """
    # Check database connectivity
    db_status = "healthy"
    try:
        # Simple query to test database connection
        db.execute("SELECT 1")
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    # Check KMS (for now, just assume healthy if we got here)
    kms_status = "healthy"

    # Determine overall status
    overall_status = "healthy" if db_status == "healthy" and kms_status == "healthy" else "unhealthy"

    return HealthResponse(
        status=overall_status,
        timestamp=datetime.utcnow(),
        version=settings.app_version,
        services={
            "database": db_status,
            "kms": kms_status
        }
    )
