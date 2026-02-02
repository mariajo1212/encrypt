"""
Audit log endpoints for the CaaS API.

This module provides endpoints for querying audit logs.
"""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional

from app.db.session import get_db
from app.models.database import User
from app.models.schemas import AuditLogResponse, AuditLogListResponse
from app.dependencies import get_current_user
from app.core.audit.logger import query_audit_logs


router = APIRouter(prefix="/api/audit", tags=["Audit"])


@router.get(
    "/logs",
    response_model=AuditLogListResponse,
    status_code=status.HTTP_200_OK,
    summary="Query audit logs",
    description="Retrieve audit logs with optional filtering"
)
async def get_audit_logs(
    operation: Optional[str] = Query(None, description="Filter by operation type"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    start_date: Optional[datetime] = Query(None, description="Filter by start date"),
    end_date: Optional[datetime] = Query(None, description="Filter by end date"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(50, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Query audit logs.

    **Filters:**
    - `operation`: Filter by operation type (encrypt, decrypt, sign, etc.)
    - `status`: Filter by status (success, failure)
    - `start_date`: Filter by start date (ISO format)
    - `end_date`: Filter by end date (ISO format)

    **Pagination:**
    - `page`: Page number (starts at 1)
    - `limit`: Number of items per page (max 100)

    **Note:** Users can only see their own audit logs.
    """
    # Query logs (filtered by current user)
    logs, total = await query_audit_logs(
        db=db,
        user_id=current_user.id,
        operation=operation,
        status=status_filter,
        start_date=start_date,
        end_date=end_date,
        page=page,
        limit=limit
    )

    # Convert to response models
    log_responses = [AuditLogResponse.model_validate(log) for log in logs]

    return AuditLogListResponse(
        logs=log_responses,
        total=total,
        page=page,
        limit=limit
    )
