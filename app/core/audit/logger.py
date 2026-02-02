"""
Audit logging module for tracking all operations.

This module provides functionality to log all cryptographic operations
and security events for compliance and security monitoring.
"""

from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import and_

from app.models.database import AuditLog
from app.models.enums import OperationType, OperationStatus, ResourceType


async def create_audit_log(
    db: Session,
    user_id: Optional[int],
    username: Optional[str],
    operation: OperationType,
    resource_type: Optional[ResourceType] = None,
    resource_id: Optional[str] = None,
    status: OperationStatus = OperationStatus.SUCCESS,
    error_message: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None
) -> AuditLog:
    """
    Create an audit log entry.

    Args:
        db: Database session
        user_id: ID of user performing operation
        username: Username of user
        operation: Type of operation
        resource_type: Type of resource affected
        resource_id: ID of resource
        status: Operation status (success/failure)
        error_message: Error message if failed
        ip_address: Client IP address
        user_agent: Client user agent
        request_id: Unique request ID
        metadata: Additional context

    Returns:
        AuditLog: Created audit log entry
    """
    audit_log = AuditLog(
        timestamp=datetime.utcnow(),
        user_id=user_id,
        username=username,
        operation=operation.value if isinstance(operation, OperationType) else operation,
        resource_type=resource_type.value if isinstance(resource_type, ResourceType) else resource_type,
        resource_id=resource_id,
        status=status.value if isinstance(status, OperationStatus) else status,
        error_message=error_message,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        log_metadata=metadata
    )

    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)

    return audit_log


async def query_audit_logs(
    db: Session,
    user_id: Optional[int] = None,
    operation: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    page: int = 1,
    limit: int = 50
):
    """
    Query audit logs with filters.

    Args:
        db: Database session
        user_id: Filter by user ID
        operation: Filter by operation type
        status: Filter by status
        start_date: Filter by start date
        end_date: Filter by end date
        page: Page number
        limit: Items per page

    Returns:
        tuple: (logs, total_count)
    """
    query = db.query(AuditLog)

    # Apply filters
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if operation:
        query = query.filter(AuditLog.operation == operation)
    if status:
        query = query.filter(AuditLog.status == status)
    if start_date:
        query = query.filter(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.filter(AuditLog.timestamp <= end_date)

    # Get total count
    total = query.count()

    # Apply pagination
    offset = (page - 1) * limit
    logs = query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()

    return logs, total
