"""
FastAPI dependencies for the CaaS application.

This module provides dependency injection functions for FastAPI endpoints,
including authentication, database sessions, and request context.
"""

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional
import uuid

from app.db.session import get_db
from app.models.database import User
from app.core.auth.jwt_handler import decode_access_token


# HTTP Bearer security scheme
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Dependency to get the current authenticated user from JWT token.

    Args:
        credentials: HTTP Bearer credentials containing the JWT token
        db: Database session

    Returns:
        User: Authenticated user object

    Raises:
        HTTPException: 401 if token is invalid or user not found

    Example:
        @app.get("/protected")
        def protected_route(current_user: User = Depends(get_current_user)):
            return {"user": current_user.username}
    """
    # Extract token from credentials
    token = credentials.credentials

    # Decode and validate token
    payload = decode_access_token(token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract user ID from payload
    user_id = payload.get("user_id")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Fetch user from database
    user = db.query(User).filter(User.id == user_id).first()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    return user


async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(HTTPBearer(auto_error=False)),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Dependency to optionally get the current user (doesn't fail if no token).

    Args:
        credentials: Optional HTTP Bearer credentials
        db: Database session

    Returns:
        Optional[User]: User object if authenticated, None otherwise

    Example:
        @app.get("/public")
        def public_route(user: Optional[User] = Depends(get_optional_user)):
            if user:
                return {"message": f"Hello {user.username}"}
            return {"message": "Hello guest"}
    """
    if credentials is None:
        return None

    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None


def get_request_id(request: Request) -> str:
    """
    Get or generate a unique request ID for tracing.

    Args:
        request: FastAPI request object

    Returns:
        str: Request ID (UUID)

    Example:
        @app.get("/route")
        def route(request_id: str = Depends(get_request_id)):
            return {"request_id": request_id}
    """
    # Check if request ID already exists in state
    if hasattr(request.state, "request_id"):
        return request.state.request_id

    # Generate new request ID
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    return request_id


def get_client_ip(request: Request) -> str:
    """
    Get the client's IP address from the request.

    Args:
        request: FastAPI request object

    Returns:
        str: Client IP address

    Example:
        @app.get("/route")
        def route(client_ip: str = Depends(get_client_ip)):
            return {"ip": client_ip}
    """
    # Check for X-Forwarded-For header (proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(",")[0].strip()

    # Check for X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fall back to direct client host
    if request.client:
        return request.client.host

    return "unknown"


def get_user_agent(request: Request) -> Optional[str]:
    """
    Get the User-Agent header from the request.

    Args:
        request: FastAPI request object

    Returns:
        Optional[str]: User-Agent string or None

    Example:
        @app.get("/route")
        def route(user_agent: str = Depends(get_user_agent)):
            return {"user_agent": user_agent}
    """
    return request.headers.get("User-Agent")
