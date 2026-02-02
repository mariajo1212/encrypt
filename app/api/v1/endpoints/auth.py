"""
Authentication endpoints for the CaaS API.

This module provides endpoints for user login, token refresh, and authentication.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta, datetime
import hashlib

from app.db.session import get_db
from app.models.database import User, RefreshToken
from app.models.schemas import LoginRequest, TokenResponse, RefreshTokenRequest
from app.core.auth.password_utils import verify_password
from app.core.auth.jwt_handler import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token
)
from app.config import settings


router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/token",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Login and obtain tokens",
    description="Authenticate with username/email and password to receive access and refresh tokens"
)
async def login(
    credentials: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return JWT tokens.

    **Process:**
    1. Validate username/email and password
    2. Generate access token (short-lived, 30 minutes)
    3. Generate refresh token (long-lived, 7 days)
    4. Store refresh token hash in database
    5. Return both tokens

    **Returns:**
    - `access_token`: Use for API authentication (Bearer token)
    - `refresh_token`: Use to obtain new access tokens
    - `expires_in`: Access token expiration time in seconds
    """
    # Find user by username or email
    user = db.query(User).filter(
        (User.username == credentials.username) | (User.email == credentials.username)
    ).first()

    # Validate user exists
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Validate password
    if not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    # Generate access token
    access_token = create_access_token(
        user_id=user.id,
        username=user.username
    )

    # Generate refresh token
    refresh_token = create_refresh_token(user_id=user.id)

    # Hash refresh token for storage
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()

    # Store refresh token in database
    # Convert Unix timestamp to datetime object
    exp_timestamp = decode_refresh_token(refresh_token)["exp"]
    db_refresh_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.fromtimestamp(exp_timestamp)
    )
    db.add(db_refresh_token)
    db.commit()

    # Return tokens
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="Bearer",
        expires_in=settings.access_token_expire_minutes * 60
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description="Use refresh token to obtain a new access token"
)
async def refresh_access_token(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """
    Refresh access token using a valid refresh token.

    **Process:**
    1. Validate refresh token
    2. Check if token is in database and not revoked
    3. Generate new access token
    4. Return new access token (refresh token remains same)

    **Note:** The refresh token itself is not renewed. Once it expires,
    the user must log in again.
    """
    # Decode and validate refresh token
    payload = decode_refresh_token(request.refresh_token)

    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract user ID
    user_id = payload.get("user_id")

    # Hash refresh token to check database
    token_hash = hashlib.sha256(request.refresh_token.encode()).hexdigest()

    # Check if refresh token exists and is not revoked
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash,
        RefreshToken.user_id == user_id,
        RefreshToken.revoked == False
    ).first()

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found or has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Get user
    user = db.query(User).filter(User.id == user_id).first()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generate new access token
    access_token = create_access_token(
        user_id=user.id,
        username=user.username
    )

    # Return new access token
    return TokenResponse(
        access_token=access_token,
        refresh_token=None,  # Don't return refresh token (it's unchanged)
        token_type="Bearer",
        expires_in=settings.access_token_expire_minutes * 60
    )


@router.post(
    "/revoke",
    status_code=status.HTTP_200_OK,
    summary="Revoke refresh token (logout)",
    description="Revoke a refresh token to log out"
)
async def revoke_refresh_token(
    request: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """
    Revoke a refresh token (logout functionality).

    **Process:**
    1. Validate refresh token
    2. Mark token as revoked in database
    3. Prevent future use of this refresh token

    **Note:** Access tokens cannot be revoked (they expire naturally).
    For immediate logout, client should discard the access token.
    """
    # Hash refresh token
    token_hash = hashlib.sha256(request.refresh_token.encode()).hexdigest()

    # Find and revoke token
    db_token = db.query(RefreshToken).filter(
        RefreshToken.token_hash == token_hash
    ).first()

    if db_token:
        from datetime import datetime
        db_token.revoked = True
        db_token.revoked_at = datetime.utcnow()
        db.commit()

    # Return success (even if token not found, for security)
    return {"message": "Refresh token revoked successfully"}
