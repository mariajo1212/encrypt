"""
JWT token handler for authentication and authorization.

This module provides functions for creating and validating JWT tokens
for access and refresh token management.
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
import uuid

from app.config import settings


def create_access_token(
    user_id: int,
    username: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT access token.

    Args:
        user_id: User's database ID
        username: User's username
        expires_delta: Optional custom expiration time

    Returns:
        str: Encoded JWT access token

    Example:
        >>> token = create_access_token(user_id=1, username="admin")
        >>> payload = decode_access_token(token)
        >>> payload['user_id']
        1
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)

    # Token payload
    to_encode = {
        "user_id": user_id,
        "username": username,
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()),  # Unique token ID
        "type": "access"
    }

    # Encode token
    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm
    )

    return encoded_jwt


def create_refresh_token(
    user_id: int,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Create a JWT refresh token.

    Args:
        user_id: User's database ID
        expires_delta: Optional custom expiration time

    Returns:
        str: Encoded JWT refresh token

    Example:
        >>> token = create_refresh_token(user_id=1)
        >>> payload = decode_refresh_token(token)
        >>> payload['type']
        'refresh'
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)

    # Token payload (minimal for refresh tokens)
    to_encode = {
        "user_id": user_id,
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": str(uuid.uuid4()),
        "type": "refresh"
    }

    # Encode token
    encoded_jwt = jwt.encode(
        to_encode,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm
    )

    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode and validate a JWT access token.

    Args:
        token: JWT token string to decode

    Returns:
        Optional[Dict[str, Any]]: Token payload if valid, None if invalid

    Example:
        >>> token = create_access_token(user_id=1, username="admin")
        >>> payload = decode_access_token(token)
        >>> payload['username']
        'admin'
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm]
        )

        # Verify token type
        if payload.get("type") != "access":
            return None

        return payload

    except jwt.ExpiredSignatureError:
        # Token has expired
        return None
    except jwt.JWTError:
        # Invalid token
        return None


def decode_refresh_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode and validate a JWT refresh token.

    Args:
        token: JWT token string to decode

    Returns:
        Optional[Dict[str, Any]]: Token payload if valid, None if invalid

    Example:
        >>> token = create_refresh_token(user_id=1)
        >>> payload = decode_refresh_token(token)
        >>> payload['user_id']
        1
    """
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm]
        )

        # Verify token type
        if payload.get("type") != "refresh":
            return None

        return payload

    except jwt.ExpiredSignatureError:
        # Token has expired
        return None
    except jwt.JWTError:
        # Invalid token
        return None


def get_token_expiration(token: str) -> Optional[datetime]:
    """
    Get the expiration time of a token without full validation.

    Args:
        token: JWT token string

    Returns:
        Optional[datetime]: Expiration datetime if decodable, None otherwise

    Example:
        >>> token = create_access_token(user_id=1, username="admin")
        >>> exp = get_token_expiration(token)
        >>> exp > datetime.utcnow()
        True
    """
    try:
        # Decode without verification to get expiration
        payload = jwt.decode(
            token,
            options={"verify_signature": False}
        )
        exp_timestamp = payload.get("exp")
        if exp_timestamp:
            return datetime.fromtimestamp(exp_timestamp)
        return None
    except jwt.JWTError:
        return None


def is_token_expired(token: str) -> bool:
    """
    Check if a token is expired.

    Args:
        token: JWT token string

    Returns:
        bool: True if expired, False otherwise

    Example:
        >>> token = create_access_token(user_id=1, username="admin")
        >>> is_token_expired(token)
        False
    """
    exp = get_token_expiration(token)
    if exp is None:
        return True
    return datetime.utcnow() > exp
