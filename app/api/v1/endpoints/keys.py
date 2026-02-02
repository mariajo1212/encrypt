"""
Key management endpoints for the CaaS API.

This module provides endpoints for creating, listing, retrieving, and deleting
cryptographic keys.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from app.db.session import get_db
from app.models.database import User, Key
from app.models.schemas import (
    KeyCreateRequest, KeyResponse, KeyListResponse, MessageResponse
)
from app.models.enums import KeyType, AlgorithmType
from app.dependencies import get_current_user
from app.core.kms.key_manager import get_key_manager


router = APIRouter(prefix="/api/keys", tags=["Key Management"])


@router.post(
    "",
    response_model=KeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new cryptographic key",
    description="Generate a new symmetric or asymmetric cryptographic key"
)
async def create_key(
    request: KeyCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new cryptographic key.

    **Supported Key Types:**
    - `symmetric`: AES-256 symmetric encryption key
    - `rsa_private` / `rsa_public`: RSA key pair (2048 or 4096 bits)
    - `ecc_private` / `ecc_public`: Elliptic Curve key pair (P-256, P-384, P-521)

    **Process:**
    1. Validate key type and algorithm compatibility
    2. Generate key(s) using secure random number generator
    3. Encrypt key(s) with master key before storage
    4. Store encrypted key(s) in database
    5. Return key metadata (never the actual key material)

    **Note:** For asymmetric keys, this endpoint generates a key pair and returns
    the private key metadata. Query the returned key_id to get the private key,
    and use the public_key_id from metadata to get the public key.
    """
    key_manager = get_key_manager()

    try:
        # Generate key based on type
        if request.key_type == KeyType.SYMMETRIC:
            # Generate symmetric key
            db_key = key_manager.generate_symmetric_key(
                key_name=request.key_name,
                user_id=current_user.id,
                algorithm=request.algorithm,
                expires_in_days=request.expires_in_days,
                db=db
            )
            # Convert to dict to avoid SQLAlchemy metadata conflicts
            key_dict = {
                "id": db_key.id,
                "key_name": db_key.key_name,
                "key_type": db_key.key_type,
                "algorithm": db_key.algorithm,
                "created_at": db_key.created_at,
                "expires_at": db_key.expires_at,
                "is_active": db_key.is_active,
                "key_metadata": db_key.key_metadata
            }
            return KeyResponse.model_validate(key_dict)

        elif request.key_type in [KeyType.RSA_PRIVATE, KeyType.RSA_PUBLIC]:
            # For RSA, we always generate a pair
            # If user requests RSA key, generate pair and return private key
            if request.algorithm not in [AlgorithmType.RSA_2048, AlgorithmType.RSA_4096]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Algorithm {request.algorithm} is not valid for RSA keys"
                )

            private_key, public_key = key_manager.generate_rsa_key_pair(
                key_name=request.key_name,
                user_id=current_user.id,
                algorithm=request.algorithm,
                expires_in_days=request.expires_in_days,
                db=db
            )

            # Return private key (metadata includes public_key_id)
            key_dict = {
                "id": private_key.id,
                "key_name": private_key.key_name,
                "key_type": private_key.key_type,
                "algorithm": private_key.algorithm,
                "created_at": private_key.created_at,
                "expires_at": private_key.expires_at,
                "is_active": private_key.is_active,
                "key_metadata": private_key.key_metadata
            }
            return KeyResponse.model_validate(key_dict)

        elif request.key_type in [KeyType.ECC_PRIVATE, KeyType.ECC_PUBLIC]:
            # For ECC, we always generate a pair
            if request.algorithm not in [AlgorithmType.ECC_P256, AlgorithmType.ECC_P384, AlgorithmType.ECC_P521]:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Algorithm {request.algorithm} is not valid for ECC keys"
                )

            private_key, public_key = key_manager.generate_ecc_key_pair(
                key_name=request.key_name,
                user_id=current_user.id,
                algorithm=request.algorithm,
                expires_in_days=request.expires_in_days,
                db=db
            )

            # Return private key (metadata includes public_key_id)
            key_dict = {
                "id": private_key.id,
                "key_name": private_key.key_name,
                "key_type": private_key.key_type,
                "algorithm": private_key.algorithm,
                "created_at": private_key.created_at,
                "expires_at": private_key.expires_at,
                "is_active": private_key.is_active,
                "key_metadata": private_key.key_metadata
            }
            return KeyResponse.model_validate(key_dict)

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported key type: {request.key_type}"
            )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create key: {str(e)}"
        )


@router.get(
    "",
    response_model=KeyListResponse,
    status_code=status.HTTP_200_OK,
    summary="List cryptographic keys",
    description="List all keys belonging to the authenticated user with optional filtering"
)
async def list_keys(
    key_type: Optional[str] = Query(None, description="Filter by key type"),
    algorithm: Optional[str] = Query(None, description="Filter by algorithm"),
    is_active: Optional[bool] = Query(True, description="Filter by active status (default: True)"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(10, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List keys belonging to the authenticated user.

    **Filters:**
    - `key_type`: Filter by key type (symmetric, rsa_private, rsa_public, etc.)
    - `algorithm`: Filter by algorithm (AES-256, RSA-2048, ECC-P256, etc.)
    - `is_active`: Filter by active status (true/false)

    **Pagination:**
    - `page`: Page number (starts at 1)
    - `limit`: Number of items per page (max 100)

    **Note:** Only metadata is returned. Actual key material is never exposed
    through this endpoint.
    """
    # Start query
    query = db.query(Key).filter(Key.user_id == current_user.id)

    # Apply filters
    if key_type:
        query = query.filter(Key.key_type == key_type)
    if algorithm:
        query = query.filter(Key.algorithm == algorithm)
    if is_active is not None:
        query = query.filter(Key.is_active == is_active)

    # Get total count
    total = query.count()

    # Apply pagination
    offset = (page - 1) * limit
    keys = query.order_by(Key.created_at.desc()).offset(offset).limit(limit).all()

    # Convert to response models
    key_responses = []
    for key in keys:
        key_dict = {
            "id": key.id,
            "key_name": key.key_name,
            "key_type": key.key_type,
            "algorithm": key.algorithm,
            "created_at": key.created_at,
            "expires_at": key.expires_at,
            "is_active": key.is_active,
            "key_metadata": key.key_metadata
        }
        key_responses.append(KeyResponse.model_validate(key_dict))

    return KeyListResponse(
        keys=key_responses,
        total=total,
        page=page,
        limit=limit
    )


@router.get(
    "/{key_id}",
    response_model=KeyResponse,
    status_code=status.HTTP_200_OK,
    summary="Get key details",
    description="Retrieve metadata for a specific key"
)
async def get_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get metadata for a specific key.

    **Returns:**
    - Key metadata including name, type, algorithm, creation date, etc.
    - Does NOT return the actual key material (for security)

    **Note:** Users can only retrieve their own keys.
    """
    # Fetch key
    db_key = db.query(Key).filter(
        Key.id == key_id,
        Key.user_id == current_user.id
    ).first()

    if not db_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {key_id} not found"
        )

    key_dict = {
        "id": db_key.id,
        "key_name": db_key.key_name,
        "key_type": db_key.key_type,
        "algorithm": db_key.algorithm,
        "created_at": db_key.created_at,
        "expires_at": db_key.expires_at,
        "is_active": db_key.is_active,
        "key_metadata": db_key.key_metadata
    }
    return KeyResponse.model_validate(key_dict)


@router.delete(
    "/{key_id}",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Delete a key",
    description="Permanently delete a cryptographic key"
)
async def delete_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a cryptographic key.

    **Warning:** This action is permanent and cannot be undone. Any data
    encrypted with this key will become unrecoverable.

    **Process:**
    1. Verify key exists and belongs to current user
    2. Mark key as inactive (soft delete)
    3. Optionally, hard delete from database (not implemented yet)

    **Note:** Users can only delete their own keys.
    """
    # Fetch key
    db_key = db.query(Key).filter(
        Key.id == key_id,
        Key.user_id == current_user.id
    ).first()

    if not db_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {key_id} not found"
        )

    # Soft delete: mark as inactive
    db_key.is_active = False
    db.commit()

    # Alternatively, hard delete (uncomment if desired):
    # db.delete(db_key)
    # db.commit()

    return MessageResponse(
        message="Key deleted successfully",
        details={"key_id": key_id}
    )
