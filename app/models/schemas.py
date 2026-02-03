"""
Pydantic schemas for request/response validation.

This module defines all Pydantic models used for API request validation
and response serialization.
"""

from pydantic import BaseModel, Field, EmailStr, field_validator
from typing import Optional, List, Dict, Any
from datetime import datetime

from app.models.enums import (
    KeyType, AlgorithmType, EncryptionMode, SignatureAlgorithm,
    OperationType, OperationStatus, EncodingFormat
)


# ============================================================================
# Authentication Schemas
# ============================================================================

class LoginRequest(BaseModel):
    """Request schema for user login."""
    username: str = Field(..., min_length=1, max_length=100, description="Username or email")
    password: str = Field(..., min_length=1, description="User password")

    class Config:
        json_schema_extra = {
            "example": {
                "username": "admin",
                "password": "Admin123!"
            }
        }


class TokenResponse(BaseModel):
    """Response schema for token generation."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: Optional[str] = Field(None, description="JWT refresh token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "Bearer",
                "expires_in": 1800
            }
        }


class RefreshTokenRequest(BaseModel):
    """Request schema for token refresh."""
    refresh_token: str = Field(..., description="Refresh token")

    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }


class UserResponse(BaseModel):
    """Response schema for user information."""
    id: int
    username: str
    email: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "username": "admin",
                "email": "admin@caas.local",
                "is_active": True,
                "created_at": "2026-02-01T10:30:00Z"
            }
        }


# ============================================================================
# Key Management Schemas
# ============================================================================

class KeyCreateRequest(BaseModel):
    """Request schema for creating a new cryptographic key."""
    key_name: str = Field(..., min_length=1, max_length=255, description="Descriptive name for the key")
    key_type: KeyType = Field(..., description="Type of key to generate")
    algorithm: AlgorithmType = Field(..., description="Cryptographic algorithm")
    expires_in_days: Optional[int] = Field(None, gt=0, description="Days until key expiration")

    class Config:
        json_schema_extra = {
            "example": {
                "key_name": "my-encryption-key",
                "key_type": "symmetric",
                "algorithm": "AES-256",
                "expires_in_days": 365
            }
        }


class KeyResponse(BaseModel):
    """Response schema for key information (without sensitive data)."""
    id: str = Field(..., description="Unique key identifier")
    key_name: str
    key_type: str
    algorithm: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    is_active: bool
    key_metadata: Optional[Dict[str, Any]] = Field(default=None, description="Additional key metadata")

    class Config:
        populate_by_name = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }
        json_schema_extra = {
            "example": {
                "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "key_name": "my-encryption-key",
                "key_type": "symmetric",
                "algorithm": "AES-256",
                "created_at": "2026-02-01T10:30:00Z",
                "expires_at": "2027-02-01T10:30:00Z",
                "is_active": True,
                "key_metadata": {"key_size": 256}
            }
        }


class KeyListResponse(BaseModel):
    """Response schema for listing keys."""
    keys: List[KeyResponse]
    total: int
    page: int = 1
    limit: int = 10


class KeyExportResponse(BaseModel):
    """Response schema for exporting a key."""
    key_id: str = Field(..., description="ID of the key")
    key_name: str = Field(..., description="Name of the key")
    key_type: str = Field(..., description="Type of key")
    algorithm: str = Field(..., description="Algorithm used")
    key_data: str = Field(..., description="Key data (base64 for symmetric, PEM for asymmetric)")
    format: str = Field(..., description="Format of key data (base64 or pem)")
    warning: str = Field(..., description="Security warning about key exposure")

    class Config:
        json_schema_extra = {
            "example": {
                "key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "key_name": "my-encryption-key",
                "key_type": "symmetric",
                "algorithm": "AES-256",
                "key_data": "base64encodedkeydata...",
                "format": "base64",
                "warning": "Keep this key secure. Anyone with access to this key can decrypt your data."
            }
        }


# ============================================================================
# Cryptographic Operation Schemas
# ============================================================================

class EncryptRequest(BaseModel):
    """Request schema for encryption operation."""
    key_id: str = Field(..., description="ID of the encryption key")
    plaintext: str = Field(..., min_length=1, description="Data to encrypt (text or base64)")
    mode: EncryptionMode = Field(default=EncryptionMode.GCM, description="Encryption mode")
    encoding: EncodingFormat = Field(default=EncodingFormat.BASE64, description="Output encoding format")
    is_file: bool = Field(default=False, description="Whether the data is a file (base64 encoded)")
    filename: str = Field(default="file", description="Original filename (only used if is_file=True)")

    @field_validator('plaintext')
    @classmethod
    def validate_plaintext_size(cls, v):
        """Validate plaintext size (max 10MB)."""
        # For base64, estimate decoded size
        estimated_size = len(v) * 3 // 4  # Base64 expands by ~33%
        if estimated_size > 10 * 1024 * 1024:
            raise ValueError("Data exceeds maximum size of 10MB")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "plaintext": "Sensitive data to encrypt",
                "mode": "GCM",
                "encoding": "base64"
            }
        }


class EncryptResponse(BaseModel):
    """Response schema for encryption operation."""
    ciphertext: str = Field(..., description="Encrypted data")
    iv: str = Field(..., description="Initialization vector")
    mode: str = Field(..., description="Encryption mode used")
    tag: Optional[str] = Field(None, description="Authentication tag (GCM only)")
    algorithm: str = Field(..., description="Algorithm used")
    key_id: str = Field(..., description="Key ID used for encryption")

    class Config:
        json_schema_extra = {
            "example": {
                "ciphertext": "base64_encoded_ciphertext_here",
                "iv": "base64_encoded_iv_here",
                "mode": "GCM",
                "tag": "base64_encoded_tag_here",
                "algorithm": "AES-256",
                "key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            }
        }


class DecryptRequest(BaseModel):
    """Request schema for decryption operation."""
    key_id: str = Field(..., description="ID of the decryption key")
    ciphertext: str = Field(..., min_length=1, description="Data to decrypt")
    iv: str = Field(..., description="Initialization vector")
    mode: EncryptionMode = Field(..., description="Encryption mode")
    tag: Optional[str] = Field(None, description="Authentication tag (required for GCM)")
    was_file: bool = Field(default=False, description="Whether the original data was a file")

    class Config:
        json_schema_extra = {
            "example": {
                "key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "ciphertext": "base64_encoded_ciphertext_here",
                "iv": "base64_encoded_iv_here",
                "mode": "GCM",
                "tag": "base64_encoded_tag_here"
            }
        }


class DecryptResponse(BaseModel):
    """Response schema for decryption operation."""
    plaintext: str = Field(..., description="Decrypted data (text or base64 if file)")
    was_file: bool = Field(default=False, description="Whether the decrypted data was originally a file")
    filename: Optional[str] = Field(default=None, description="Original filename (if was a file)")

    class Config:
        json_schema_extra = {
            "example": {
                "plaintext": "Decrypted sensitive data",
                "was_file": False,
                "filename": None
            }
        }
        # Ensure all fields are included in JSON serialization
        use_enum_values = True


class HashRequest(BaseModel):
    """Request schema for hashing operation."""
    data: str = Field(..., min_length=1, description="Data to hash (text or base64)")
    algorithm: AlgorithmType = Field(default=AlgorithmType.SHA_256, description="Hash algorithm")
    return_format: EncodingFormat = Field(default=EncodingFormat.HEX, description="Output format")
    is_file: bool = Field(default=False, description="Whether the data is a file (base64 encoded)")

    @field_validator('data')
    @classmethod
    def validate_data_size(cls, v):
        """Validate data size (max 10MB)."""
        # For base64, estimate decoded size
        estimated_size = len(v) * 3 // 4
        if estimated_size > 10 * 1024 * 1024:
            raise ValueError("Data exceeds maximum size of 10MB")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "data": "Data to hash",
                "algorithm": "SHA-256",
                "return_format": "hex"
            }
        }


class HashResponse(BaseModel):
    """Response schema for hashing operation."""
    hash: str = Field(..., description="Hash value")
    algorithm: str = Field(..., description="Algorithm used")

    class Config:
        json_schema_extra = {
            "example": {
                "hash": "a1b2c3d4e5f67890...",
                "algorithm": "SHA-256"
            }
        }


class HashVerifyRequest(BaseModel):
    """Request schema for hash verification."""
    data: str = Field(..., min_length=1, description="Original data (text or base64)")
    hash: str = Field(..., description="Hash to verify against")
    algorithm: AlgorithmType = Field(default=AlgorithmType.SHA_256, description="Hash algorithm")
    is_file: bool = Field(default=False, description="Whether the data is a file (base64 encoded)")

    class Config:
        json_schema_extra = {
            "example": {
                "data": "Original data",
                "hash": "a1b2c3d4e5f67890...",
                "algorithm": "SHA-256",
                "is_file": False
            }
        }


class HashVerifyResponse(BaseModel):
    """Response schema for hash verification."""
    verified: bool = Field(..., description="True if hash matches")

    class Config:
        json_schema_extra = {
            "example": {
                "verified": True
            }
        }


class SignRequest(BaseModel):
    """Request schema for digital signature."""
    key_id: str = Field(..., description="ID of the private key")
    data: str = Field(..., min_length=1, description="Data to sign (text or base64)")
    algorithm: SignatureAlgorithm = Field(..., description="Signature algorithm")
    hash_algorithm: AlgorithmType = Field(default=AlgorithmType.SHA_256, description="Hash algorithm")
    is_file: bool = Field(default=False, description="Whether the data is a file (base64 encoded)")

    class Config:
        json_schema_extra = {
            "example": {
                "key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "data": "Data to sign",
                "algorithm": "RSA-PSS",
                "hash_algorithm": "SHA-256"
            }
        }


class SignResponse(BaseModel):
    """Response schema for digital signature."""
    signature: str = Field(..., description="Digital signature")
    algorithm: str = Field(..., description="Signature algorithm used")
    hash_algorithm: str = Field(..., description="Hash algorithm used")
    key_id: str = Field(..., description="Key ID used for signing")

    class Config:
        json_schema_extra = {
            "example": {
                "signature": "base64_encoded_signature_here",
                "algorithm": "RSA-PSS",
                "hash_algorithm": "SHA-256",
                "key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            }
        }


class VerifyRequest(BaseModel):
    """Request schema for signature verification."""
    key_id: str = Field(..., description="ID of the public key")
    data: str = Field(..., min_length=1, description="Original data (text or base64)")
    signature: str = Field(..., description="Signature to verify")
    algorithm: SignatureAlgorithm = Field(..., description="Signature algorithm")
    hash_algorithm: AlgorithmType = Field(default=AlgorithmType.SHA_256, description="Hash algorithm")
    is_file: bool = Field(default=False, description="Whether the data is a file (base64 encoded)")

    class Config:
        json_schema_extra = {
            "example": {
                "key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "data": "Original data",
                "signature": "base64_encoded_signature_here",
                "algorithm": "RSA-PSS",
                "hash_algorithm": "SHA-256"
            }
        }


class VerifyResponse(BaseModel):
    """Response schema for signature verification."""
    verified: bool = Field(..., description="True if signature is valid")

    class Config:
        json_schema_extra = {
            "example": {
                "verified": True
            }
        }


# ============================================================================
# Audit Schemas
# ============================================================================

class AuditLogResponse(BaseModel):
    """Response schema for audit log entry."""
    id: int
    timestamp: datetime
    username: Optional[str]
    operation: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    status: str
    error_message: Optional[str]
    ip_address: Optional[str]
    request_id: Optional[str]

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "timestamp": "2026-02-01T10:30:00Z",
                "username": "admin",
                "operation": "encrypt",
                "resource_type": "data",
                "resource_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "status": "success",
                "error_message": None,
                "ip_address": "192.168.1.100",
                "request_id": "req-uuid-here"
            }
        }


class AuditLogListResponse(BaseModel):
    """Response schema for listing audit logs."""
    logs: List[AuditLogResponse]
    total: int
    page: int = 1
    limit: int = 50


# ============================================================================
# Health & Error Schemas
# ============================================================================

class HealthResponse(BaseModel):
    """Response schema for health check."""
    status: str = Field(..., description="Service status")
    timestamp: datetime = Field(..., description="Current timestamp")
    version: str = Field(..., description="API version")
    services: Dict[str, str] = Field(..., description="Status of dependent services")

    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2026-02-01T10:30:00Z",
                "version": "1.0.0",
                "services": {
                    "database": "healthy",
                    "kms": "healthy"
                }
            }
        }


class ErrorResponse(BaseModel):
    """Standard error response schema."""
    error: Dict[str, Any] = Field(..., description="Error details")

    class Config:
        json_schema_extra = {
            "example": {
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": "Invalid input data",
                    "details": {
                        "field": "key_id",
                        "issue": "Key not found"
                    },
                    "request_id": "req-uuid-here"
                }
            }
        }


class MessageResponse(BaseModel):
    """Generic message response schema."""
    message: str = Field(..., description="Response message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details")

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Operation completed successfully",
                "details": {"key_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}
            }
        }
