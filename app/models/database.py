"""
Database models for the CaaS application.

This module defines SQLAlchemy ORM models for all database tables.
"""

from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Index, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

Base = declarative_base()


class User(Base):
    """User model for authentication and authorization."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)

    # Relationships
    keys = relationship("Key", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"


class Key(Base):
    """Key model for storing encrypted cryptographic keys."""

    __tablename__ = "keys"

    id = Column(String(36), primary_key=True)  # UUID
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    key_name = Column(String(255), nullable=False)
    key_type = Column(String(50), nullable=False)  # symmetric, rsa_private, rsa_public, etc.
    algorithm = Column(String(50), nullable=False)  # AES-256, RSA-2048, ECC-P256, etc.
    encrypted_key_data = Column(Text, nullable=False)  # Base64 encoded encrypted key
    key_metadata = Column(JSON, nullable=True)  # Additional metadata (key size, mode, etc.)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)

    # Relationships
    user = relationship("User", back_populates="keys")

    # Indexes
    __table_args__ = (
        Index("idx_keys_user_id", "user_id"),
        Index("idx_keys_key_type", "key_type"),
        Index("idx_keys_is_active", "is_active"),
    )

    def __repr__(self):
        return f"<Key(id='{self.id}', name='{self.key_name}', type='{self.key_type}', algorithm='{self.algorithm}')>"


class AuditLog(Base):
    """Audit log model for tracking all operations."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=func.now(), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username = Column(String(100), nullable=True)
    operation = Column(String(100), nullable=False, index=True)  # encrypt, decrypt, sign, etc.
    resource_type = Column(String(50), nullable=True)  # key, data, token
    resource_id = Column(String(255), nullable=True)
    status = Column(String(20), nullable=False, index=True)  # success, failure
    error_message = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv4 or IPv6
    user_agent = Column(Text, nullable=True)
    request_id = Column(String(36), nullable=True)  # UUID for request tracking
    log_metadata = Column(JSON, nullable=True)  # Additional context

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    # Indexes
    __table_args__ = (
        Index("idx_audit_timestamp", "timestamp"),
        Index("idx_audit_user_id", "user_id"),
        Index("idx_audit_operation", "operation"),
        Index("idx_audit_status", "status"),
    )

    def __repr__(self):
        return f"<AuditLog(id={self.id}, operation='{self.operation}', status='{self.status}', timestamp='{self.timestamp}')>"


class RefreshToken(Base):
    """Refresh token model for JWT token management."""

    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), unique=True, nullable=False, index=True)  # Hash of refresh token
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    revoked_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="refresh_tokens")

    # Indexes
    __table_args__ = (
        Index("idx_refresh_tokens_user_id", "user_id"),
        Index("idx_refresh_tokens_token_hash", "token_hash"),
        Index("idx_refresh_tokens_expires_at", "expires_at"),
    )

    def __repr__(self):
        return f"<RefreshToken(id={self.id}, user_id={self.user_id}, revoked={self.revoked})>"
