"""
Key Manager module for generating and managing cryptographic keys.

This module provides functionality to generate various types of cryptographic keys
(symmetric, RSA, ECC) and manage their lifecycle.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import uuid
from datetime import datetime, timedelta
from typing import Tuple, Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models.database import Key
from app.models.enums import KeyType, AlgorithmType
from app.core.kms.key_storage import get_key_storage


class KeyManager:
    """
    Manages cryptographic key generation and lifecycle.

    Supports:
    - Symmetric keys (AES-256)
    - Asymmetric keys (RSA-2048, RSA-4096)
    - Elliptic Curve keys (P-256, P-384, P-521)
    """

    def __init__(self):
        """Initialize KeyManager with key storage."""
        self.key_storage = get_key_storage()

    # ========================================================================
    # Symmetric Key Generation
    # ========================================================================

    def generate_symmetric_key(
        self,
        key_name: str,
        user_id: int,
        algorithm: AlgorithmType = AlgorithmType.AES_256,
        expires_in_days: Optional[int] = None,
        db: Optional[Session] = None
    ) -> Key:
        """
        Generate a symmetric encryption key (AES-256).

        Args:
            key_name: Descriptive name for the key
            user_id: ID of the user owning the key
            algorithm: Symmetric algorithm (default: AES-256)
            expires_in_days: Optional expiration in days
            db: Database session for storing the key

        Returns:
            Key: Database model of the created key

        Example:
            >>> manager = KeyManager()
            >>> key = manager.generate_symmetric_key("my-key", user_id=1, db=db)
            >>> key.key_type == KeyType.SYMMETRIC
            True
        """
        # Generate random 256-bit key for AES-256
        key_bytes = os.urandom(32)

        # Encrypt key for storage
        encrypted_key_data = self.key_storage.encrypt_and_encode(key_bytes)

        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        # Create key metadata
        metadata = {
            "key_size": 256,
            "mode": "GCM/CBC"
        }

        # Create database record
        db_key = Key(
            id=str(uuid.uuid4()),
            user_id=user_id,
            key_name=key_name,
            key_type=KeyType.SYMMETRIC.value,
            algorithm=algorithm.value,
            encrypted_key_data=encrypted_key_data,
            key_metadata=metadata,
            expires_at=expires_at,
            is_active=True
        )

        if db:
            db.add(db_key)
            db.commit()
            db.refresh(db_key)

        return db_key

    # ========================================================================
    # RSA Key Generation
    # ========================================================================

    def generate_rsa_key_pair(
        self,
        key_name: str,
        user_id: int,
        algorithm: AlgorithmType = AlgorithmType.RSA_2048,
        expires_in_days: Optional[int] = None,
        db: Optional[Session] = None
    ) -> Tuple[Key, Key]:
        """
        Generate an RSA key pair (private and public keys).

        Args:
            key_name: Descriptive name for the key pair
            user_id: ID of the user owning the keys
            algorithm: RSA algorithm (RSA-2048 or RSA-4096)
            expires_in_days: Optional expiration in days
            db: Database session for storing the keys

        Returns:
            Tuple[Key, Key]: (private_key, public_key) database models

        Example:
            >>> manager = KeyManager()
            >>> private_key, public_key = manager.generate_rsa_key_pair(
            ...     "my-rsa-pair", user_id=1, db=db
            ... )
            >>> private_key.key_type == KeyType.RSA_PRIVATE
            True
        """
        # Determine key size from algorithm
        key_size = 2048 if algorithm == AlgorithmType.RSA_2048 else 4096

        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Encrypt keys for storage
        encrypted_private_key = self.key_storage.encrypt_and_encode(private_pem)
        encrypted_public_key = self.key_storage.encrypt_and_encode(public_pem)

        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        # Create metadata
        metadata = {
            "key_size": key_size,
            "public_exponent": 65537,
            "pair_id": str(uuid.uuid4())  # Link private and public keys
        }

        # Generate UUIDs for the keys
        private_key_id = str(uuid.uuid4())
        public_key_id = str(uuid.uuid4())

        # Store link to companion key in metadata
        private_metadata = {**metadata, "public_key_id": public_key_id}
        public_metadata = {**metadata, "private_key_id": private_key_id}

        # Create database records
        db_private_key = Key(
            id=private_key_id,
            user_id=user_id,
            key_name=f"{key_name} (Private)",
            key_type=KeyType.RSA_PRIVATE.value,
            algorithm=algorithm.value,
            encrypted_key_data=encrypted_private_key,
            key_metadata=private_metadata,
            expires_at=expires_at,
            is_active=True
        )

        db_public_key = Key(
            id=public_key_id,
            user_id=user_id,
            key_name=f"{key_name} (Public)",
            key_type=KeyType.RSA_PUBLIC.value,
            algorithm=algorithm.value,
            encrypted_key_data=encrypted_public_key,
            key_metadata=public_metadata,
            expires_at=expires_at,
            is_active=True
        )

        if db:
            db.add(db_private_key)
            db.add(db_public_key)
            db.commit()
            db.refresh(db_private_key)
            db.refresh(db_public_key)

        return db_private_key, db_public_key

    # ========================================================================
    # ECC Key Generation
    # ========================================================================

    def generate_ecc_key_pair(
        self,
        key_name: str,
        user_id: int,
        algorithm: AlgorithmType = AlgorithmType.ECC_P256,
        expires_in_days: Optional[int] = None,
        db: Optional[Session] = None
    ) -> Tuple[Key, Key]:
        """
        Generate an Elliptic Curve key pair (private and public keys).

        Args:
            key_name: Descriptive name for the key pair
            user_id: ID of the user owning the keys
            algorithm: ECC algorithm (ECC-P256, ECC-P384, or ECC-P521)
            expires_in_days: Optional expiration in days
            db: Database session for storing the keys

        Returns:
            Tuple[Key, Key]: (private_key, public_key) database models

        Example:
            >>> manager = KeyManager()
            >>> private_key, public_key = manager.generate_ecc_key_pair(
            ...     "my-ecc-pair", user_id=1, algorithm=AlgorithmType.ECC_P256, db=db
            ... )
            >>> private_key.key_type == KeyType.ECC_PRIVATE
            True
        """
        # Select curve based on algorithm
        curve_map = {
            AlgorithmType.ECC_P256: ec.SECP256R1(),
            AlgorithmType.ECC_P384: ec.SECP384R1(),
            AlgorithmType.ECC_P521: ec.SECP521R1(),
        }
        curve = curve_map.get(algorithm, ec.SECP256R1())

        # Generate ECC key pair
        private_key = ec.generate_private_key(curve, default_backend())
        public_key = private_key.public_key()

        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Serialize public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Encrypt keys for storage
        encrypted_private_key = self.key_storage.encrypt_and_encode(private_pem)
        encrypted_public_key = self.key_storage.encrypt_and_encode(public_pem)

        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        # Create metadata
        curve_name = algorithm.value.split('-')[1]  # Extract P256, P384, P521
        metadata = {
            "curve": curve_name,
            "pair_id": str(uuid.uuid4())
        }

        # Generate UUIDs for the keys
        private_key_id = str(uuid.uuid4())
        public_key_id = str(uuid.uuid4())

        # Store link to companion key in metadata
        private_metadata = {**metadata, "public_key_id": public_key_id}
        public_metadata = {**metadata, "private_key_id": private_key_id}

        # Create database records
        db_private_key = Key(
            id=private_key_id,
            user_id=user_id,
            key_name=f"{key_name} (Private)",
            key_type=KeyType.ECC_PRIVATE.value,
            algorithm=algorithm.value,
            encrypted_key_data=encrypted_private_key,
            key_metadata=private_metadata,
            expires_at=expires_at,
            is_active=True
        )

        db_public_key = Key(
            id=public_key_id,
            user_id=user_id,
            key_name=f"{key_name} (Public)",
            key_type=KeyType.ECC_PUBLIC.value,
            algorithm=algorithm.value,
            encrypted_key_data=encrypted_public_key,
            key_metadata=public_metadata,
            expires_at=expires_at,
            is_active=True
        )

        if db:
            db.add(db_private_key)
            db.add(db_public_key)
            db.commit()
            db.refresh(db_private_key)
            db.refresh(db_public_key)

        return db_private_key, db_public_key

    # ========================================================================
    # Key Retrieval
    # ========================================================================

    def get_decrypted_key(self, db_key: Key) -> bytes:
        """
        Retrieve and decrypt a key from the database.

        Args:
            db_key: Key database model

        Returns:
            bytes: Decrypted key bytes

        Raises:
            ValueError: If key is expired or inactive

        Example:
            >>> manager = KeyManager()
            >>> db_key = db.query(Key).filter(Key.id == key_id).first()
            >>> key_bytes = manager.get_decrypted_key(db_key)
        """
        # Check if key is active
        if not db_key.is_active:
            raise ValueError(f"Key {db_key.id} is not active")

        # Check if key is expired
        if db_key.expires_at and datetime.utcnow() > db_key.expires_at:
            raise ValueError(f"Key {db_key.id} has expired")

        # Decrypt and return key
        return self.key_storage.decode_and_decrypt(db_key.encrypted_key_data)


# Singleton instance
_key_manager_instance = None


def get_key_manager() -> KeyManager:
    """
    Get the singleton KeyManager instance.

    Returns:
        KeyManager: The key manager instance

    Example:
        >>> manager1 = get_key_manager()
        >>> manager2 = get_key_manager()
        >>> manager1 is manager2
        True
    """
    global _key_manager_instance
    if _key_manager_instance is None:
        _key_manager_instance = KeyManager()
    return _key_manager_instance
