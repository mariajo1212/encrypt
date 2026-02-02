"""
Key storage module for secure key encryption at rest.

This module provides functionality to encrypt and decrypt cryptographic keys
using a master key derived from environment secrets. All keys are encrypted
before being stored in the database.
"""

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import base64
from typing import Tuple

from app.config import settings


class KeyStorage:
    """
    Handles encryption and decryption of cryptographic keys at rest.

    Uses a master key derived from environment secrets to encrypt all keys
    before storage. Keys are encrypted using AES-256-GCM for authenticated encryption.
    """

    def __init__(self):
        """Initialize KeyStorage with derived master key."""
        self.master_key = self._derive_master_key()

    def _derive_master_key(self) -> bytes:
        """
        Derive a master key from environment secrets using PBKDF2.

        Uses PBKDF2 with SHA-256 and 100,000 iterations for key derivation.

        Returns:
            bytes: 32-byte (256-bit) master key

        Security Note:
            The master key secret and salt should be:
            - Unique per environment (dev/staging/production)
            - Rotated periodically
            - Never committed to version control
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=settings.master_key_salt.encode('utf-8'),
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(settings.master_key_secret.encode('utf-8'))

    def encrypt_key(self, key_data: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt key data using AES-256-GCM.

        Args:
            key_data: Raw key bytes to encrypt

        Returns:
            Tuple[bytes, bytes, bytes]: (ciphertext, nonce, tag)

        Example:
            >>> storage = KeyStorage()
            >>> key = os.urandom(32)
            >>> ciphertext, nonce, tag = storage.encrypt_key(key)
            >>> decrypted = storage.decrypt_key(ciphertext, nonce, tag)
            >>> key == decrypted
            True
        """
        # Initialize AES-GCM with master key
        aesgcm = AESGCM(self.master_key)

        # Generate random nonce (96 bits for GCM)
        nonce = os.urandom(12)

        # Encrypt key data
        ciphertext_and_tag = aesgcm.encrypt(nonce, key_data, None)

        # Split ciphertext and tag
        # In AESGCM, the tag is appended to the ciphertext
        ciphertext = ciphertext_and_tag[:-16]
        tag = ciphertext_and_tag[-16:]

        return ciphertext, nonce, tag

    def decrypt_key(self, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
        """
        Decrypt key data using AES-256-GCM.

        Args:
            ciphertext: Encrypted key data
            nonce: Nonce used during encryption
            tag: Authentication tag

        Returns:
            bytes: Decrypted key data

        Raises:
            Exception: If decryption fails (wrong key, tampered data, etc.)

        Example:
            >>> storage = KeyStorage()
            >>> key = os.urandom(32)
            >>> ciphertext, nonce, tag = storage.encrypt_key(key)
            >>> decrypted = storage.decrypt_key(ciphertext, nonce, tag)
            >>> key == decrypted
            True
        """
        # Initialize AES-GCM with master key
        aesgcm = AESGCM(self.master_key)

        # Reconstruct ciphertext with tag
        ciphertext_with_tag = ciphertext + tag

        # Decrypt key data
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

        return plaintext

    def encode_encrypted_key(
        self,
        ciphertext: bytes,
        nonce: bytes,
        tag: bytes
    ) -> str:
        """
        Encode encrypted key components as a single Base64 string for storage.

        Format: base64(nonce || ciphertext || tag)

        Args:
            ciphertext: Encrypted key data
            nonce: Nonce used during encryption
            tag: Authentication tag

        Returns:
            str: Base64 encoded string containing all components

        Example:
            >>> storage = KeyStorage()
            >>> key = os.urandom(32)
            >>> ct, nonce, tag = storage.encrypt_key(key)
            >>> encoded = storage.encode_encrypted_key(ct, nonce, tag)
            >>> decoded_ct, decoded_nonce, decoded_tag = storage.decode_encrypted_key(encoded)
            >>> ct == decoded_ct and nonce == decoded_nonce and tag == decoded_tag
            True
        """
        # Concatenate: nonce (12 bytes) || ciphertext || tag (16 bytes)
        combined = nonce + ciphertext + tag

        # Base64 encode for storage
        return base64.b64encode(combined).decode('utf-8')

    def decode_encrypted_key(self, encoded_data: str) -> Tuple[bytes, bytes, bytes]:
        """
        Decode Base64 encoded encrypted key into components.

        Args:
            encoded_data: Base64 encoded string from storage

        Returns:
            Tuple[bytes, bytes, bytes]: (ciphertext, nonce, tag)

        Raises:
            ValueError: If encoded data is invalid or corrupted

        Example:
            >>> storage = KeyStorage()
            >>> key = os.urandom(32)
            >>> ct, nonce, tag = storage.encrypt_key(key)
            >>> encoded = storage.encode_encrypted_key(ct, nonce, tag)
            >>> decoded_ct, decoded_nonce, decoded_tag = storage.decode_encrypted_key(encoded)
            >>> ct == decoded_ct
            True
        """
        try:
            # Base64 decode
            combined = base64.b64decode(encoded_data)

            # Extract components
            nonce = combined[:12]  # First 12 bytes
            tag = combined[-16:]   # Last 16 bytes
            ciphertext = combined[12:-16]  # Everything in between

            return ciphertext, nonce, tag

        except Exception as e:
            raise ValueError(f"Failed to decode encrypted key data: {e}")

    def encrypt_and_encode(self, key_data: bytes) -> str:
        """
        Convenience method to encrypt key and encode for storage in one step.

        Args:
            key_data: Raw key bytes to encrypt

        Returns:
            str: Base64 encoded encrypted key ready for database storage

        Example:
            >>> storage = KeyStorage()
            >>> key = os.urandom(32)
            >>> encrypted = storage.encrypt_and_encode(key)
            >>> decrypted = storage.decode_and_decrypt(encrypted)
            >>> key == decrypted
            True
        """
        ciphertext, nonce, tag = self.encrypt_key(key_data)
        return self.encode_encrypted_key(ciphertext, nonce, tag)

    def decode_and_decrypt(self, encoded_data: str) -> bytes:
        """
        Convenience method to decode and decrypt key in one step.

        Args:
            encoded_data: Base64 encoded encrypted key from storage

        Returns:
            bytes: Decrypted key data

        Raises:
            ValueError: If decoding or decryption fails

        Example:
            >>> storage = KeyStorage()
            >>> key = os.urandom(32)
            >>> encrypted = storage.encrypt_and_encode(key)
            >>> decrypted = storage.decode_and_decrypt(encrypted)
            >>> key == decrypted
            True
        """
        ciphertext, nonce, tag = self.decode_encrypted_key(encoded_data)
        return self.decrypt_key(ciphertext, nonce, tag)


# Singleton instance
_key_storage_instance = None


def get_key_storage() -> KeyStorage:
    """
    Get the singleton KeyStorage instance.

    Returns:
        KeyStorage: The key storage instance

    Example:
        >>> storage1 = get_key_storage()
        >>> storage2 = get_key_storage()
        >>> storage1 is storage2
        True
    """
    global _key_storage_instance
    if _key_storage_instance is None:
        _key_storage_instance = KeyStorage()
    return _key_storage_instance
