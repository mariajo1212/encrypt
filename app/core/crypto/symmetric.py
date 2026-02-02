"""
Symmetric encryption module for AES-256.

This module provides AES-256 encryption and decryption in both GCM and CBC modes.
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
from typing import Dict, Tuple
import base64

from app.models.enums import EncryptionMode


def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> Dict[str, bytes]:
    """
    Encrypt data using AES-256-GCM (Galois/Counter Mode).

    GCM provides both confidentiality and authenticity (authenticated encryption).

    Args:
        key: 32-byte (256-bit) encryption key
        plaintext: Data to encrypt

    Returns:
        Dict containing:
            - ciphertext: Encrypted data
            - nonce: 12-byte nonce (initialization vector)
            - tag: 16-byte authentication tag

    Example:
        >>> key = os.urandom(32)
        >>> plaintext = b"Secret message"
        >>> result = encrypt_aes_gcm(key, plaintext)
        >>> 'ciphertext' in result and 'nonce' in result and 'tag' in result
        True
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-256")

    # Initialize AES-GCM
    aesgcm = AESGCM(key)

    # Generate random 96-bit nonce
    nonce = os.urandom(12)

    # Encrypt and get ciphertext with appended tag
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    # Split ciphertext and tag (tag is last 16 bytes)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]

    return {
        "ciphertext": ciphertext,
        "nonce": nonce,
        "tag": tag
    }


def decrypt_aes_gcm(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt data using AES-256-GCM.

    Args:
        key: 32-byte (256-bit) encryption key
        ciphertext: Encrypted data
        nonce: 12-byte nonce used during encryption
        tag: 16-byte authentication tag

    Returns:
        bytes: Decrypted plaintext

    Raises:
        Exception: If authentication fails (wrong key or tampered data)

    Example:
        >>> key = os.urandom(32)
        >>> plaintext = b"Secret message"
        >>> result = encrypt_aes_gcm(key, plaintext)
        >>> decrypted = decrypt_aes_gcm(key, result['ciphertext'], result['nonce'], result['tag'])
        >>> plaintext == decrypted
        True
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-256")

    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes for GCM mode")

    if len(tag) != 16:
        raise ValueError("Tag must be 16 bytes")

    # Initialize AES-GCM
    aesgcm = AESGCM(key)

    # Reconstruct ciphertext with tag
    ciphertext_with_tag = ciphertext + tag

    # Decrypt and verify authentication
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

    return plaintext


def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> Dict[str, bytes]:
    """
    Encrypt data using AES-256-CBC (Cipher Block Chaining).

    CBC mode requires padding for data that's not a multiple of block size.

    Args:
        key: 32-byte (256-bit) encryption key
        plaintext: Data to encrypt

    Returns:
        Dict containing:
            - ciphertext: Encrypted data (includes padding)
            - iv: 16-byte initialization vector

    Example:
        >>> key = os.urandom(32)
        >>> plaintext = b"Secret message"
        >>> result = encrypt_aes_cbc(key, plaintext)
        >>> 'ciphertext' in result and 'iv' in result
        True
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-256")

    # Generate random 128-bit IV
    iv = os.urandom(16)

    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding (AES block size is 128 bits = 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # Encrypt
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return {
        "ciphertext": ciphertext,
        "iv": iv
    }


def decrypt_aes_cbc(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """
    Decrypt data using AES-256-CBC.

    Args:
        key: 32-byte (256-bit) encryption key
        ciphertext: Encrypted data
        iv: 16-byte initialization vector used during encryption

    Returns:
        bytes: Decrypted plaintext (padding removed)

    Raises:
        Exception: If decryption fails

    Example:
        >>> key = os.urandom(32)
        >>> plaintext = b"Secret message"
        >>> result = encrypt_aes_cbc(key, plaintext)
        >>> decrypted = decrypt_aes_cbc(key, result['ciphertext'], result['iv'])
        >>> plaintext == decrypted
        True
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits) for AES-256")

    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes for CBC mode")

    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def encrypt(
    key: bytes,
    plaintext: bytes,
    mode: EncryptionMode = EncryptionMode.GCM
) -> Dict[str, bytes]:
    """
    Encrypt data using specified mode.

    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt
        mode: Encryption mode (GCM or CBC)

    Returns:
        Dict containing encryption results (format depends on mode)

    Example:
        >>> key = os.urandom(32)
        >>> result = encrypt(key, b"Secret", EncryptionMode.GCM)
        >>> 'ciphertext' in result
        True
    """
    if mode == EncryptionMode.GCM:
        return encrypt_aes_gcm(key, plaintext)
    elif mode == EncryptionMode.CBC:
        return encrypt_aes_cbc(key, plaintext)
    else:
        raise ValueError(f"Unsupported encryption mode: {mode}")


def decrypt(
    key: bytes,
    ciphertext: bytes,
    mode: EncryptionMode,
    iv_or_nonce: bytes,
    tag: bytes = None
) -> bytes:
    """
    Decrypt data using specified mode.

    Args:
        key: 32-byte encryption key
        ciphertext: Encrypted data
        mode: Encryption mode (GCM or CBC)
        iv_or_nonce: IV (CBC) or nonce (GCM)
        tag: Authentication tag (required for GCM)

    Returns:
        bytes: Decrypted plaintext

    Example:
        >>> key = os.urandom(32)
        >>> enc_result = encrypt(key, b"Secret", EncryptionMode.GCM)
        >>> plaintext = decrypt(key, enc_result['ciphertext'], EncryptionMode.GCM,
        ...                     enc_result['nonce'], enc_result['tag'])
        >>> plaintext == b"Secret"
        True
    """
    if mode == EncryptionMode.GCM:
        if tag is None:
            raise ValueError("Tag is required for GCM mode")
        return decrypt_aes_gcm(key, ciphertext, iv_or_nonce, tag)
    elif mode == EncryptionMode.CBC:
        return decrypt_aes_cbc(key, ciphertext, iv_or_nonce)
    else:
        raise ValueError(f"Unsupported encryption mode: {mode}")
