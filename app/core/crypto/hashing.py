"""
Hashing module for SHA-256.

This module provides cryptographic hashing functions using SHA-256 algorithm.
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hashlib
from typing import Union
import base64

from app.models.enums import AlgorithmType, EncodingFormat


def hash_sha256(data: bytes) -> bytes:
    """
    Generate SHA-256 hash of data.

    Args:
        data: Data to hash

    Returns:
        bytes: 32-byte (256-bit) hash digest

    Example:
        >>> data = b"Hello, World!"
        >>> hash_value = hash_sha256(data)
        >>> len(hash_value)
        32
    """
    # Use hashlib for simplicity (cryptography library also available)
    digest = hashlib.sha256(data).digest()
    return digest


def hash_sha256_hex(data: bytes) -> str:
    """
    Generate SHA-256 hash and return as hexadecimal string.

    Args:
        data: Data to hash

    Returns:
        str: Hexadecimal representation of hash (64 characters)

    Example:
        >>> data = b"Hello, World!"
        >>> hash_hex = hash_sha256_hex(data)
        >>> len(hash_hex)
        64
    """
    return hashlib.sha256(data).hexdigest()


def hash_sha256_base64(data: bytes) -> str:
    """
    Generate SHA-256 hash and return as Base64 string.

    Args:
        data: Data to hash

    Returns:
        str: Base64 representation of hash

    Example:
        >>> data = b"Hello, World!"
        >>> hash_b64 = hash_sha256_base64(data)
        >>> isinstance(hash_b64, str)
        True
    """
    digest = hash_sha256(data)
    return base64.b64encode(digest).decode('utf-8')


def hash_data(
    data: bytes,
    algorithm: AlgorithmType = AlgorithmType.SHA_256,
    return_format: EncodingFormat = EncodingFormat.HEX
) -> str:
    """
    Hash data using specified algorithm and return in specified format.

    Args:
        data: Data to hash
        algorithm: Hash algorithm (currently only SHA-256 supported)
        return_format: Output format (hex or base64)

    Returns:
        str: Hash in specified format

    Raises:
        ValueError: If algorithm is not supported

    Example:
        >>> data = b"Test data"
        >>> hash_hex = hash_data(data, AlgorithmType.SHA_256, EncodingFormat.HEX)
        >>> len(hash_hex)
        64
    """
    # Currently only SHA-256 is implemented
    if algorithm not in [AlgorithmType.SHA_256, AlgorithmType.SHA_384, AlgorithmType.SHA_512]:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    # Generate hash based on algorithm
    if algorithm == AlgorithmType.SHA_256:
        if return_format == EncodingFormat.HEX:
            return hash_sha256_hex(data)
        elif return_format == EncodingFormat.BASE64:
            return hash_sha256_base64(data)
        else:
            raise ValueError(f"Unsupported return format: {return_format}")

    elif algorithm == AlgorithmType.SHA_384:
        digest = hashlib.sha384(data)
        if return_format == EncodingFormat.HEX:
            return digest.hexdigest()
        elif return_format == EncodingFormat.BASE64:
            return base64.b64encode(digest.digest()).decode('utf-8')

    elif algorithm == AlgorithmType.SHA_512:
        digest = hashlib.sha512(data)
        if return_format == EncodingFormat.HEX:
            return digest.hexdigest()
        elif return_format == EncodingFormat.BASE64:
            return base64.b64encode(digest.digest()).decode('utf-8')

    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def verify_hash(data: bytes, expected_hash: str, algorithm: AlgorithmType = AlgorithmType.SHA_256) -> bool:
    """
    Verify that data matches the expected hash.

    Args:
        data: Original data to hash
        expected_hash: Expected hash value (hex or base64)
        algorithm: Hash algorithm used

    Returns:
        bool: True if hash matches, False otherwise

    Example:
        >>> data = b"Test data"
        >>> hash_value = hash_data(data, AlgorithmType.SHA_256, EncodingFormat.HEX)
        >>> verify_hash(data, hash_value, AlgorithmType.SHA_256)
        True
        >>> verify_hash(b"Wrong data", hash_value, AlgorithmType.SHA_256)
        False
    """
    # Detect format (hex has 64 chars for SHA-256, base64 is shorter)
    if len(expected_hash) == 64:
        # Assume hex format
        actual_hash = hash_data(data, algorithm, EncodingFormat.HEX)
    elif len(expected_hash) == 96:
        # SHA-384 hex
        actual_hash = hash_data(data, algorithm, EncodingFormat.HEX)
    elif len(expected_hash) == 128:
        # SHA-512 hex
        actual_hash = hash_data(data, algorithm, EncodingFormat.HEX)
    else:
        # Assume base64 format
        actual_hash = hash_data(data, algorithm, EncodingFormat.BASE64)

    # Use constant-time comparison to prevent timing attacks
    return compare_digests(actual_hash, expected_hash)


def compare_digests(a: str, b: str) -> bool:
    """
    Compare two digest strings in constant time to prevent timing attacks.

    Args:
        a: First digest
        b: Second digest

    Returns:
        bool: True if digests match, False otherwise

    Example:
        >>> compare_digests("abc", "abc")
        True
        >>> compare_digests("abc", "xyz")
        False
    """
    # Use hmac.compare_digest for constant-time comparison
    import hmac
    return hmac.compare_digest(a, b)


def hash_file_chunked(file_path: str, chunk_size: int = 65536) -> str:
    """
    Hash a file in chunks (for large files).

    Args:
        file_path: Path to file
        chunk_size: Size of chunks to read (default: 64KB)

    Returns:
        str: Hexadecimal hash of file

    Example:
        >>> # Assuming file exists
        >>> hash_value = hash_file_chunked("test.txt")
        >>> len(hash_value)
        64
    """
    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as f:
        # Read file in chunks
        while chunk := f.read(chunk_size):
            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def hash_string(text: str, encoding: str = 'utf-8') -> str:
    """
    Hash a string (convenience function).

    Args:
        text: Text to hash
        encoding: Text encoding (default: utf-8)

    Returns:
        str: Hexadecimal hash

    Example:
        >>> hash_value = hash_string("Hello, World!")
        >>> len(hash_value)
        64
    """
    return hash_sha256_hex(text.encode(encoding))
