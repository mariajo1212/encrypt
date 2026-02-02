"""
Digital signatures module for RSA and ECC.

This module provides functionality for creating and verifying digital signatures
using RSA and Elliptic Curve algorithms.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from typing import Tuple
import base64

from app.models.enums import SignatureAlgorithm, AlgorithmType


# ============================================================================
# RSA Signatures
# ============================================================================

def sign_rsa_pss(private_key_pem: bytes, data: bytes, hash_algorithm: str = "SHA-256") -> bytes:
    """
    Sign data using RSA-PSS (Probabilistic Signature Scheme).

    PSS is the recommended RSA signature scheme due to better security properties.

    Args:
        private_key_pem: RSA private key in PEM format
        data: Data to sign
        hash_algorithm: Hash algorithm (SHA-256, SHA-384, SHA-512)

    Returns:
        bytes: Digital signature

    Example:
        >>> # Assuming we have a private key
        >>> signature = sign_rsa_pss(private_key_pem, b"Message to sign")
        >>> len(signature) > 0
        True
    """
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    # Select hash algorithm
    hash_algo = _get_hash_algorithm(hash_algorithm)

    # Sign data using PSS padding
    signature = private_key.sign(
        data,
        asym_padding.PSS(
            mgf=asym_padding.MGF1(hash_algo),
            salt_length=asym_padding.PSS.MAX_LENGTH
        ),
        hash_algo
    )

    return signature


def verify_rsa_pss(public_key_pem: bytes, data: bytes, signature: bytes, hash_algorithm: str = "SHA-256") -> bool:
    """
    Verify RSA-PSS signature.

    Args:
        public_key_pem: RSA public key in PEM format
        data: Original data that was signed
        signature: Signature to verify
        hash_algorithm: Hash algorithm used for signing

    Returns:
        bool: True if signature is valid, False otherwise

    Example:
        >>> # Assuming we have keys and signature
        >>> is_valid = verify_rsa_pss(public_key_pem, b"Message", signature)
    """
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

        # Select hash algorithm
        hash_algo = _get_hash_algorithm(hash_algorithm)

        # Verify signature
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hash_algo),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hash_algo
        )

        return True

    except Exception:
        return False


def sign_rsa_pkcs1(private_key_pem: bytes, data: bytes, hash_algorithm: str = "SHA-256") -> bytes:
    """
    Sign data using RSA-PKCS#1 v1.5.

    Note: PSS is preferred over PKCS#1 v1.5 for new applications.

    Args:
        private_key_pem: RSA private key in PEM format
        data: Data to sign
        hash_algorithm: Hash algorithm (SHA-256, SHA-384, SHA-512)

    Returns:
        bytes: Digital signature

    Example:
        >>> signature = sign_rsa_pkcs1(private_key_pem, b"Message to sign")
        >>> len(signature) > 0
        True
    """
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    # Select hash algorithm
    hash_algo = _get_hash_algorithm(hash_algorithm)

    # Sign data using PKCS1v15 padding
    signature = private_key.sign(
        data,
        asym_padding.PKCS1v15(),
        hash_algo
    )

    return signature


def verify_rsa_pkcs1(public_key_pem: bytes, data: bytes, signature: bytes, hash_algorithm: str = "SHA-256") -> bool:
    """
    Verify RSA-PKCS#1 v1.5 signature.

    Args:
        public_key_pem: RSA public key in PEM format
        data: Original data that was signed
        signature: Signature to verify
        hash_algorithm: Hash algorithm used for signing

    Returns:
        bool: True if signature is valid, False otherwise

    Example:
        >>> is_valid = verify_rsa_pkcs1(public_key_pem, b"Message", signature)
    """
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

        # Select hash algorithm
        hash_algo = _get_hash_algorithm(hash_algorithm)

        # Verify signature
        public_key.verify(
            signature,
            data,
            asym_padding.PKCS1v15(),
            hash_algo
        )

        return True

    except Exception:
        return False


# ============================================================================
# ECC Signatures (ECDSA)
# ============================================================================

def sign_ecdsa(private_key_pem: bytes, data: bytes, hash_algorithm: str = "SHA-256") -> bytes:
    """
    Sign data using ECDSA (Elliptic Curve Digital Signature Algorithm).

    Args:
        private_key_pem: ECC private key in PEM format
        data: Data to sign
        hash_algorithm: Hash algorithm (SHA-256, SHA-384, SHA-512)

    Returns:
        bytes: Digital signature

    Example:
        >>> signature = sign_ecdsa(private_key_pem, b"Message to sign")
        >>> len(signature) > 0
        True
    """
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )

    # Select hash algorithm
    hash_algo = _get_hash_algorithm(hash_algorithm)

    # Sign data using ECDSA
    signature = private_key.sign(
        data,
        ec.ECDSA(hash_algo)
    )

    return signature


def verify_ecdsa(public_key_pem: bytes, data: bytes, signature: bytes, hash_algorithm: str = "SHA-256") -> bool:
    """
    Verify ECDSA signature.

    Args:
        public_key_pem: ECC public key in PEM format
        data: Original data that was signed
        signature: Signature to verify
        hash_algorithm: Hash algorithm used for signing

    Returns:
        bool: True if signature is valid, False otherwise

    Example:
        >>> is_valid = verify_ecdsa(public_key_pem, b"Message", signature)
    """
    try:
        # Load public key
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )

        # Select hash algorithm
        hash_algo = _get_hash_algorithm(hash_algorithm)

        # Verify signature
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hash_algo)
        )

        return True

    except Exception:
        return False


# ============================================================================
# Helper Functions
# ============================================================================

def _get_hash_algorithm(algorithm_name: str):
    """
    Get hash algorithm instance from name.

    Args:
        algorithm_name: Name of hash algorithm (SHA-256, SHA-384, SHA-512)

    Returns:
        Hash algorithm instance

    Raises:
        ValueError: If algorithm is not supported
    """
    algorithm_map = {
        "SHA-256": hashes.SHA256(),
        "SHA-384": hashes.SHA384(),
        "SHA-512": hashes.SHA512(),
    }

    algo = algorithm_map.get(algorithm_name.upper())
    if algo is None:
        raise ValueError(f"Unsupported hash algorithm: {algorithm_name}")

    return algo


def sign_data(
    private_key_pem: bytes,
    data: bytes,
    algorithm: SignatureAlgorithm,
    hash_algorithm: AlgorithmType = AlgorithmType.SHA_256
) -> bytes:
    """
    Sign data using specified signature algorithm.

    Args:
        private_key_pem: Private key in PEM format
        data: Data to sign
        algorithm: Signature algorithm (RSA-PSS, RSA-PKCS1, ECDSA)
        hash_algorithm: Hash algorithm to use

    Returns:
        bytes: Digital signature

    Example:
        >>> signature = sign_data(private_key_pem, b"Message",
        ...                       SignatureAlgorithm.RSA_PSS,
        ...                       AlgorithmType.SHA_256)
    """
    hash_algo_str = hash_algorithm.value

    if algorithm == SignatureAlgorithm.RSA_PSS:
        return sign_rsa_pss(private_key_pem, data, hash_algo_str)
    elif algorithm == SignatureAlgorithm.RSA_PKCS1:
        return sign_rsa_pkcs1(private_key_pem, data, hash_algo_str)
    elif algorithm == SignatureAlgorithm.ECDSA:
        return sign_ecdsa(private_key_pem, data, hash_algo_str)
    else:
        raise ValueError(f"Unsupported signature algorithm: {algorithm}")


def verify_signature(
    public_key_pem: bytes,
    data: bytes,
    signature: bytes,
    algorithm: SignatureAlgorithm,
    hash_algorithm: AlgorithmType = AlgorithmType.SHA_256
) -> bool:
    """
    Verify signature using specified algorithm.

    Args:
        public_key_pem: Public key in PEM format
        data: Original data that was signed
        signature: Signature to verify
        algorithm: Signature algorithm (RSA-PSS, RSA-PKCS1, ECDSA)
        hash_algorithm: Hash algorithm used for signing

    Returns:
        bool: True if signature is valid, False otherwise

    Example:
        >>> is_valid = verify_signature(public_key_pem, b"Message", signature,
        ...                              SignatureAlgorithm.RSA_PSS,
        ...                              AlgorithmType.SHA_256)
    """
    hash_algo_str = hash_algorithm.value

    if algorithm == SignatureAlgorithm.RSA_PSS:
        return verify_rsa_pss(public_key_pem, data, signature, hash_algo_str)
    elif algorithm == SignatureAlgorithm.RSA_PKCS1:
        return verify_rsa_pkcs1(public_key_pem, data, signature, hash_algo_str)
    elif algorithm == SignatureAlgorithm.ECDSA:
        return verify_ecdsa(public_key_pem, data, signature, hash_algo_str)
    else:
        raise ValueError(f"Unsupported signature algorithm: {algorithm}")
