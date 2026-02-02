"""
Enumerations for the CaaS application.

This module defines all enum types used throughout the application
for type safety and consistency.
"""

from enum import Enum


class KeyType(str, Enum):
    """Types of cryptographic keys."""
    SYMMETRIC = "symmetric"
    RSA_PRIVATE = "rsa_private"
    RSA_PUBLIC = "rsa_public"
    ECC_PRIVATE = "ecc_private"
    ECC_PUBLIC = "ecc_public"


class AlgorithmType(str, Enum):
    """Cryptographic algorithm types."""
    # Symmetric algorithms
    AES_256 = "AES-256"

    # Asymmetric algorithms - RSA
    RSA_2048 = "RSA-2048"
    RSA_4096 = "RSA-4096"

    # Asymmetric algorithms - ECC
    ECC_P256 = "ECC-P256"
    ECC_P384 = "ECC-P384"
    ECC_P521 = "ECC-P521"

    # Hash algorithms
    SHA_256 = "SHA-256"
    SHA_384 = "SHA-384"
    SHA_512 = "SHA-512"


class EncryptionMode(str, Enum):
    """AES encryption modes."""
    GCM = "GCM"
    CBC = "CBC"


class SignatureAlgorithm(str, Enum):
    """Digital signature algorithms."""
    RSA_PSS = "RSA-PSS"
    RSA_PKCS1 = "RSA-PKCS1"
    ECDSA = "ECDSA"


class OperationType(str, Enum):
    """Types of operations for audit logging."""
    # Authentication operations
    LOGIN = "login"
    LOGOUT = "logout"
    TOKEN_REFRESH = "token_refresh"

    # Key management operations
    KEY_CREATE = "key_create"
    KEY_RETRIEVE = "key_retrieve"
    KEY_LIST = "key_list"
    KEY_DELETE = "key_delete"

    # Cryptographic operations
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    HASH = "hash"
    HASH_VERIFY = "hash_verify"
    SIGN = "sign"
    VERIFY = "verify"

    # Audit operations
    AUDIT_QUERY = "audit_query"


class ResourceType(str, Enum):
    """Types of resources for audit logging."""
    KEY = "key"
    DATA = "data"
    TOKEN = "token"
    USER = "user"
    AUDIT_LOG = "audit_log"


class OperationStatus(str, Enum):
    """Status of operations for audit logging."""
    SUCCESS = "success"
    FAILURE = "failure"
    PENDING = "pending"


class EncodingFormat(str, Enum):
    """Encoding formats for cryptographic data."""
    BASE64 = "base64"
    HEX = "hex"
