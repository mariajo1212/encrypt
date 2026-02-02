"""Custom exceptions for the CaaS application."""

class CaaSException(Exception):
    """Base exception for CaaS application."""
    def __init__(self, message: str, error_code: str = "CAAS_ERROR"):
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)

class KeyNotFoundException(CaaSException):
    """Raised when a key is not found."""
    def __init__(self, key_id: str):
        super().__init__(f"Key {key_id} not found", "KEY_NOT_FOUND")

class KeyExpiredException(CaaSException):
    """Raised when a key has expired."""
    def __init__(self, key_id: str):
        super().__init__(f"Key {key_id} has expired", "KEY_EXPIRED")

class InvalidKeyTypeException(CaaSException):
    """Raised when key type is invalid for operation."""
    def __init__(self, expected: str, actual: str):
        super().__init__(
            f"Invalid key type. Expected {expected}, got {actual}",
            "INVALID_KEY_TYPE"
        )

class CryptoOperationException(CaaSException):
    """Raised when cryptographic operation fails."""
    def __init__(self, operation: str, details: str):
        super().__init__(
            f"Cryptographic operation '{operation}' failed: {details}",
            "CRYPTO_OPERATION_FAILED"
        )
