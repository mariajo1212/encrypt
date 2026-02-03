"""
Cryptographic operations endpoints for the CaaS API.

This module provides endpoints for encryption, decryption, hashing, and hash verification.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from sqlalchemy.orm import Session
import base64
import json
import logging

logger = logging.getLogger(__name__)

from app.db.session import get_db
from app.models.database import User, Key
from app.models.schemas import (
    EncryptRequest, EncryptResponse,
    DecryptRequest, DecryptResponse,
    HashRequest, HashResponse,
    HashVerifyRequest, HashVerifyResponse,
    SignRequest, SignResponse,
    VerifyRequest, VerifyResponse
)
from app.models.enums import EncryptionMode, KeyType, SignatureAlgorithm
from app.dependencies import get_current_user
from app.core.kms.key_manager import get_key_manager
from app.core.crypto.symmetric import encrypt, decrypt
from app.core.crypto.hashing import hash_data, verify_hash
from app.core.crypto.signatures import sign_data, verify_signature


router = APIRouter(prefix="/api/crypto", tags=["Cryptographic Operations"])


# ============================================================================
# Encryption & Decryption Endpoints
# ============================================================================

@router.post(
    "/encrypt",
    response_model=EncryptResponse,
    status_code=status.HTTP_200_OK,
    summary="Encrypt data",
    description="Encrypt data using AES-256 with specified mode (GCM or CBC)"
)
async def encrypt_data(
    request: EncryptRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Encrypt data using AES-256.

    **Supported Modes:**
    - `GCM`: Galois/Counter Mode (authenticated encryption, recommended)
    - `CBC`: Cipher Block Chaining (requires padding)

    **Process:**
    1. Retrieve encryption key from KMS
    2. Validate key is active and not expired
    3. Encrypt plaintext using specified mode
    4. Return ciphertext with necessary metadata (IV/nonce, tag)

    **Security Notes:**
    - GCM mode provides both confidentiality and authenticity
    - Each encryption uses a unique random IV/nonce
    - Keys are decrypted from storage only during the operation
    """
    # Get key from database
    db_key = db.query(Key).filter(
        Key.id == request.key_id,
        Key.user_id == current_user.id
    ).first()

    if not db_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {request.key_id} not found"
        )

    # Validate key type
    if db_key.key_type != KeyType.SYMMETRIC.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key type must be symmetric, got {db_key.key_type}"
        )

    try:
        # Get decrypted key
        key_manager = get_key_manager()
        key_bytes = key_manager.get_decrypted_key(db_key)

        # Convert plaintext to bytes (handle files vs text)
        if request.is_file:
            # Decode from base64 if it's a file
            plaintext_bytes = base64.b64decode(request.plaintext)
        else:
            # Regular text encoding
            plaintext_bytes = request.plaintext.encode('utf-8')

        # Add metadata to data if it's a file
        if request.is_file:
            # Create metadata JSON
            metadata = {
                "type": "file",
                "name": getattr(request, 'filename', 'file')
            }
            metadata_json = json.dumps(metadata)
            metadata_bytes = metadata_json.encode('utf-8')

            # Format: [4 bytes length][metadata][data]
            metadata_length = len(metadata_bytes)
            plaintext_with_meta = metadata_length.to_bytes(4, byteorder='big') + metadata_bytes + plaintext_bytes
            print(f"[DEBUG ENCRYPT] Added metadata: {metadata}, length: {metadata_length}, total size: {len(plaintext_with_meta)}")
        else:
            plaintext_with_meta = plaintext_bytes

        # Encrypt data
        encrypt_result = encrypt(key_bytes, plaintext_with_meta, request.mode)

        # Encode results based on requested format
        if request.encoding.value == "base64":
            ciphertext_encoded = base64.b64encode(encrypt_result['ciphertext']).decode('utf-8')
            iv_encoded = base64.b64encode(encrypt_result.get('iv') or encrypt_result.get('nonce')).decode('utf-8')
            tag_encoded = None
            if 'tag' in encrypt_result:
                tag_encoded = base64.b64encode(encrypt_result['tag']).decode('utf-8')
        else:
            # Hex encoding
            ciphertext_encoded = encrypt_result['ciphertext'].hex()
            iv_encoded = (encrypt_result.get('iv') or encrypt_result.get('nonce')).hex()
            tag_encoded = None
            if 'tag' in encrypt_result:
                tag_encoded = encrypt_result['tag'].hex()

        # Build response
        return EncryptResponse(
            ciphertext=ciphertext_encoded,
            iv=iv_encoded,
            mode=request.mode.value,
            tag=tag_encoded,
            algorithm=db_key.algorithm,
            key_id=request.key_id
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Encryption failed: {str(e)}"
        )


@router.post(
    "/decrypt",
    response_model=DecryptResponse,
    status_code=status.HTTP_200_OK,
    summary="Decrypt data",
    description="Decrypt data using AES-256 with specified mode"
)
async def decrypt_data(
    request: DecryptRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Decrypt data using AES-256.

    **Process:**
    1. Retrieve decryption key from KMS
    2. Decode ciphertext, IV/nonce, and tag (if GCM)
    3. Decrypt ciphertext using specified mode
    4. Return plaintext

    **Requirements:**
    - Same key used for encryption
    - Correct IV/nonce from encryption
    - For GCM: authentication tag from encryption

    **Security Notes:**
    - GCM mode verifies authenticity (fails if data was tampered)
    - Decryption fails if key, IV, or tag is incorrect
    """
    # Get key from database
    db_key = db.query(Key).filter(
        Key.id == request.key_id,
        Key.user_id == current_user.id
    ).first()

    if not db_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {request.key_id} not found"
        )

    # Validate key type
    if db_key.key_type != KeyType.SYMMETRIC.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key type must be symmetric, got {db_key.key_type}"
        )

    # Validate GCM requires tag
    if request.mode == EncryptionMode.GCM and not request.tag:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tag is required for GCM mode"
        )

    try:
        # Get decrypted key
        key_manager = get_key_manager()
        key_bytes = key_manager.get_decrypted_key(db_key)

        # Decode ciphertext and IV/nonce (try base64 first, then hex)
        try:
            ciphertext_bytes = base64.b64decode(request.ciphertext)
            iv_bytes = base64.b64decode(request.iv)
            tag_bytes = base64.b64decode(request.tag) if request.tag else None
        except Exception:
            # Try hex decoding
            ciphertext_bytes = bytes.fromhex(request.ciphertext)
            iv_bytes = bytes.fromhex(request.iv)
            tag_bytes = bytes.fromhex(request.tag) if request.tag else None

        # Decrypt ciphertext
        plaintext_bytes = decrypt(
            key_bytes,
            ciphertext_bytes,
            request.mode,
            iv_bytes,
            tag_bytes
        )

        # Try to extract metadata from decrypted data
        is_file = False
        filename = None
        actual_data = plaintext_bytes

        # Check if data starts with metadata (4 bytes length + JSON)
        if len(plaintext_bytes) >= 4:
            try:
                metadata_length = int.from_bytes(plaintext_bytes[:4], byteorder='big')
                logger.info(f"[DECRYPT DEBUG] Metadata length: {metadata_length}")
                # Sanity check: metadata shouldn't be larger than 1KB
                if 0 < metadata_length < 1024 and len(plaintext_bytes) >= 4 + metadata_length:
                    metadata_json = plaintext_bytes[4:4+metadata_length].decode('utf-8')
                    logger.info(f"[DECRYPT DEBUG] Metadata JSON: {metadata_json}")
                    metadata = json.loads(metadata_json)
                    logger.info(f"[DECRYPT DEBUG] Parsed metadata: {metadata}")

                    # Validate metadata structure
                    if isinstance(metadata, dict) and 'type' in metadata:
                        if metadata['type'] == 'file':
                            is_file = True
                            filename = metadata.get('name', 'file')
                            # Extract actual data (without metadata)
                            actual_data = plaintext_bytes[4+metadata_length:]
                            logger.info(f"[DECRYPT DEBUG] Detected file! filename: {filename}, data size: {len(actual_data)}")
            except Exception as e:
                # If metadata extraction fails, treat as regular data
                logger.info(f"[DECRYPT DEBUG] Metadata extraction failed: {e}")
                pass

        # Return data based on type
        if is_file:
            # Return file as base64
            plaintext = base64.b64encode(actual_data).decode('utf-8')
        else:
            # Try to decode as text
            try:
                plaintext = actual_data.decode('utf-8')
            except UnicodeDecodeError:
                # If can't decode, it might be a file without metadata
                is_file = True
                filename = 'file'
                plaintext = base64.b64encode(actual_data).decode('utf-8')

        logger.info(f"[DECRYPT DEBUG] Returning: was_file={is_file}, filename={filename}, plaintext length={len(plaintext)}")

        # Create response dict explicitly to ensure all fields are present
        response_data = {
            "plaintext": plaintext,
            "was_file": is_file if is_file is not None else False,
            "filename": filename if filename is not None else None
        }

        logger.info(f"[DECRYPT DEBUG] Response data: {response_data}")

        # Return explicit JSON response
        return JSONResponse(content=response_data)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Decryption failed: {str(e)}"
        )


# ============================================================================
# Hashing Endpoints
# ============================================================================

@router.post(
    "/hash",
    response_model=HashResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate hash",
    description="Generate cryptographic hash (SHA-256) of data"
)
async def hash_data_endpoint(
    request: HashRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Generate cryptographic hash of data.

    **Supported Algorithms:**
    - SHA-256 (recommended, produces 256-bit hash)
    - SHA-384 (produces 384-bit hash)
    - SHA-512 (produces 512-bit hash)

    **Output Formats:**
    - `hex`: Hexadecimal string (default)
    - `base64`: Base64 encoded string

    **Use Cases:**
    - Data integrity verification
    - Password hashing (not recommended, use dedicated password hashing)
    - Digital fingerprinting
    - Deduplication

    **Security Notes:**
    - Hash is deterministic (same input = same output)
    - One-way function (cannot reverse hash to get original data)
    - Small change in input produces completely different hash
    """
    try:
        # Convert data to bytes (handle files vs text)
        if request.is_file:
            # Decode from base64 if it's a file
            data_bytes = base64.b64decode(request.data)
        else:
            # Regular text encoding
            data_bytes = request.data.encode('utf-8')

        # Generate hash
        hash_value = hash_data(
            data_bytes,
            request.algorithm,
            request.return_format
        )

        return HashResponse(
            hash=hash_value,
            algorithm=request.algorithm.value
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Hashing failed: {str(e)}"
        )


@router.post(
    "/hash/verify",
    response_model=HashVerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify hash",
    description="Verify that data matches an expected hash"
)
async def verify_hash_endpoint(
    request: HashVerifyRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Verify that data matches the expected hash.

    **Process:**
    1. Hash the provided data using specified algorithm
    2. Compare with expected hash
    3. Return verification result

    **Use Cases:**
    - Verify file integrity after download
    - Detect data tampering
    - Validate data hasn't changed

    **Security Notes:**
    - Uses constant-time comparison to prevent timing attacks
    - Automatically detects hash format (hex or base64)
    """
    try:
        # Convert data to bytes (handle files vs text)
        if request.is_file:
            # Decode from base64 if it's a file
            data_bytes = base64.b64decode(request.data)
        else:
            # Regular text encoding
            data_bytes = request.data.encode('utf-8')

        # Verify hash
        is_valid = verify_hash(
            data_bytes,
            request.hash,
            request.algorithm
        )

        return HashVerifyResponse(verified=is_valid)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Hash verification failed: {str(e)}"
        )


# ============================================================================
# Digital Signature Endpoints
# ============================================================================

@router.post(
    "/sign",
    response_model=SignResponse,
    status_code=status.HTTP_200_OK,
    summary="Sign data",
    description="Create digital signature using RSA or ECC"
)
async def sign_data_endpoint(
    request: SignRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a digital signature for data.

    **Supported Algorithms:**
    - `RSA-PSS`: RSA Probabilistic Signature Scheme (recommended for RSA)
    - `RSA-PKCS1`: RSA PKCS#1 v1.5 (legacy, PSS preferred)
    - `ECDSA`: Elliptic Curve Digital Signature Algorithm

    **Process:**
    1. Retrieve private key from KMS
    2. Hash data using specified hash algorithm
    3. Sign hash with private key
    4. Return Base64 encoded signature

    **Use Cases:**
    - Prove data authenticity
    - Non-repudiation (signer cannot deny signing)
    - Verify data integrity

    **Security Notes:**
    - Private key never leaves the system
    - Signature can only be created by holder of private key
    - Anyone with public key can verify signature
    """
    # Get private key from database
    db_key = db.query(Key).filter(
        Key.id == request.key_id,
        Key.user_id == current_user.id
    ).first()

    if not db_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {request.key_id} not found"
        )

    # Validate key type (must be private key)
    if db_key.key_type not in [KeyType.RSA_PRIVATE.value, KeyType.ECC_PRIVATE.value]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key type must be a private key (RSA or ECC), got {db_key.key_type}"
        )

    # Validate algorithm matches key type
    if db_key.key_type == KeyType.RSA_PRIVATE.value:
        if request.algorithm not in [SignatureAlgorithm.RSA_PSS, SignatureAlgorithm.RSA_PKCS1]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Algorithm {request.algorithm} is not valid for RSA keys"
            )
    elif db_key.key_type == KeyType.ECC_PRIVATE.value:
        if request.algorithm != SignatureAlgorithm.ECDSA:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Algorithm {request.algorithm} is not valid for ECC keys"
            )

    try:
        # Get decrypted private key
        key_manager = get_key_manager()
        private_key_pem = key_manager.get_decrypted_key(db_key)

        # Convert data to bytes (handle files vs text)
        if request.is_file:
            # Decode from base64 if it's a file
            data_bytes = base64.b64decode(request.data)
        else:
            # Regular text encoding
            data_bytes = request.data.encode('utf-8')

        # Sign data
        signature_bytes = sign_data(
            private_key_pem,
            data_bytes,
            request.algorithm,
            request.hash_algorithm
        )

        # Encode signature as Base64
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')

        return SignResponse(
            signature=signature_b64,
            algorithm=request.algorithm.value,
            hash_algorithm=request.hash_algorithm.value,
            key_id=request.key_id
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Signing failed: {str(e)}"
        )


@router.post(
    "/verify",
    response_model=VerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify signature",
    description="Verify digital signature using public key"
)
async def verify_signature_endpoint(
    request: VerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify a digital signature.

    **Process:**
    1. Retrieve public key from KMS
    2. Decode signature from Base64
    3. Verify signature against data
    4. Return verification result

    **Returns:**
    - `verified: true` if signature is valid
    - `verified: false` if signature is invalid or data was modified

    **Use Cases:**
    - Verify data authenticity
    - Detect data tampering
    - Confirm identity of signer

    **Security Notes:**
    - Verification can be done by anyone with the public key
    - Invalid signature indicates data was modified or wrong key used
    - Valid signature proves data integrity and authenticity
    """
    # Get public key from database
    db_key = db.query(Key).filter(
        Key.id == request.key_id,
        Key.user_id == current_user.id
    ).first()

    if not db_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Key {request.key_id} not found"
        )

    # Validate key type (must be public key)
    if db_key.key_type not in [KeyType.RSA_PUBLIC.value, KeyType.ECC_PUBLIC.value]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Key type must be a public key (RSA or ECC), got {db_key.key_type}"
        )

    # Validate algorithm matches key type
    if db_key.key_type == KeyType.RSA_PUBLIC.value:
        if request.algorithm not in [SignatureAlgorithm.RSA_PSS, SignatureAlgorithm.RSA_PKCS1]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Algorithm {request.algorithm} is not valid for RSA keys"
            )
    elif db_key.key_type == KeyType.ECC_PUBLIC.value:
        if request.algorithm != SignatureAlgorithm.ECDSA:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Algorithm {request.algorithm} is not valid for ECC keys"
            )

    try:
        # Get decrypted public key
        key_manager = get_key_manager()
        public_key_pem = key_manager.get_decrypted_key(db_key)

        # Convert data to bytes (handle files vs text)
        if request.is_file:
            # Decode from base64 if it's a file
            data_bytes = base64.b64decode(request.data)
        else:
            # Regular text encoding
            data_bytes = request.data.encode('utf-8')

        # Decode signature from Base64
        signature_bytes = base64.b64decode(request.signature)

        # Verify signature
        is_valid = verify_signature(
            public_key_pem,
            data_bytes,
            signature_bytes,
            request.algorithm,
            request.hash_algorithm
        )

        return VerifyResponse(verified=is_valid)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Verification failed: {str(e)}"
        )
