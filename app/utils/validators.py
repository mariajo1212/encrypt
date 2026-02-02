"""Input validators for the CaaS application."""

import re
from typing import Optional

def validate_uuid(uuid_string: str) -> bool:
    """Validate UUID format."""
    uuid_pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    return bool(uuid_pattern.match(uuid_string))

def validate_base64(data: str) -> bool:
    """Validate Base64 format."""
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
    return bool(base64_pattern.match(data))

def validate_hex(data: str) -> bool:
    """Validate hexadecimal format."""
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    return bool(hex_pattern.match(data))
