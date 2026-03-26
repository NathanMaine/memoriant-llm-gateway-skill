"""API key authentication for the governed LLM gateway.

Validates incoming API keys by comparing their SHA-256 hash against
a configured set of known key hashes. Keys are never stored in
plaintext -- only their hashes appear in the configuration.
"""

import hashlib
import hmac
from typing import Dict, Optional


class AuthenticationError(Exception):
    """Raised when API key validation fails."""

    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


def hash_api_key(raw_key: str) -> str:
    """Compute the SHA-256 hash of a raw API key.

    Use this to generate the hash value for config files::

        python -c "from src.auth import hash_api_key; print(hash_api_key('your-key'))"

    Args:
        raw_key: The plaintext API key.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def validate_api_key(
    header_value: Optional[str],
    api_keys: Dict[str, str],
) -> str:
    """Validate an API key and return the associated client name.

    Args:
        header_value: The value from the X-API-Key header (may be None).
        api_keys: Mapping of key_name -> sha256_hash from config.

    Returns:
        The key name (client identifier) associated with the valid key.

    Raises:
        AuthenticationError: If the key is missing or invalid.
    """
    if not header_value:
        raise AuthenticationError("Missing API key. Provide X-API-Key header.")

    incoming_hash = hash_api_key(header_value)
    matched_name: Optional[str] = None

    for key_name, expected_hash in api_keys.items():
        if hmac.compare_digest(incoming_hash, expected_hash):
            matched_name = key_name

    if matched_name is None:
        raise AuthenticationError("Invalid API key.")
    return matched_name
