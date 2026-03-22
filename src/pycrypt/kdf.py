"""Key derivation -- turning passwords into strong keys.

A password like "pizza123" is too short and predictable for encryption.
Key derivation mixes it with salt (random data) and many rounds of
hashing to produce a long, strong, unpredictable key.

We use PBKDF2 (Password-Based Key Derivation Function 2), the same
algorithm used by Wi-Fi (WPA2), macOS login, and many others.
"""

import hashlib
import os

DEFAULT_KEY_LENGTH = 32  # 256 bits
DEFAULT_ROUNDS = 100_000


def derive_key(
    password: str,
    salt: bytes | None = None,
    key_length: int = DEFAULT_KEY_LENGTH,
    rounds: int = DEFAULT_ROUNDS,
) -> tuple[bytes, bytes]:
    """Derive a cryptographic key from a password.

    Uses PBKDF2-HMAC-SHA256 with a random salt.

    Args:
        password: The password to derive from.
        salt: Random salt bytes (generated if not provided).
        key_length: Length of the derived key in bytes.
        rounds: Number of hash iterations (more = slower + safer).

    Returns:
        A tuple of (derived_key, salt). Store the salt alongside
        the key so you can re-derive it later.

    """
    if salt is None:
        salt = os.urandom(16)

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations=rounds,
        dklen=key_length,
    )
    return key, salt
