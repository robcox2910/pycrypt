"""Digital signatures -- symmetric signing for the digital age.

A digital signature proves who wrote a message (authenticity) and
that it hasn't been changed (integrity).

Our educational version uses a symmetric signing scheme: the same key
is used for both signing and verifying (similar to HMAC). Real
cryptographic signature systems like RSA and ECDSA use separate
private/public key pairs -- that requires advanced math we'll learn
later.

The key ideas are the same:
- Only the key holder can create a valid signature
- Verification checks that the signature matches the message
- Changing the message breaks the signature
"""

import hmac as _hmac

from pycrypt.hashing import sha256


def sign(message: str, key: bytes) -> str:
    """Sign a message.

    Create a signature that proves the message is authentic and
    hasn't been changed. Only someone with the key can produce a
    valid signature.

    Args:
        message: The message to sign.
        key: The secret key.

    Returns:
        The signature as a hex string.

    """
    return sha256(message + key.hex())


def verify(message: str, signature: str, key: bytes) -> bool:
    """Verify a signature.

    Recompute what the signature should be and check if it matches.
    Uses constant-time comparison to prevent timing attacks.

    Args:
        message: The message that was supposedly signed.
        signature: The hex signature to verify.
        key: The secret key (same key used for signing).

    Returns:
        True if the signature is valid.

    """
    expected = sign(message, key)
    return _hmac.compare_digest(signature, expected)
