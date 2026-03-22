"""Digital signatures -- wax seals for the digital age.

A digital signature proves who wrote a message (authenticity) and
that it hasn't been changed (integrity).

In real cryptography (RSA, ECDSA), you sign with a private key and
verify with a public key using clever maths. Our educational version
uses a simpler approach: a shared signing key (like HMAC), but teaches
the concept of signing and verification as separate operations.

The key ideas are the same:
- Only the key holder can create a valid signature
- Anyone can verify the signature matches the message
- Changing the message breaks the signature
"""

import hmac as _hmac
import os

from pycrypt.hashing import sha256

KEY_SIZE = 32


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a signing key pair.

    In real systems, the private key signs and the public key verifies.
    Our simplified version generates two related keys where the signing
    key is secret and the verification key is shared.

    Returns:
        A tuple of (signing_key, verification_key).
        In practice, both are needed for verification in our simplified
        scheme. Real RSA/ECDSA only needs the public key to verify.

    """
    signing_key = os.urandom(KEY_SIZE)
    verification_key = sha256(signing_key.hex()).encode("utf-8")[:KEY_SIZE]
    return signing_key, verification_key


def sign(message: str, signing_key: bytes) -> str:
    """Sign a message.

    Create a signature that proves the message is authentic and
    hasn't been changed. Only someone with the signing key can
    produce a valid signature.

    Args:
        message: The message to sign.
        signing_key: The secret signing key.

    Returns:
        The signature as a hex string.

    """
    return sha256(message + signing_key.hex())


def verify(message: str, signature: str, signing_key: bytes) -> bool:
    """Verify a signature.

    Recompute what the signature should be and check if it matches.
    Uses constant-time comparison to prevent timing attacks.

    Args:
        message: The message that was supposedly signed.
        signature: The hex signature to verify.
        signing_key: The signing key.

    Returns:
        True if the signature is valid.

    """
    expected = sign(message, signing_key)
    return _hmac.compare_digest(signature, expected)
