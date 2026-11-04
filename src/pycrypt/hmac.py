"""HMAC -- tamper-evident seals for messages.

HMAC (Hash-based Message Authentication Code) combines a message with
a secret key to produce a tag. If the message changes, the tag won't
match -- like a broken seal on a jar tells you someone opened it.

Both sender and receiver need the same secret key.

HMAC is built from a hash in two layers, like a letter sealed inside an
envelope that is sealed again:

1. Make the key exactly one block (64 bytes) long: hash it down if it is
   longer, pad it with zeros if it is shorter.
2. Inner layer: hash ``(key XOR 0x36...) + message``.
3. Outer layer: hash ``(key XOR 0x5c...) + inner fingerprint``.

The two different masks (``0x36`` and ``0x5c``) make the inner and outer
keys different, which stops a class of attacks that a single
``hash(key + message)`` would fall to. The hash here is PyCrypt's own
hand-written SHA-256.

Checking a tag still uses Python's ``hmac.compare_digest``: it compares
two strings in the same amount of time whether they differ early or late,
so an attacker can't learn the tag one character at a time by timing us.
"""

import hmac as _hmac

from pycrypt.errors import VerificationError
from pycrypt.hashing import BLOCK_SIZE, sha256_digest

INNER_MASK = 0x36
OUTER_MASK = 0x5C


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Make an HMAC-SHA256 tag from raw bytes, by hand.

    Args:
        key: The shared secret key, any length.
        message: The message to seal.

    Returns:
        The 32-byte tag.

    """
    if len(key) > BLOCK_SIZE:
        key = sha256_digest(key)
    key = key.ljust(BLOCK_SIZE, b"\x00")
    inner_key = bytes(byte ^ INNER_MASK for byte in key)
    outer_key = bytes(byte ^ OUTER_MASK for byte in key)
    return sha256_digest(outer_key + sha256_digest(inner_key + message))


def hmac_sign(message: str, key: str) -> str:
    """Create an HMAC tag for a message.

    Args:
        message: The message to authenticate.
        key: The shared secret key.

    Returns:
        A hex-encoded HMAC tag.

    """
    return hmac_sha256(key.encode("utf-8"), message.encode("utf-8")).hex()


def hmac_verify(message: str, tag: str, key: str) -> bool:
    """Verify that a message matches its HMAC tag.

    Uses constant-time comparison to prevent timing attacks.

    Args:
        message: The message to verify.
        tag: The HMAC tag to check against.
        key: The shared secret key.

    Returns:
        True if the message is authentic and unmodified.

    """
    expected = hmac_sign(message, key)
    return _hmac.compare_digest(expected, tag)


def hmac_verify_or_raise(message: str, tag: str, key: str) -> None:
    """Verify a message or raise VerificationError.

    Args:
        message: The message to verify.
        tag: The HMAC tag to check.
        key: The shared secret key.

    Raises:
        VerificationError: If verification fails.

    """
    if not hmac_verify(message, tag, key):
        msg = "HMAC verification failed -- message may have been tampered with"
        raise VerificationError(msg)
