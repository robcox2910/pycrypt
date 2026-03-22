"""HMAC -- tamper-evident seals for messages.

HMAC (Hash-based Message Authentication Code) combines a message with
a secret key to produce a tag. If the message changes, the tag won't
match -- like a broken seal on a jar tells you someone opened it.

Both sender and receiver need the same secret key.
"""

import hashlib
import hmac as _hmac

from pycrypt.errors import VerificationError


def hmac_sign(message: str, key: str) -> str:
    """Create an HMAC tag for a message.

    Args:
        message: The message to authenticate.
        key: The shared secret key.

    Returns:
        A hex-encoded HMAC tag.

    """
    tag = _hmac.new(
        key.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256,
    )
    return tag.hexdigest()


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
