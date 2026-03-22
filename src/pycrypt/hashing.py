"""Hashing -- one-way fingerprints for data.

A hash function is like a meat grinder: put any data in, get a
fixed-size fingerprint out. You can't reverse it, but the same input
always gives the same fingerprint.

We implement SHA-256 (used by Bitcoin, TLS, and most of the internet)
using Python's hashlib.
"""

import hashlib

SHA256_HEX_LENGTH = 64


def sha256(data: str) -> str:
    """Calculate the SHA-256 hash of a string.

    Args:
        data: The text to hash.

    Returns:
        A 64-character hexadecimal hash string.

    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Calculate the SHA-256 hash of raw bytes.

    Args:
        data: The bytes to hash.

    Returns:
        A 64-character hexadecimal hash string.

    """
    return hashlib.sha256(data).hexdigest()


def md5(data: str) -> str:
    """Calculate the MD5 hash of a string.

    MD5 is broken for security but useful for checksums and teaching.
    Never use MD5 for passwords or security.

    Args:
        data: The text to hash.

    Returns:
        A 32-character hexadecimal hash string.

    """
    return hashlib.md5(data.encode("utf-8")).hexdigest()  # noqa: S324
