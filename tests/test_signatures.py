"""Tests for digital signatures.

Signatures prove who wrote a message and that it hasn't been changed.
These tests verify the signing and verification process.
"""

import os

from pycrypt.signatures import sign, verify

KEY_SIZE = 32


class TestSignAndVerify:
    """Verify signing and verification."""

    def test_valid_signature(self) -> None:
        """A valid signature should verify successfully."""
        key = os.urandom(KEY_SIZE)
        sig = sign("I wrote this!", key)
        assert verify("I wrote this!", sig, key)

    def test_tampered_message_fails(self) -> None:
        """A changed message should fail verification."""
        key = os.urandom(KEY_SIZE)
        sig = sign("Original message", key)
        assert not verify("Tampered message", sig, key)

    def test_wrong_key_fails(self) -> None:
        """A signature verified with a different key should fail."""
        key1 = os.urandom(KEY_SIZE)
        key2 = os.urandom(KEY_SIZE)
        sig = sign("Hello", key1)
        assert not verify("Hello", sig, key2)

    def test_signature_is_deterministic(self) -> None:
        """Same message + same key = same signature."""
        key = os.urandom(KEY_SIZE)
        sig1 = sign("Hello", key)
        sig2 = sign("Hello", key)
        assert sig1 == sig2

    def test_different_messages_different_signatures(self) -> None:
        """Different messages should produce different signatures."""
        key = os.urandom(KEY_SIZE)
        sig1 = sign("Hello", key)
        sig2 = sign("World", key)
        assert sig1 != sig2

    def test_signature_is_hex_string(self) -> None:
        """The signature should be a hex string."""
        key = os.urandom(KEY_SIZE)
        sig = sign("Hello", key)
        assert isinstance(sig, str)
        int(sig, 16)  # Should not raise if valid hex.
