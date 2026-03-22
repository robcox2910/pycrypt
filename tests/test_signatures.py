"""Tests for digital signatures.

Signatures prove who wrote a message and that it hasn't been changed.
These tests verify the signing and verification process.
"""

from pycrypt.signatures import generate_keypair, sign, verify

KEY_SIZE = 32


class TestGenerateKeypair:
    """Verify key pair generation."""

    def test_returns_two_keys(self) -> None:
        """Generate should return signing and verification keys."""
        signing_key, verification_key = generate_keypair()
        assert len(signing_key) == KEY_SIZE
        assert len(verification_key) == KEY_SIZE

    def test_keys_are_different(self) -> None:
        """The two keys should be different."""
        signing_key, verification_key = generate_keypair()
        assert signing_key != verification_key

    def test_each_pair_unique(self) -> None:
        """Each call should generate a unique pair."""
        pair1 = generate_keypair()
        pair2 = generate_keypair()
        assert pair1[0] != pair2[0]


class TestSignAndVerify:
    """Verify signing and verification."""

    def test_valid_signature(self) -> None:
        """A valid signature should verify successfully."""
        signing_key, _verification_key = generate_keypair()
        sig = sign("I wrote this!", signing_key)
        assert verify("I wrote this!", sig, signing_key)

    def test_tampered_message_fails(self) -> None:
        """A changed message should fail verification."""
        signing_key, _verification_key = generate_keypair()
        sig = sign("Original message", signing_key)
        assert not verify("Tampered message", sig, signing_key)

    def test_wrong_key_fails(self) -> None:
        """A signature verified with a different key should fail."""
        key1, _ = generate_keypair()
        key2, _ = generate_keypair()
        sig = sign("Hello", key1)
        assert not verify("Hello", sig, key2)

    def test_signature_is_deterministic(self) -> None:
        """Same message + same key = same signature."""
        signing_key, _ = generate_keypair()
        sig1 = sign("Hello", signing_key)
        sig2 = sign("Hello", signing_key)
        assert sig1 == sig2

    def test_different_messages_different_signatures(self) -> None:
        """Different messages should produce different signatures."""
        signing_key, _ = generate_keypair()
        sig1 = sign("Hello", signing_key)
        sig2 = sign("World", signing_key)
        assert sig1 != sig2

    def test_signature_is_hex_string(self) -> None:
        """The signature should be a hex string."""
        signing_key, _ = generate_keypair()
        sig = sign("Hello", signing_key)
        assert isinstance(sig, str)
        int(sig, 16)  # Should not raise if valid hex.
