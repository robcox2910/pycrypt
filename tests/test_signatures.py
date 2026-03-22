"""Test digital signatures -- sign and verify messages with key pairs."""

from pycrypt.signatures import generate_keypair, sign, verify

KEY_LENGTH = 32


class TestGenerateKeypair:
    """Test key pair generation."""

    def test_returns_two_different_values(self) -> None:
        """Verify the private and public keys are different."""
        private_key, public_key = generate_keypair()
        assert private_key != public_key

    def test_private_key_is_bytes(self) -> None:
        """Verify the private key is returned as bytes."""
        private_key, _ = generate_keypair()
        assert isinstance(private_key, bytes)

    def test_public_key_is_bytes(self) -> None:
        """Verify the public key is returned as bytes."""
        _, public_key = generate_keypair()
        assert isinstance(public_key, bytes)

    def test_private_key_length(self) -> None:
        """Verify the private key is 32 bytes."""
        private_key, _ = generate_keypair()
        assert len(private_key) == KEY_LENGTH

    def test_keys_are_unique(self) -> None:
        """Verify each call generates a different key pair."""
        private_a, _ = generate_keypair()
        private_b, _ = generate_keypair()
        assert private_a != private_b


class TestSignAndVerify:
    """Test message signing and verification."""

    def test_valid_signature(self) -> None:
        """Verify a signature created with the private key validates with the public key."""
        private_key, public_key = generate_keypair()
        message = "I wrote this!"
        signature = sign(message, private_key)
        assert verify(message, signature, public_key) is True

    def test_fails_for_wrong_message(self) -> None:
        """Verify verification fails when the message is different."""
        private_key, public_key = generate_keypair()
        signature = sign("original message", private_key)
        assert verify("tampered message", signature, public_key) is False

    def test_fails_for_wrong_key(self) -> None:
        """Verify verification fails with a different key pair's public key."""
        private_key_a, _ = generate_keypair()
        _, public_key_b = generate_keypair()
        signature = sign("hello", private_key_a)
        assert verify("hello", signature, public_key_b) is False

    def test_signature_is_bytes(self) -> None:
        """Verify the signature is returned as bytes."""
        private_key, _ = generate_keypair()
        signature = sign("test", private_key)
        assert isinstance(signature, bytes)

    def test_deterministic_with_same_key(self) -> None:
        """Verify signing the same message with the same key gives the same signature."""
        private_key, _ = generate_keypair()
        sig_a = sign("hello", private_key)
        sig_b = sign("hello", private_key)
        assert sig_a == sig_b
