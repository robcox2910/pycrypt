"""Test key derivation -- turning passwords into strong keys."""

from pycrypt.kdf import DEFAULT_KEY_LENGTH, derive_key

FAST_ROUNDS = 1000  # Use fewer rounds in tests for speed.
CUSTOM_KEY_LENGTH = 16


class TestDeriveKey:
    """Test PBKDF2 key derivation."""

    def test_same_password_and_salt_same_key(self) -> None:
        """Verify the same password and salt always produce the same key."""
        salt = b"fixed-salt-value"
        key_a, _ = derive_key("password", salt=salt, rounds=FAST_ROUNDS)
        key_b, _ = derive_key("password", salt=salt, rounds=FAST_ROUNDS)
        assert key_a == key_b

    def test_different_salt_different_key(self) -> None:
        """Verify different salts produce different keys."""
        key_a, _ = derive_key("password", salt=b"salt-one", rounds=FAST_ROUNDS)
        key_b, _ = derive_key("password", salt=b"salt-two", rounds=FAST_ROUNDS)
        assert key_a != key_b

    def test_key_is_correct_length(self) -> None:
        """Verify the derived key has the requested length."""
        key, _ = derive_key("password", salt=b"salt", rounds=FAST_ROUNDS)
        assert len(key) == DEFAULT_KEY_LENGTH

    def test_custom_key_length(self) -> None:
        """Verify a custom key length is respected."""
        key, _ = derive_key(
            "password",
            salt=b"salt",
            key_length=CUSTOM_KEY_LENGTH,
            rounds=FAST_ROUNDS,
        )
        assert len(key) == CUSTOM_KEY_LENGTH

    def test_auto_generates_salt(self) -> None:
        """Verify a salt is generated when none is provided."""
        _, salt = derive_key("password", rounds=FAST_ROUNDS)
        assert isinstance(salt, bytes)
        assert len(salt) > 0

    def test_auto_salt_is_random(self) -> None:
        """Verify auto-generated salts are different each time."""
        _, salt_a = derive_key("password", rounds=FAST_ROUNDS)
        _, salt_b = derive_key("password", rounds=FAST_ROUNDS)
        assert salt_a != salt_b

    def test_returns_tuple(self) -> None:
        """Verify derive_key returns a (key, salt) tuple."""
        result = derive_key("password", salt=b"salt", rounds=FAST_ROUNDS)
        key, salt = result
        assert isinstance(key, bytes)
        assert isinstance(salt, bytes)
