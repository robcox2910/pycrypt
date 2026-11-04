"""Test key derivation -- turning passwords into strong keys."""

import pytest

from pycrypt.kdf import DEFAULT_KEY_LENGTH, derive_key, pbkdf2_hmac_sha256

FAST_ROUNDS = 1000  # Use fewer rounds in tests for speed.
CUSTOM_KEY_LENGTH = 16
LONG_KEY_LENGTH = 64  # Two blocks of SHA-256 output, so PBKDF2 has to loop.

# Published PBKDF2-HMAC-SHA256 answers. The last one comes from RFC 7914
# and asks for 64 bytes, so it checks the multi-block path too.
PBKDF2_VECTORS = [
    (
        b"password",
        b"salt",
        1,
        32,
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
    ),
    (
        b"password",
        b"salt",
        2,
        32,
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
    ),
    (
        b"passwd",
        b"salt",
        1,
        LONG_KEY_LENGTH,
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
        "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
    ),
]


class TestOfficialVectors:
    """Check the hand-written PBKDF2 against published answers."""

    @pytest.mark.parametrize(("password", "salt", "rounds", "length", "expected"), PBKDF2_VECTORS)
    def test_matches_published_vectors(
        self, password: bytes, salt: bytes, rounds: int, length: int, expected: str
    ) -> None:
        """Verify PBKDF2-HMAC-SHA256 gives the published answer for each case."""
        assert pbkdf2_hmac_sha256(password, salt, rounds, length).hex() == expected


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
