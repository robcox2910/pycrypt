"""Test HMAC -- tamper-evident message authentication."""

import pytest

from pycrypt.errors import VerificationError
from pycrypt.hmac import hmac_sha256, hmac_sign, hmac_verify, hmac_verify_or_raise

SHA256_HMAC_HEX_LENGTH = 64

# Test cases 1, 2 and 6 from RFC 4231. Case 6 uses a key longer than one
# 64-byte block, which HMAC has to hash down first.
RFC4231_VECTORS = [
    (
        b"\x0b" * 20,
        b"Hi There",
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    ),
    (
        b"Jefe",
        b"what do ya want for nothing?",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    ),
    (
        b"\xaa" * 131,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    ),
]


class TestOfficialVectors:
    """Check the hand-written HMAC against RFC 4231's published answers."""

    @pytest.mark.parametrize(("key", "message", "expected"), RFC4231_VECTORS)
    def test_matches_rfc4231(self, key: bytes, message: bytes, expected: str) -> None:
        """Verify HMAC-SHA256 gives the RFC's answer for each test case."""
        assert hmac_sha256(key, message).hex() == expected


class TestHmacSign:
    """Test HMAC tag generation."""

    def test_deterministic(self) -> None:
        """Verify the same message and key always produce the same tag."""
        tag_a = hmac_sign("hello", "secret")
        tag_b = hmac_sign("hello", "secret")
        assert tag_a == tag_b

    def test_different_messages_different_tags(self) -> None:
        """Verify different messages produce different tags."""
        tag_a = hmac_sign("hello", "secret")
        tag_b = hmac_sign("world", "secret")
        assert tag_a != tag_b

    def test_different_keys_different_tags(self) -> None:
        """Verify different keys produce different tags for the same message."""
        tag_a = hmac_sign("hello", "key1")
        tag_b = hmac_sign("hello", "key2")
        assert tag_a != tag_b

    def test_tag_length(self) -> None:
        """Verify the HMAC tag is a 64-character hex string."""
        tag = hmac_sign("hello", "secret")
        assert len(tag) == SHA256_HMAC_HEX_LENGTH


class TestHmacVerify:
    """Test HMAC tag verification."""

    def test_succeeds_for_correct_message(self) -> None:
        """Verify a valid tag passes verification."""
        tag = hmac_sign("hello", "secret")
        assert hmac_verify("hello", tag, "secret") is True

    def test_fails_for_tampered_message(self) -> None:
        """Verify a tampered message fails verification."""
        tag = hmac_sign("hello", "secret")
        assert hmac_verify("TAMPERED", tag, "secret") is False

    def test_fails_for_wrong_key(self) -> None:
        """Verify the wrong key fails verification."""
        tag = hmac_sign("hello", "correct-key")
        assert hmac_verify("hello", tag, "wrong-key") is False


class TestHmacVerifyOrRaise:
    """Test HMAC verification that raises on failure."""

    def test_succeeds_silently(self) -> None:
        """Verify no exception is raised for a valid tag."""
        tag = hmac_sign("hello", "secret")
        hmac_verify_or_raise("hello", tag, "secret")  # Should not raise.

    def test_raises_on_tampered_message(self) -> None:
        """Verify a VerificationError is raised for a tampered message."""
        tag = hmac_sign("hello", "secret")
        with pytest.raises(VerificationError, match="HMAC verification failed"):
            hmac_verify_or_raise("TAMPERED", tag, "secret")

    def test_raises_on_wrong_key(self) -> None:
        """Verify a VerificationError is raised for the wrong key."""
        tag = hmac_sign("hello", "correct-key")
        with pytest.raises(VerificationError):
            hmac_verify_or_raise("hello", tag, "wrong-key")
