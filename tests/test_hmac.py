"""Test HMAC -- tamper-evident message authentication."""

import pytest

from pycrypt.errors import VerificationError
from pycrypt.hmac import hmac_sign, hmac_verify, hmac_verify_or_raise

SHA256_HMAC_HEX_LENGTH = 64


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
