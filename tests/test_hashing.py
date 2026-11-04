"""Test the hashing module -- SHA-256 and MD5 fingerprints."""

import pytest

from pycrypt.hashing import md5, md5_digest, sha256, sha256_bytes, sha256_digest

SHA256_HEX_LENGTH = 64
MD5_HEX_LENGTH = 32
SHA256_DIGEST_BYTES = 32
MD5_DIGEST_BYTES = 16

# Official answers from the standards, so we know the hand-written
# versions match everyone else's SHA-256 and MD5 exactly.
NIST_SHA256_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
]
RFC1321_MD5_VECTORS = [
    (b"", "d41d8cd98f00b204e9800998ecf8427e"),
    (b"a", "0cc175b9c0f1b6a831c399e269772661"),
    (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
    (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
    (
        b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "57edf4a22be3c955ac49da2e2107b67a",
    ),
]


class TestOfficialVectors:
    """Check the hand-written hashes against the published answers."""

    @pytest.mark.parametrize(("message", "expected"), NIST_SHA256_VECTORS)
    def test_sha256_matches_nist(self, message: bytes, expected: str) -> None:
        """Verify SHA-256 gives NIST's answer for each test message."""
        assert sha256_digest(message).hex() == expected

    @pytest.mark.parametrize(("message", "expected"), RFC1321_MD5_VECTORS)
    def test_md5_matches_rfc1321(self, message: bytes, expected: str) -> None:
        """Verify MD5 gives RFC 1321's answer for each test message."""
        assert md5_digest(message).hex() == expected

    def test_digest_sizes(self) -> None:
        """Verify SHA-256 makes 32 bytes and MD5 makes 16."""
        assert len(sha256_digest(b"x")) == SHA256_DIGEST_BYTES
        assert len(md5_digest(b"x")) == MD5_DIGEST_BYTES


class TestSha256:
    """Test SHA-256 hashing."""

    def test_deterministic(self) -> None:
        """Verify the same input always produce the same hash."""
        result_a = sha256("hello")
        result_b = sha256("hello")
        assert result_a == result_b

    def test_different_inputs_produce_different_hashes(self) -> None:
        """Verify different inputs produce different hashes."""
        hash_a = sha256("hello")
        hash_b = sha256("world")
        assert hash_a != hash_b

    def test_output_length(self) -> None:
        """Verify SHA-256 output is always 64 hex characters."""
        result = sha256("test data")
        assert len(result) == SHA256_HEX_LENGTH

    def test_hex_characters_only(self) -> None:
        """Verify the hash contains only valid hex characters."""
        result = sha256("anything")
        assert all(c in "0123456789abcdef" for c in result)


class TestMd5:
    """Test MD5 hashing."""

    def test_output_length(self) -> None:
        """Verify MD5 output is always 32 hex characters."""
        result = md5("test data")
        assert len(result) == MD5_HEX_LENGTH

    def test_different_from_sha256(self) -> None:
        """Verify MD5 and SHA-256 produce different hashes for the same input."""
        md5_hash = md5("hello")
        sha256_hash = sha256("hello")
        assert md5_hash != sha256_hash

    def test_deterministic(self) -> None:
        """Verify the same input always produce the same MD5 hash."""
        result_a = md5("hello")
        result_b = md5("hello")
        assert result_a == result_b


class TestSha256Bytes:
    """Test SHA-256 hashing of raw bytes."""

    def test_output_length(self) -> None:
        """Verify SHA-256 bytes output is 64 hex characters."""
        result = sha256_bytes(b"raw bytes")
        assert len(result) == SHA256_HEX_LENGTH

    def test_matches_string_version(self) -> None:
        """Verify hashing bytes gives the same result as hashing the equivalent string."""
        text = "hello"
        assert sha256_bytes(text.encode("utf-8")) == sha256(text)

    def test_deterministic(self) -> None:
        """Verify the same bytes always produce the same hash."""
        result_a = sha256_bytes(b"\x00\x01\x02")
        result_b = sha256_bytes(b"\x00\x01\x02")
        assert result_a == result_b
