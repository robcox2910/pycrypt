"""Test the hashing module -- SHA-256 and MD5 fingerprints."""

from pycrypt.hashing import md5, sha256, sha256_bytes

SHA256_HEX_LENGTH = 64
MD5_HEX_LENGTH = 32


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
