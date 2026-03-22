"""Test the Caesar cipher -- shift-based encryption."""

from pycrypt.caesar import brute_force, decrypt, encrypt

SHIFT_3 = 3
SHIFT_1 = 1
ALPHABET_SIZE = 26


class TestCaesarEncrypt:
    """Test Caesar cipher encryption."""

    def test_shift_letters(self) -> None:
        """Verify letters are shifted by the given amount."""
        result = encrypt("ABC", SHIFT_3)
        assert result == "DEF"

    def test_wrapping_z_plus_one(self) -> None:
        """Verify Z wraps around to A with shift 1."""
        result = encrypt("Z", SHIFT_1)
        assert result == "A"

    def test_lowercase(self) -> None:
        """Verify lowercase letters are shifted correctly."""
        result = encrypt("abc", SHIFT_3)
        assert result == "def"

    def test_spaces_preserved(self) -> None:
        """Verify spaces and non-letter characters are not changed."""
        result = encrypt("HELLO WORLD!", SHIFT_3)
        assert result == "KHOOR ZRUOG!"

    def test_numbers_preserved(self) -> None:
        """Verify digits are left unchanged."""
        result = encrypt("ABC 123", SHIFT_3)
        assert result == "DEF 123"


class TestCaesarDecrypt:
    """Test Caesar cipher decryption."""

    def test_round_trip(self) -> None:
        """Verify encrypting then decrypting returns the original text."""
        original = "Hello World"
        encrypted = encrypt(original, SHIFT_3)
        decrypted = decrypt(encrypted, SHIFT_3)
        assert decrypted == original

    def test_decrypt_reverses_encrypt(self) -> None:
        """Verify decrypt undoes encrypt for uppercase text."""
        encrypted = encrypt("XYZ", SHIFT_3)
        assert encrypted == "ABC"
        decrypted = decrypt(encrypted, SHIFT_3)
        assert decrypted == "XYZ"


class TestBruteForce:
    """Test brute-force attack on Caesar cipher."""

    def test_returns_26_results(self) -> None:
        """Verify brute force returns exactly 26 results (one per shift)."""
        results = brute_force("KHOOR")
        assert len(results) == ALPHABET_SIZE

    def test_contains_original(self) -> None:
        """Verify the original plaintext appears in the brute-force results."""
        original = "HELLO"
        encrypted = encrypt(original, SHIFT_3)
        results = brute_force(encrypted)
        decrypted_texts = [text for _, text in results]
        assert original in decrypted_texts

    def test_result_format(self) -> None:
        """Verify each result is a (shift, text) tuple."""
        results = brute_force("ABC")
        for shift, text in results:
            assert isinstance(shift, int)
            assert isinstance(text, str)
