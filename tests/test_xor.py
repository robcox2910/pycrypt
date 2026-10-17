"""Test the XOR cipher -- symmetric bitwise encryption."""

import pytest

import pycrypt.xor
from pycrypt.errors import PyCryptError
from pycrypt.xor import xor_decrypt, xor_encrypt, xor_encrypt_bytes


class TestXorEncrypt:
    """Test XOR encryption of strings."""

    def test_round_trip(self) -> None:
        """Verify encrypting then decrypting with XOR returns the original."""
        message = "secret message"
        key = "mykey"
        encrypted = xor_encrypt(message, key)
        # XOR is symmetric: XOR the encrypted bytes with the same key to decrypt.
        decrypted_bytes = xor_encrypt_bytes(encrypted, key.encode("utf-8"))
        assert decrypted_bytes.decode("utf-8") == message

    def test_different_keys_different_output(self) -> None:
        """Verify different keys produce different ciphertext."""
        message = "hello"
        result_a = xor_encrypt(message, "key1")
        result_b = xor_encrypt(message, "key2")
        assert result_a != result_b

    def test_key_repeats_for_long_messages(self) -> None:
        """Verify a short key repeats to cover a longer message."""
        key = "ab"
        message = "xxxx"
        encrypted = xor_encrypt(message, key)
        # With a 2-byte repeating key, bytes 0 and 2 should match,
        # and bytes 1 and 3 should match.
        assert encrypted[0] == encrypted[2]
        assert encrypted[1] == encrypted[3]

    def test_output_is_bytes(self) -> None:
        """Verify xor_encrypt returns bytes."""
        result = xor_encrypt("test", "key")
        assert isinstance(result, bytes)

    def test_same_key_same_output(self) -> None:
        """Verify the same message and key always produce the same result."""
        result_a = xor_encrypt("hello", "key")
        result_b = xor_encrypt("hello", "key")
        assert result_a == result_b

    def test_empty_key_raises(self) -> None:
        """Verify an empty key raises PyCryptError."""
        with pytest.raises(PyCryptError):
            xor_encrypt("data", "")


class TestXorEncryptBytes:
    """Test XOR encryption of raw bytes."""

    def test_round_trip(self) -> None:
        """Verify encrypting then decrypting bytes returns the original."""
        data = b"binary data"
        key = b"secret"
        encrypted = xor_encrypt_bytes(data, key)
        decrypted = xor_encrypt_bytes(encrypted, key)
        assert decrypted == data

    def test_output_length_matches_input(self) -> None:
        """Verify the output length matches the input length."""
        data = b"hello"
        key = b"k"
        result = xor_encrypt_bytes(data, key)
        assert len(result) == len(data)


class TestDecrypt:
    """xor_decrypt undoes xor_encrypt and hands back readable text."""

    def test_round_trip_returns_the_original_text(self) -> None:
        """Encrypting then decrypting with the same key gives back the message."""
        secret = xor_encrypt("meet at noon 🙂", "key")
        assert xor_decrypt(secret, "key") == "meet at noon 🙂"

    def test_wrong_key_does_not_reveal_the_message(self) -> None:
        """A different key gives back something other than the message."""
        secret = xor_encrypt("meet at noon", "key")
        assert xor_decrypt(secret, "nope") != "meet at noon"


def test_module_warns_it_is_for_learning_only() -> None:
    """A repeating-key XOR is easy to break, so the module says so up front."""
    assert pycrypt.xor.__doc__ is not None
    assert "FOR LEARNING ONLY" in pycrypt.xor.__doc__
