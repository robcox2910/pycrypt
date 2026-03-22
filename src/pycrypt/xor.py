"""XOR cipher -- flipping switches to hide data.

XOR is its own inverse: encrypt and decrypt use the same operation.
Each byte of the message is XOR'd with a byte from the key. The key
repeats if it's shorter than the message.

This is the foundation of almost all modern encryption.
"""


def xor_encrypt(data: str, key: str) -> bytes:
    """Encrypt (or decrypt) data using XOR with a repeating key.

    XOR is symmetric -- the same function encrypts and decrypts.

    Args:
        data: The text to encrypt (or ciphertext bytes as a string).
        key: The encryption key.

    Returns:
        The XOR'd result as bytes.

    """
    data_bytes = data.encode("utf-8")
    key_bytes = key.encode("utf-8")
    return _xor_bytes(data_bytes, key_bytes)


def xor_encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """Encrypt (or decrypt) raw bytes using XOR with a repeating key.

    Args:
        data: The bytes to encrypt.
        key: The key bytes.

    Returns:
        The XOR'd result.

    """
    return _xor_bytes(data, key)


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR each byte of data with a repeating key."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))
