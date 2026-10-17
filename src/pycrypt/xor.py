"""XOR cipher -- flipping switches to hide data.

FOR LEARNING ONLY -- never use this to protect real secrets.

XOR is its own inverse: encrypt and decrypt use the same operation.
Each byte of the message is XOR'd with a byte from the key. The key
repeats if it's shorter than the message.

Why is that unsafe? Because the key *repeats*, the same pattern of
switch-flips happens again and again, and patterns are a codebreaker's
best friend. If an attacker can guess even a few letters of the message
(every letter starts with "Dear..."), XOR-ing those guesses with the
secret text hands them that part of the key -- and the key repeats.

XOR itself is a genuine building block: real ciphers like AES and
ChaCha20 use it inside. What makes them safe is how they produce a long,
never-repeating key stream -- which is the hard part we skip here.
"""

from pycrypt.errors import PyCryptError


def xor_encrypt(data: str, key: str) -> bytes:
    """Encrypt text using XOR with a repeating key.

    To turn the result back into text, use :func:`xor_decrypt` -- it does
    the very same XOR again, then reads the bytes back as text.

    Args:
        data: The text to encrypt.
        key: The encryption key.

    Returns:
        The XOR'd result as bytes.

    """
    data_bytes = data.encode("utf-8")
    key_bytes = key.encode("utf-8")
    return _xor_bytes(data_bytes, key_bytes)


def xor_decrypt(ciphertext: bytes, key: str) -> str:
    """Decrypt bytes made by :func:`xor_encrypt`, back into text.

    XOR is its own undo button: flipping the same switches twice puts them
    all back where they started. So decrypting is just XOR-ing again with
    the same key.

    Args:
        ciphertext: The bytes returned by ``xor_encrypt``.
        key: The same key that was used to encrypt.

    Returns:
        The original text (unreadable gibberish if the key is wrong).

    """
    return _xor_bytes(ciphertext, key.encode("utf-8")).decode("utf-8", errors="replace")


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
    if len(key) == 0:
        msg = "Key must not be empty"
        raise PyCryptError(msg)
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))
