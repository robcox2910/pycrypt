"""Caesar cipher -- the secret decoder ring.

The simplest cipher: shift every letter by a fixed number. A becomes
D (shift 3), B becomes E, and so on. It wraps around: X becomes A.

This is easy to break (only 26 possible shifts) but it's the perfect
starting point for understanding encryption.
"""

ALPHABET_SIZE = 26
UPPER_A = ord("A")
LOWER_A = ord("a")


def encrypt(plaintext: str, shift: int) -> str:
    """Encrypt a message using the Caesar cipher.

    Shift each letter by the given amount. Non-letter characters
    (spaces, numbers, punctuation) are left unchanged.

    Args:
        plaintext: The message to encrypt.
        shift: How many positions to shift (1-25).

    Returns:
        The encrypted message.

    """
    result: list[str] = []
    for char in plaintext:
        if char.isupper():
            shifted = (ord(char) - UPPER_A + shift) % ALPHABET_SIZE
            result.append(chr(shifted + UPPER_A))
        elif char.islower():
            shifted = (ord(char) - LOWER_A + shift) % ALPHABET_SIZE
            result.append(chr(shifted + LOWER_A))
        else:
            result.append(char)
    return "".join(result)


def decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt a Caesar cipher message.

    Shift each letter backwards by the given amount.

    Args:
        ciphertext: The encrypted message.
        shift: The shift that was used to encrypt.

    Returns:
        The original message.

    """
    return encrypt(ciphertext, -shift)


def brute_force(ciphertext: str) -> list[tuple[int, str]]:
    """Try all 26 possible shifts and return the results.

    This shows why the Caesar cipher is weak -- you can break it by
    trying every possible key.

    Args:
        ciphertext: The encrypted message.

    Returns:
        A list of (shift, decrypted_text) tuples.

    """
    return [(shift, decrypt(ciphertext, shift)) for shift in range(ALPHABET_SIZE)]
