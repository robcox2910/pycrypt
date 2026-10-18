"""Caesar cipher -- the secret decoder ring.

The simplest cipher: shift every letter by a fixed number. A becomes
D (shift 3), B becomes E, and so on. It wraps around: X becomes A.

Only the 26 letters of the English alphabet move. Everything else --
spaces, digits, punctuation, and letters from other alphabets like
"À" or "Σ" -- is left exactly as it was.

This is easy to break (only 26 possible shifts) but it's the perfect
starting point for understanding encryption.
"""

ALPHABET_SIZE = 26
UPPER_A = ord("A")
LOWER_A = ord("a")


def encrypt(plaintext: str, shift: int) -> str:
    """Encrypt a message using the Caesar cipher.

    Shift each letter A-Z (or a-z) by the given amount. Everything else
    (spaces, numbers, punctuation, accented letters) is left unchanged.

    Args:
        plaintext: The message to encrypt.
        shift: How many positions to shift. Any whole number works:
            27 does the same as 1, and -1 the same as 25.

    Returns:
        The encrypted message.

    """
    result: list[str] = []
    for char in plaintext:
        if "A" <= char <= "Z":
            shifted = (ord(char) - UPPER_A + shift) % ALPHABET_SIZE
            result.append(chr(shifted + UPPER_A))
        elif "a" <= char <= "z":
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
