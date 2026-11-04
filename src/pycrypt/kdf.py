"""Key derivation -- turning passwords into strong keys.

A password like "pizza123" is too short and predictable for encryption.
Key derivation mixes it with salt (random data) and many rounds of
hashing to produce a long, strong, unpredictable key.

We use PBKDF2 (Password-Based Key Derivation Function 2), the same
algorithm used by Wi-Fi (WPA2), macOS login, and many others. PyCrypt
writes it by hand on top of its own HMAC:

1. Seal ``salt + block number`` with HMAC, using the password as the key.
2. Seal that result again, and again, for the chosen number of rounds,
   XOR-ing every result together as you go.
3. If you asked for more than 32 bytes, do the same for block 2, 3 and so
   on, and join the blocks together.

All those rounds are the point: they make each guess slow, so someone
trying millions of possible passwords has to do millions of times the work.

Our default is only 1,000 rounds. Real systems use hundreds of thousands
(OWASP recommends 600,000 for PBKDF2-HMAC-SHA256), but they run the hash
in fast C code. PyCrypt's SHA-256 is plain Python you can read, which is
around a hundred times slower, so 1,000 rounds already takes about half a
second. Try ``rounds=10_000`` and feel the slowness that protects real
passwords.
"""

import os

from pycrypt.hmac import hmac_sha256

DEFAULT_KEY_LENGTH = 32  # 256 bits
DEFAULT_ROUNDS = 1_000  # Low for readable Python; see the module docstring.
SHA256_OUTPUT_BYTES = 32
BLOCK_NUMBER_BYTES = 4


def pbkdf2_hmac_sha256(password: bytes, salt: bytes, rounds: int, key_length: int) -> bytes:
    """Stretch a password into a key with PBKDF2-HMAC-SHA256, by hand.

    Args:
        password: The password, as bytes.
        salt: Random salt bytes.
        rounds: How many times to re-seal each block.
        key_length: How many bytes of key to make.

    Returns:
        The derived key, ``key_length`` bytes long.

    """
    blocks: list[bytes] = []
    block_count = -(-key_length // SHA256_OUTPUT_BYTES)  # Round up.
    for block_number in range(1, block_count + 1):
        seal = hmac_sha256(password, salt + block_number.to_bytes(BLOCK_NUMBER_BYTES, "big"))
        combined = int.from_bytes(seal)
        for _ in range(rounds - 1):
            seal = hmac_sha256(password, seal)
            combined ^= int.from_bytes(seal)
        blocks.append(combined.to_bytes(SHA256_OUTPUT_BYTES))
    return b"".join(blocks)[:key_length]


def derive_key(
    password: str,
    salt: bytes | None = None,
    key_length: int = DEFAULT_KEY_LENGTH,
    rounds: int = DEFAULT_ROUNDS,
) -> tuple[bytes, bytes]:
    """Derive a cryptographic key from a password.

    Uses PBKDF2-HMAC-SHA256 with a random salt.

    Args:
        password: The password to derive from.
        salt: Random salt bytes (generated if not provided).
        key_length: Length of the derived key in bytes.
        rounds: Number of hash iterations (more = slower + safer).

    Returns:
        A tuple of (derived_key, salt). Store the salt alongside
        the key so you can re-derive it later.

    """
    if salt is None:
        salt = os.urandom(16)

    key = pbkdf2_hmac_sha256(password.encode("utf-8"), salt, rounds, key_length)
    return key, salt
