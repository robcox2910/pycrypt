"""Hashing -- one-way fingerprints for data, written out by hand.

A hash function is like a meat grinder: put any data in, get a
fixed-size fingerprint out. You can't reverse it, but the same input
always gives the same fingerprint.

This module builds two real hash functions from scratch, so you can read
every step:

- **SHA-256**, used by Bitcoin, TLS, Git's newer object format and most
  of the internet.
- **MD5**, an older hash that is now broken for security but is still a
  nice, smaller example to read.

Both work the same way at heart:

1. **Pad** the message so its length is a whole number of 64-byte blocks,
   with the original length written into the last few bytes.
2. Start with a few fixed numbers (the *state*).
3. For each block, **stir** the block into the state with lots of
   rotating, adding and mixing, round after round.
4. The final state, written out as bytes, is the fingerprint.

The stirring is designed so that changing one bit of the message changes
about half the bits of the answer (the *avalanche* effect).

The tests check every answer against Python's own ``hashlib``, which is
how we know the hand-written versions are right.
"""

import math
import struct
from typing import Literal

BLOCK_SIZE = 64  # Both hashes chew through the message 64 bytes at a time.
SHA256_HEX_LENGTH = 64
MASK_32 = 0xFFFFFFFF  # Keep every number to 32 bits, like the real chips do.
LENGTH_BYTES = 8  # The padded message ends with its length in 8 bytes.
BITS_PER_BYTE = 8

# --- Shared padding -----------------------------------------------------------


def _pad(message: bytes, length_order: Literal["big", "little"]) -> bytes:
    """Pad a message out to whole 64-byte blocks, ending with its bit length.

    Add a single ``1`` bit (the byte ``0x80``), then zeros, then the
    original length in bits as an 8-byte number. SHA-256 writes the length
    big-endian (biggest byte first) and MD5 little-endian.

    Args:
        message: The bytes to pad.
        length_order: ``"big"`` for SHA-256 or ``"little"`` for MD5.

    Returns:
        The padded message, a multiple of 64 bytes long.

    """
    bit_length = (len(message) * BITS_PER_BYTE) & 0xFFFFFFFFFFFFFFFF
    padded = message + b"\x80"
    while len(padded) % BLOCK_SIZE != BLOCK_SIZE - LENGTH_BYTES:
        padded += b"\x00"
    return padded + bit_length.to_bytes(LENGTH_BYTES, length_order)


# --- SHA-256 --------------------------------------------------------------------

# The starting state: the first 32 bits of the fractional parts of the
# square roots of the first 8 primes. "Nothing up my sleeve" numbers --
# anyone can check where they came from.
SHA256_START = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

# One round constant per round: the first 32 bits of the fractional parts
# of the cube roots of the first 64 primes.
SHA256_ROUND_CONSTANTS = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)  # fmt: skip
SHA256_ROUNDS = 64
SHA256_BLOCK_WORDS = 16


def _rotate_right(value: int, places: int) -> int:
    """Rotate a 32-bit number right: bits that fall off the end wrap round."""
    return ((value >> places) | (value << (32 - places))) & MASK_32


def _sha256_schedule(block: bytes) -> list[int]:
    """Stretch one 64-byte block into 64 words, one for each round.

    The first 16 words are the block itself. Each later word mixes four
    earlier ones, so every bit of the block ends up spread across the
    rounds.

    Args:
        block: One 64-byte block of the padded message.

    Returns:
        A list of 64 32-bit words.

    """
    words = list(struct.unpack(">16I", block))
    for i in range(SHA256_BLOCK_WORDS, SHA256_ROUNDS):
        w15, w2 = words[i - 15], words[i - 2]
        s0 = _rotate_right(w15, 7) ^ _rotate_right(w15, 18) ^ (w15 >> 3)
        s1 = _rotate_right(w2, 17) ^ _rotate_right(w2, 19) ^ (w2 >> 10)
        words.append((words[i - 16] + s0 + words[i - 7] + s1) & MASK_32)
    return words


def _sha256_compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    """Stir one 64-byte block into the eight-number state.

    Eight working values (a to h) go through 64 rounds. Each round mixes
    in one word of the block and one round constant, then shuffles the
    values along by one place. At the end, the result is added back onto
    the old state.

    Args:
        state: The current eight 32-bit numbers.
        block: One 64-byte block of the padded message.

    Returns:
        The new eight-number state.

    """
    a, b, c, d, e, f, g, h = state
    for constant, word in zip(SHA256_ROUND_CONSTANTS, _sha256_schedule(block), strict=True):
        big_e = _rotate_right(e, 6) ^ _rotate_right(e, 11) ^ _rotate_right(e, 25)
        choose = (e & f) ^ (~e & g)  # e picks, bit by bit, between f and g.
        temp1 = (h + big_e + choose + constant + word) & MASK_32
        big_a = _rotate_right(a, 2) ^ _rotate_right(a, 13) ^ _rotate_right(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)  # Each bit votes: what do most say?
        temp2 = (big_a + majority) & MASK_32
        a, b, c, d, e, f, g, h = (temp1 + temp2) & MASK_32, a, b, c, (d + temp1) & MASK_32, e, f, g
    return tuple(
        (old + new) & MASK_32 for old, new in zip(state, (a, b, c, d, e, f, g, h), strict=True)
    )


def sha256_digest(data: bytes) -> bytes:
    """Calculate the SHA-256 fingerprint of some bytes, by hand.

    Args:
        data: The bytes to hash.

    Returns:
        The 32-byte fingerprint.

    """
    padded = _pad(data, "big")
    state = SHA256_START
    for start in range(0, len(padded), BLOCK_SIZE):
        state = _sha256_compress(state, padded[start : start + BLOCK_SIZE])
    return struct.pack(">8I", *state)


def sha256(data: str) -> str:
    """Calculate the SHA-256 hash of a string.

    Args:
        data: The text to hash.

    Returns:
        A 64-character hexadecimal hash string.

    """
    return sha256_digest(data.encode("utf-8")).hex()


def sha256_bytes(data: bytes) -> str:
    """Calculate the SHA-256 hash of raw bytes.

    Args:
        data: The bytes to hash.

    Returns:
        A 64-character hexadecimal hash string.

    """
    return sha256_digest(data).hex()


# --- MD5 ------------------------------------------------------------------------

MD5_START = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
MD5_ROUNDS = 64
ROUNDS_PER_STAGE = 16

# How far to rotate in each of the 64 steps (four stages of 16).
MD5_ROTATIONS = (7, 12, 17, 22) * 4 + (5, 9, 14, 20) * 4 + (4, 11, 16, 23) * 4 + (6, 10, 15, 21) * 4

# One constant per step, made from the sine function: the whole-number part
# of abs(sin(i + 1)) times 2**32. More "nothing up my sleeve" numbers.
MD5_CONSTANTS = tuple(int(abs(math.sin(i + 1)) * 2**32) & MASK_32 for i in range(MD5_ROUNDS))


def _rotate_left(value: int, places: int) -> int:
    """Rotate a 32-bit number left: bits that fall off the front wrap round."""
    return ((value << places) | (value >> (32 - places))) & MASK_32


def _md5_mix(step: int, b: int, c: int, d: int) -> tuple[int, int]:
    """Pick MD5's mixing function and message word for one step.

    MD5 has four stages of 16 steps, each with its own way of combining
    three of the four working values, and its own order for visiting the
    16 words of the block.

    Args:
        step: Which of the 64 steps this is.
        b: The second working value.
        c: The third working value.
        d: The fourth working value.

    Returns:
        The mixed value and the index of the message word to add.

    """
    stage = step // ROUNDS_PER_STAGE
    if stage == 0:
        return (b & c) | (~b & d), step
    if stage == 1:
        return (d & b) | (~d & c), (5 * step + 1) % ROUNDS_PER_STAGE
    if stage == 2:  # noqa: PLR2004 -- the stages are simply numbered 0 to 3.
        return b ^ c ^ d, (3 * step + 5) % ROUNDS_PER_STAGE
    return c ^ (b | (~d & MASK_32)), (7 * step) % ROUNDS_PER_STAGE


def _md5_compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    """Stir one 64-byte block into MD5's four-number state.

    Args:
        state: The current four 32-bit numbers.
        block: One 64-byte block of the padded message.

    Returns:
        The new four-number state.

    """
    words = struct.unpack("<16I", block)
    a, b, c, d = state
    for step in range(MD5_ROUNDS):
        mixed, index = _md5_mix(step, b, c, d)
        mixed = (mixed + a + MD5_CONSTANTS[step] + words[index]) & MASK_32
        a, d, c = d, c, b
        b = (b + _rotate_left(mixed, MD5_ROTATIONS[step])) & MASK_32
    return tuple((old + new) & MASK_32 for old, new in zip(state, (a, b, c, d), strict=True))


def md5_digest(data: bytes) -> bytes:
    """Calculate the MD5 fingerprint of some bytes, by hand.

    MD5 is broken for security (people can make two different files with
    the same fingerprint), so never use it for passwords or signatures.
    It is still handy for checksums and for learning.

    Args:
        data: The bytes to hash.

    Returns:
        The 16-byte fingerprint.

    """
    padded = _pad(data, "little")
    state = MD5_START
    for start in range(0, len(padded), BLOCK_SIZE):
        state = _md5_compress(state, padded[start : start + BLOCK_SIZE])
    return struct.pack("<4I", *state)


def md5(data: str) -> str:
    """Calculate the MD5 hash of a string.

    MD5 is broken for security but useful for checksums and teaching.
    Never use MD5 for passwords or security.

    Args:
        data: The text to hash.

    Returns:
        A 32-character hexadecimal hash string.

    """
    return md5_digest(data.encode("utf-8")).hex()
