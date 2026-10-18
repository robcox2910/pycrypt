"""Property-based tests -- rules that must hold for *every* input.

An ordinary test checks one example someone thought of: "encrypt HELLO
with shift 3 and you get KHOOR". A property test states a rule instead,
such as "decrypting undoes encrypting, whatever the message and whatever
the shift", and lets Hypothesis invent hundreds of messages and shifts to
try to break it. If one breaks the rule, Hypothesis *shrinks* it down to
the smallest input that still fails, and shows you that.

Each test below says its rule in plain English in its docstring. The
strategies at the top are recipes for making random inputs; each one is
named for what it makes.

See ``docs/property-testing.md`` for the walk-through.
"""

import hmac as stdlib_hmac
import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pycrypt.caesar import decrypt, encrypt
from pycrypt.errors import VerificationError
from pycrypt.hmac import hmac_sign, hmac_verify, hmac_verify_or_raise
from pycrypt.xor import xor_decrypt, xor_encrypt, xor_encrypt_bytes

# --- Strategies: recipes for random inputs -----------------------------------


def any_text() -> st.SearchStrategy[str]:
    """Make any text at all: empty, emoji, accents, spaces, Chinese, the lot."""
    return st.text()


def any_bytes() -> st.SearchStrategy[bytes]:
    """Make any run of raw bytes, including the empty one."""
    return st.binary()


def text_keys() -> st.SearchStrategy[str]:
    """Make a text key with at least one character."""
    # The XOR cipher refuses an empty key ("Key must not be empty" in
    # pycrypt.xor._xor_bytes), so an empty key is not a valid input here.
    return st.text(min_size=1)


def byte_keys() -> st.SearchStrategy[bytes]:
    """Make a key of raw bytes with at least one byte."""
    # Same rule as text_keys(): pycrypt.xor._xor_bytes refuses an empty key.
    return st.binary(min_size=1)


def any_shift() -> st.SearchStrategy[int]:
    """Make any whole number to shift by: zero, negative, or far above 26."""
    return st.integers()


def extra_text() -> st.SearchStrategy[str]:
    """Make at least one character to sneak into a message."""
    return st.text(min_size=1)


def any_position() -> st.SearchStrategy[int]:
    """Make a place to insert something (wrapped to fit the message in the test)."""
    return st.integers(min_value=0)


# --- XOR: flipping the same switches twice puts them back ---------------------


@given(data=any_bytes(), key=byte_keys())
def test_xor_bytes_round_trip(data: bytes, key: bytes) -> None:
    """XOR-ing any bytes twice with the same key gives back the original bytes."""
    scrambled = xor_encrypt_bytes(data, key)
    assert xor_encrypt_bytes(scrambled, key) == data


@given(text=any_text(), key=text_keys())
def test_xor_text_round_trip(text: str, key: str) -> None:
    """Decrypting with the same key gives back exactly the text you encrypted."""
    assert xor_decrypt(xor_encrypt(text, key), key) == text


# --- Caesar: every shift can be undone ----------------------------------------


@given(text=any_text(), shift=any_shift())
def test_caesar_round_trip(text: str, shift: int) -> None:
    """Decrypting with the same shift gives back exactly the text you encrypted."""
    assert decrypt(encrypt(text, shift), shift) == text


@given(text=any_text(), shift=any_shift())
def test_caesar_moves_only_english_letters(text: str, shift: int) -> None:
    """Only A-Z and a-z move; they keep their case, and everything else stays put."""
    secret = encrypt(text, shift)
    assert len(secret) == len(text)
    for before, after in zip(text, secret, strict=True):
        if before in string.ascii_uppercase:
            assert after in string.ascii_uppercase
        elif before in string.ascii_lowercase:
            assert after in string.ascii_lowercase
        else:
            assert after == before


# --- HMAC: the seal matches the standard library and breaks when tampered -----


@given(message=any_text(), key=any_text())
def test_hmac_tag_matches_standard_library(message: str, key: str) -> None:
    """Our tag is the same as the one Python's own hmac module makes."""
    expected = stdlib_hmac.digest(key.encode("utf-8"), message.encode("utf-8"), "sha256").hex()
    assert hmac_sign(message, key) == expected


@given(message=any_text(), key=any_text())
def test_hmac_accepts_its_own_tag(message: str, key: str) -> None:
    """A message always passes the check with the tag it was signed with."""
    tag = hmac_sign(message, key)
    assert hmac_verify(message, tag, key)
    hmac_verify_or_raise(message, tag, key)


@given(message=any_text(), key=any_text(), extra=extra_text(), position=any_position())
def test_hmac_rejects_tampered_message(message: str, key: str, extra: str, position: int) -> None:
    """Sneak anything into a signed message, anywhere, and the check fails."""
    tag = hmac_sign(message, key)
    where = position % (len(message) + 1)
    tampered = message[:where] + extra + message[where:]
    assert not hmac_verify(tampered, tag, key)
    with pytest.raises(VerificationError):
        hmac_verify_or_raise(tampered, tag, key)
