"""PyCrypt CLI -- demonstrate cryptography concepts."""

import sys

from pycrypt.caesar import decrypt as caesar_decrypt
from pycrypt.caesar import encrypt as caesar_encrypt
from pycrypt.hashing import sha256
from pycrypt.hmac import hmac_sign, hmac_verify
from pycrypt.xor import xor_encrypt

CAESAR_SHIFT = 3
SEPARATOR = "-" * 50


def _demo_hashing() -> None:
    """Demonstrate SHA-256 hashing."""
    sys.stdout.write("1. HASHING (SHA-256)\n")
    sys.stdout.write(SEPARATOR + "\n")
    message = "Hello, World!"
    digest = sha256(message)
    sys.stdout.write(f'   sha256("{message}") = {digest}\n')
    sys.stdout.write(f'   sha256("{message}") = {sha256(message)}  (same!)\n')
    sys.stdout.write(f'   sha256("hello, world!") = {sha256("hello, world!")}  (different!)\n\n')


def _demo_caesar() -> None:
    """Demonstrate Caesar cipher encryption."""
    sys.stdout.write("2. CAESAR CIPHER\n")
    sys.stdout.write(SEPARATOR + "\n")
    plaintext = "HELLO WORLD"
    encrypted = caesar_encrypt(plaintext, CAESAR_SHIFT)
    decrypted = caesar_decrypt(encrypted, CAESAR_SHIFT)
    sys.stdout.write(f"   Plaintext:  {plaintext}\n")
    sys.stdout.write(f"   Encrypted:  {encrypted}  (shift {CAESAR_SHIFT})\n")
    sys.stdout.write(f"   Decrypted:  {decrypted}\n\n")


def _demo_xor() -> None:
    """Demonstrate XOR encryption."""
    sys.stdout.write("3. XOR CIPHER\n")
    sys.stdout.write(SEPARATOR + "\n")
    message = "secret"
    key = "mykey"
    encrypted = xor_encrypt(message, key)
    sys.stdout.write(f'   xor_encrypt("{message}", "{key}") = {encrypted.hex()}\n')
    decrypted = xor_encrypt(message, key)
    sys.stdout.write(f"   XOR is symmetric: encrypt again = {decrypted.hex()}\n\n")


def _demo_hmac() -> None:
    """Demonstrate HMAC signing and verification."""
    sys.stdout.write("4. HMAC (Message Authentication)\n")
    sys.stdout.write(SEPARATOR + "\n")
    message = "transfer $10"
    key = "shared-secret"
    tag = hmac_sign(message, key)
    sys.stdout.write(f"   Message: {message}\n")
    sys.stdout.write(f"   HMAC tag: {tag}\n")
    sys.stdout.write(f"   Verify original:  {hmac_verify(message, tag, key)}\n")
    sys.stdout.write(f'   Verify tampered:  {hmac_verify("transfer $1000", tag, key)}\n\n')


def main() -> None:
    """Run all cryptography demos."""
    sys.stdout.write("PyCrypt -- Cryptography from scratch\n\n")
    _demo_hashing()
    _demo_caesar()
    _demo_xor()
    _demo_hmac()
    sys.stdout.write("Learn more: https://robcox2910.github.io/pycrypt/\n")
