"""Digital signatures -- wax seals for the digital age.

A digital signature proves who wrote a message (authenticity) and
that it hasn't been changed (integrity). The signer uses their
private key; anyone can verify with the public key.

This is a simplified educational implementation using HMAC-based
signing. Real systems use RSA or ECDSA, but the concepts are
identical: private key signs, public key verifies.
"""

import os

from pycrypt.hashing import sha256
from pycrypt.xor import xor_encrypt_bytes


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new private/public key pair.

    In real cryptography, these are mathematically related (RSA,
    ECDSA). Our educational version uses random bytes.

    Returns:
        A tuple of (private_key, public_key).

    """
    private_key = os.urandom(32)
    # Derive the public key from the private key (simplified).
    public_key = sha256(private_key.hex()).encode("utf-8")[:32]
    return private_key, public_key


def sign(message: str, private_key: bytes) -> bytes:
    """Sign a message with a private key.

    Hash the message, then encrypt the hash with the private key.
    Only the private key holder can create this signature.

    Args:
        message: The message to sign.
        private_key: The signer's private key.

    Returns:
        The signature as bytes.

    """
    message_hash = sha256(message).encode("utf-8")
    return xor_encrypt_bytes(message_hash, private_key)


def verify(message: str, signature: bytes, public_key: bytes) -> bool:
    """Verify a signature against a message and public key.

    Decrypt the signature using the public key's corresponding
    private key relationship, and compare to the message hash.

    Args:
        message: The message that was supposedly signed.
        signature: The signature to verify.
        public_key: The signer's public key.

    Returns:
        True if the signature is valid.

    """
    message_hash = sha256(message)
    # Recover the hash from the signature.
    recovered = xor_encrypt_bytes(signature, public_key)
    try:
        recovered_str = recovered.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return recovered_str == message_hash
