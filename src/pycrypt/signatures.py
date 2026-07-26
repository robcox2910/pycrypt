"""Digital signatures -- a wax seal only you and your friend can make.

FOR LEARNING ONLY -- never use this to protect real secrets.

Imagine a wax seal that only you and your best friend know how to
press -- because you both share the same secret stamp. When your
friend gets a letter with that seal, they know it's really from you
(authenticity) and that no one changed it on the way (integrity).

Our educational version works exactly like that shared stamp: the
*same* secret key is used to both make (sign) and check (verify) the
seal. Under the hood we reuse HMAC, so the "seal" really is an HMAC
tag. Real signature systems like RSA and ECDSA use a *pair* of keys --
a private one to sign and a public one anyone can verify with -- so
the whole world can check a signature without knowing your secret.
That needs advanced math we'll learn later.

The key ideas are the same:
- Only someone with the shared key can create a valid signature
- Verification checks that the signature matches the message
- Changing the message breaks the signature
"""

import hmac as _hmac

from pycrypt.hmac import hmac_sign


def sign(message: str, key: bytes) -> str:
    """Sign a message -- press the shared wax seal.

    Create a signature that proves the message is authentic and
    hasn't been changed. Only someone with the key can produce a
    valid signature. Internally this is an HMAC tag over the message.

    Args:
        message: The message to sign.
        key: The secret key (shared between signer and verifier).

    Returns:
        The signature as a hex string.

    """
    return hmac_sign(message, key.hex())


def verify(message: str, signature: str, key: bytes) -> bool:
    """Verify a signature -- check the wax seal is genuine.

    Recompute what the signature should be and check if it matches.
    Uses constant-time comparison to prevent timing attacks.

    Args:
        message: The message that was supposedly signed.
        signature: The hex signature to verify.
        key: The secret key (same key used for signing).

    Returns:
        True if the signature is valid.

    """
    expected = sign(message, key)
    return _hmac.compare_digest(signature, expected)
