# Digital Signatures

!!! warning "For learning, not real security"
    This is a teaching version of signing. Never use it to protect
    real messages or money -- use a vetted library for that.

## The Shared Wax Seal

Imagine you and your best friend share a secret wax stamp that only the
two of you know how to press. When your friend gets a letter sealed
with that stamp, they know it's really from you (nobody else can make
the seal) and that no one tampered with it on the way (a changed letter
breaks the seal).

A **digital signature** in PyCrypt works exactly like that shared
stamp -- the *same* secret key is used to make (sign) and to check
(verify) the seal:

1. The signer combines the message with the shared secret key.
2. That produces a signature (under the hood, an HMAC tag).
3. Anyone who holds the *same* key recomputes it and checks it matches.

If the recomputed signature matches, two things are proven:

- **Authenticity** -- only someone with the shared key could have made it
- **Integrity** -- the message hasn't been changed since signing

Real systems like RSA and ECDSA use a **pair** of keys instead: a
*private* key to sign and a *public* key anyone can verify with, so the
whole world can check a signature without knowing your secret. That
needs advanced math we'll learn later -- building it yourself is a
great exercise to try once you've met modular arithmetic!

## Signatures in PyCrypt

```python
import os
from pycrypt.signatures import sign, verify

# Create a shared secret key.
key = os.urandom(32)

# Sign a message with the key.
signature = sign("I approve this transfer", key)

# Verify with the same key.
verify("I approve this transfer", signature, key)
# True

verify("I approve a DIFFERENT transfer", signature, key)
# False -- message was changed!
```

## What We Test

- Signing produces a hex-string signature.
- Verification succeeds for the correct message + signature.
- Verification fails if the message is changed.
- Verification fails if a different key is used.
- Signing the same message with the same key is deterministic.
- The signature really is an HMAC tag (not a homemade hash).

## What's Next?

You've learned every major concept in cryptography! Hashing, the
Caesar cipher, XOR encryption, key derivation, HMAC authentication,
and digital signatures. These are the same building blocks that
protect billions of messages, payments, and connections every day.
