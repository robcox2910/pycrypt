# Digital Signatures

## The Wax Seal

In medieval times, a king would press his signet ring into hot wax on
a letter. Anyone could verify the seal was the king's (they'd
recognise the pattern), but only the king could create it (only he
had the ring).

A **digital signature** works the same way:

1. The sender hashes the message.
2. The sender encrypts the hash with their **private key** (the ring).
3. Anyone can decrypt it with the sender's **public key** to verify.

If the decrypted hash matches the message's hash, two things are
proven:
- **Authenticity** -- only the private key holder could have signed it
- **Integrity** -- the message hasn't been changed since signing

Our simplified version uses one key for both signing and verifying
(like a shared stamp). Real systems like RSA use separate private/public
keys -- that requires advanced math we'll learn later.

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

- Signing produces a signature.
- Verification succeeds for the correct message + signature.
- Verification fails if the message is changed.
- Verification fails if a different key is used.
- Each key pair is unique.

## What's Next?

You've learned every major concept in cryptography! Hashing, the
Caesar cipher, XOR encryption, key derivation, HMAC authentication,
and digital signatures. These are the same building blocks that
protect billions of messages, payments, and connections every day.
