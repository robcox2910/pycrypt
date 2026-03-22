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

## Signatures in PyCrypt

```python
from pycrypt.signatures import generate_keypair, sign, verify

# Generate a key pair (private ring + public pattern).
private_key, public_key = generate_keypair()

# Sign a message with the private key.
signature = sign("I approve this transfer", private_key)

# Anyone can verify with the public key.
verify("I approve this transfer", signature, public_key)
# True

verify("I approve a DIFFERENT transfer", signature, public_key)
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
