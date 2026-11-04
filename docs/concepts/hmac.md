# HMAC

## The Tamper-Evident Seal

Imagine buying a jar of jam. The lid has a safety seal -- if someone
opened the jar and put something inside, the broken seal would tell
you not to trust it.

**HMAC** (Hash-based Message Authentication Code) is a tamper-evident
seal for data. It combines a message with a secret key to produce a
**tag**. If even one bit of the message changes, the tag changes too.

## How It Works

```
message + secret key → HMAC tag
```

The sender calculates the tag and attaches it. The receiver
recalculates the tag with the same key. If the tags match, the
message is authentic and untampered.

## The Recipe Inside

HMAC seals the message twice, like a letter in an envelope inside
another envelope:

1. Make the key exactly 64 bytes: hash it if it's longer, pad it with
   zeros if it's shorter.
2. **Inner envelope:** mix the key with one mask (`0x36`), stick the
   message on the end, and hash it.
3. **Outer envelope:** mix the key with a different mask (`0x5c`), stick
   the inner fingerprint on the end, and hash that.

Why not just hash `key + message`? With hashes like SHA-256, an attacker
who sees that fingerprint can tack extra text onto the message and work
out a valid fingerprint for it without knowing the key. The two envelopes
stop that trick. PyCrypt builds HMAC by hand on top of its own SHA-256.

## HMAC in PyCrypt

```python
from pycrypt.hmac import hmac_sign, hmac_verify

# Sign a message.
tag = hmac_sign("Transfer $100 to Alice", key="shared_secret")

# Verify it hasn't been tampered with.
hmac_verify("Transfer $100 to Alice", tag, key="shared_secret")
# True

hmac_verify("Transfer $999 to Eve", tag, key="shared_secret")
# False -- the message was changed!
```

## What We Test

- Same message + same key = same tag.
- Different messages = different tags.
- Verification succeeds for unmodified messages.
- Verification fails for tampered messages.
- Different keys produce different tags.
- Tags match the official answers in RFC 4231, and Python's own `hmac`
  module for any key and message.

## Next Up

HMAC proves a message wasn't changed, but both sides need the same
key. What if you want to prove who sent it to anyone, even strangers?
Head to [Digital Signatures](signatures.md).
