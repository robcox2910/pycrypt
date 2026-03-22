# Hashing

## The Meat Grinder

Put a steak into a meat grinder and you get mince. You can't put the
mince back into a steak -- the process is **one-way**. But if you put
the same steak in twice, you get the same mince both times.

A **hash function** works the same way for data:

- **One-way** -- you can't reverse a hash to get the original
- **Deterministic** -- same input always gives the same hash
- **Avalanche** -- a tiny change in input completely changes the hash

## What's It Used For?

| Use Case | How Hashing Helps |
|----------|------------------|
| **Passwords** | Store the hash, not the password. Check by hashing what the user types. |
| **File integrity** | Hash a downloaded file and compare to the expected hash. |
| **Git** | Every commit, file, and tree is identified by its hash. |
| **Digital signatures** | Sign the hash of a message (much faster than signing the whole thing). |

## SHA-256: The Industry Standard

We use **SHA-256**, which produces a 64-character hex string (256 bits).
It's what Bitcoin, TLS, and most of the internet uses.

```python
from pycrypt.hashing import sha256

sha256("Hello, world!")
# "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
```

## What We Test

- Same input always produces the same hash.
- Different inputs produce different hashes.
- The hash is exactly 64 hex characters.
- Even a one-character change produces a completely different hash.

## Next Up

Now that we can fingerprint data, let's learn to hide messages.
Head to [Caesar Cipher](caesar.md).
