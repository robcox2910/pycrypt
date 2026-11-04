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
It's what Bitcoin, TLS, and most of the internet uses. PyCrypt writes it
out by hand in `pycrypt/hashing.py`, so you can read every step.

```python
from pycrypt.hashing import sha256

sha256("Hello, world!")
# "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
```

## How SHA-256 Works Inside

Think of SHA-256 as a cake mixer with eight bowls of numbers in it.

1. **Pad the message.** Add a `1` bit, then zeros, then the message's
   length, until it fills whole 64-byte blocks. Even an empty message
   becomes one full block.
2. **Fill the bowls.** Start with eight fixed numbers. They come from the
   square roots of the first eight prime numbers, so everyone can check
   nobody hid a trick in them.
3. **Mix in each block.** Stretch the block into 64 words, then do 64
   rounds. Each round rotates the numbers (bits that fall off one end
   come back on the other), adds in one word and one constant, and lets
   the bits "vote" and "choose" between each other. Then everything
   shuffles along one bowl.
4. **Read the bowls.** After the last block, the eight numbers written
   side by side are the fingerprint.

All that rotating and mixing is what makes the **avalanche**: change one
letter and about half the bits of the answer flip.

PyCrypt also has **MD5**, an older and smaller hash built the same way
with four bowls and a different mixing recipe. MD5 is broken for security
(people can make two files with the same fingerprint), but it's a nice one
to read first.

```python
from pycrypt.hashing import md5, sha256_digest

md5("hello")
# "5d41402abc4b2a76b9719d911017c592"
sha256_digest(b"abc").hex()
# "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
```

## What We Test

- Same input always produces the same hash.
- Different inputs produce different hashes.
- The hash is exactly 64 hex characters.
- Even a one-character change produces a completely different hash.
- SHA-256 and MD5 give the official answers from their standards (NIST
  and RFC 1321), and match Python's own `hashlib` for any input at all.

## Next Up

Now that we can fingerprint data, let's learn to hide messages.
Head to [Caesar Cipher](caesar.md).
