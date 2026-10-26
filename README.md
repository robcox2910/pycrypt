# PyCrypt

**An educational cryptography library in plain Python.** The classic
ciphers (Caesar, XOR) are built from scratch; the modern primitives
(SHA-256, HMAC, PBKDF2) wrap Python's battle-tested `hashlib`/`hmac`
standard library so you can see how the pieces fit together.

> ⚠️ **For LEARNING, not real security.** The Caesar and XOR ciphers
> and the homemade-style signatures here are easy to break. Never use
> PyCrypt to protect real passwords, messages, or secrets -- use a
> vetted library like `cryptography` for that.

## What Is Cryptography?

Imagine you want to pass a secret note to your friend in class, but you don't
want anyone else to read it. You could write it in a secret code that only you
and your friend understand. That's cryptography!

Cryptography is the science of keeping information secret and safe. It's used
every time you:

- Send a text message
- Log in to a website
- Pay for something online
- Download an app

PyCrypt teaches you how all of this works by building each piece from scratch.

## Examples

### Hashing -- One-Way Fingerprints

A hash turns any text into a fixed-size "fingerprint." You can't reverse it,
but the same input always gives the same fingerprint.

```python
from pycrypt.hashing import sha256

# Same input always gives the same hash
print(sha256("hello"))  # "2cf24dba5fb0a30e..."
print(sha256("hello"))  # "2cf24dba5fb0a30e..." (identical!)

# Even a tiny change makes a completely different hash
print(sha256("Hello"))  # "185f8db32271fe25..." (totally different!)
```

### Caesar Cipher -- The Secret Decoder Ring

Shift every letter by a number. A becomes D (shift 3), B becomes E, and so on.
It wraps around, so Z becomes C.

```python
from pycrypt.caesar import encrypt, decrypt, brute_force

secret = encrypt("HELLO WORLD", shift=3)
print(secret)  # "KHOOR ZRUOG"

original = decrypt(secret, shift=3)
print(original)  # "HELLO WORLD"

# Try all 26 possible shifts to crack it!
for shift, text in brute_force(secret):
    print(f"Shift {shift}: {text}")
```

### XOR Cipher -- Flipping Switches

XOR is its own inverse -- encrypt and decrypt use the exact same operation.
Real ciphers like AES use XOR inside, but a short repeating key like ours is
easy to break -- **for learning only**.

```python
from pycrypt.xor import xor_encrypt, xor_encrypt_bytes

encrypted = xor_encrypt("secret message", key="mykey")
print(encrypted)  # looks like random bytes

# Decrypt by XOR-ing again with the same key
decrypted = xor_encrypt_bytes(encrypted, b"mykey").decode("utf-8")
print(decrypted)  # "secret message"
```

### HMAC -- Tamper-Evident Seals

HMAC is like a wax seal on an envelope. If someone changes the message, the
seal breaks.

```python
from pycrypt.hmac import hmac_sign, hmac_verify

tag = hmac_sign("transfer $10", key="shared-secret")
print(hmac_verify("transfer $10", tag, key="shared-secret"))   # True
print(hmac_verify("transfer $1000", tag, key="shared-secret"))  # False!
```

### Digital Signatures -- A Shared Wax Seal

A digital signature proves who wrote a message and that it hasn't been
changed. Our version is like a wax seal that only you and your friend
know how to make: you both share one secret key, and that same key is
used to sign *and* to verify. (Real systems like RSA use a separate
private key to sign and a public key anyone can verify with.)

```python
import os
from pycrypt.signatures import sign, verify

# You and your friend share this one secret key.
key = os.urandom(32)

signature = sign("I wrote this!", key)
print(verify("I wrote this!", signature, key))       # True
print(verify("I didn't write this", signature, key))  # False
```

## Features

- **Hashing** -- SHA-256 and MD5 fingerprints
- **Caesar Cipher** -- Shift-based encryption with brute-force cracking
- **XOR Cipher** -- Symmetric encryption using bitwise XOR
- **Key Derivation** -- Turn passwords into strong keys with PBKDF2
- **HMAC** -- Tamper-proof message authentication codes
- **Digital Signatures** -- Sign and verify messages with a shared secret key
- **CLI Tool** -- A demo that prints hashing, Caesar, XOR, and HMAC examples
- **100% Typed** -- Full type annotations with strict Pyright checking

## Quick Start

```bash
# Install with uv
uv add pycrypt

# Or install from source
git clone https://github.com/robcox2910/pycrypt.git
cd pycrypt
uv sync --all-extras

# Run the CLI demo
uv run pycrypt

# Run the tests
uv run pytest
```

<!-- docs:start -->
## Documentation

Full docs (with kid-friendly explanations of every idea): https://robcox2910.github.io/pycrypt/
<!-- docs:end -->

## Releasing

Other projects in the series ([PyStack](https://github.com/robcox2910/pystack)) use a pinned release of this one,
not whatever is on `main`. To publish a change for them:

1. Merge the change to `main`.
2. Tag it: `git tag -a vX.Y.Z -m vX.Y.Z && git push origin vX.Y.Z`.
   A change to the public API bumps the minor version (`v0.1.0` → `v0.2.0`);
   anything else bumps the patch (`v0.1.0` → `v0.1.1`).
3. In each project that uses it, edit the tag in `[tool.uv.sources]`, run
   `uv lock --upgrade-package <name>`, and open a pull request so CI checks
   the pair together.

<!-- series:start -->
## Related Projects

This project is one of a series that builds real systems "from scratch in Python" to teach how they work. See the [series home](https://robcox2910.github.io/) for the full story.

| Project | What it teaches | Repository | Docs |
| --- | --- | --- | --- |
| PyOS | Operating systems | [py-os](https://github.com/robcox2910/py-os) | [Docs](https://robcox2910.github.io/py-os/) |
| Pebble | Compilers and programming languages | [pebble-lang](https://github.com/robcox2910/pebble-lang) | [Docs](https://robcox2910.github.io/pebble-lang/) |
| PyDB | Relational databases | [pydb](https://github.com/robcox2910/pydb) | [Docs](https://robcox2910.github.io/pydb/) |
| PyKV | Key-value stores | [pykv](https://github.com/robcox2910/pykv) | [Docs](https://robcox2910.github.io/pykv/) |
| PyDocDB | Document databases | [pydoc-db](https://github.com/robcox2910/pydoc-db) | [Docs](https://robcox2910.github.io/pydoc-db/) |
| PyGraphDB | Graph databases | [pygraphdb](https://github.com/robcox2910/pygraphdb) | [Docs](https://robcox2910.github.io/pygraphdb/) |
| PyTSDB | Time-series databases | [pytsdb](https://github.com/robcox2910/pytsdb) | [Docs](https://robcox2910.github.io/pytsdb/) |
| PyVecDB | Vector databases | [pyvecdb](https://github.com/robcox2910/pyvecdb) | [Docs](https://robcox2910.github.io/pyvecdb/) |
| PyColDB | Column-family databases | [pycoldb](https://github.com/robcox2910/pycoldb) | [Docs](https://robcox2910.github.io/pycoldb/) |
| **PyCrypt** | **Cryptography** | [pycrypt](https://github.com/robcox2910/pycrypt) | [Docs](https://robcox2910.github.io/pycrypt/) |
| PyNet | Computer networking | [pynet](https://github.com/robcox2910/pynet) | [Docs](https://robcox2910.github.io/pynet/) |
| PyWeb | HTTP web servers | [pyweb](https://github.com/robcox2910/pyweb) | [Docs](https://robcox2910.github.io/pyweb/) |
| PyGit | Version control | [pygit](https://github.com/robcox2910/pygit) | [Docs](https://robcox2910.github.io/pygit/) |
| PySearch | Search engines | [pysearch](https://github.com/robcox2910/pysearch) | [Docs](https://robcox2910.github.io/pysearch/) |
| PyMQ | Message queues | [pymq](https://github.com/robcox2910/pymq) | [Docs](https://robcox2910.github.io/pymq/) |
| PyLLM | Language models (the brain) | [pyllm](https://github.com/robcox2910/pyllm) | [Docs](https://robcox2910.github.io/pyllm/) |
| PyScheduler | Job scheduling | [pyscheduler](https://github.com/robcox2910/pyscheduler) | [Docs](https://robcox2910.github.io/pyscheduler/) |
| PyStack | Full-stack integration | [pystack](https://github.com/robcox2910/pystack) | [Docs](https://robcox2910.github.io/pystack/) |
<!-- series:end -->

## License

MIT -- see [LICENSE](LICENSE) for details.
