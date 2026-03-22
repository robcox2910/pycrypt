# PyCrypt

**An educational cryptography library built from scratch in Python.**

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
This is the foundation of modern encryption.

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

### Digital Signatures -- Proving Who Wrote It

A digital signature proves who wrote a message and that it hasn't been
changed. The signer uses their private key; anyone can verify with the
public key.

```python
from pycrypt.signatures import generate_keypair, sign, verify

private_key, public_key = generate_keypair()

signature = sign("I wrote this!", private_key)
print(verify("I wrote this!", signature, public_key))   # True
print(verify("I didn't write this", signature, public_key))  # False
```

## Features

- **Hashing** -- SHA-256 and MD5 fingerprints
- **Caesar Cipher** -- Shift-based encryption with brute-force cracking
- **XOR Cipher** -- Symmetric encryption using bitwise XOR
- **Key Derivation** -- Turn passwords into strong keys with PBKDF2
- **HMAC** -- Tamper-proof message authentication codes
- **Digital Signatures** -- Sign and verify messages with key pairs
- **CLI Tool** -- Interactive demos of every concept
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

## Documentation

Full documentation with kid-friendly explanations of every concept:
[https://robcox2910.github.io/pycrypt/](https://robcox2910.github.io/pycrypt/)

## Related Projects

PyCrypt is part of a series of educational "build it from scratch" projects:

| Project | What It Teaches |
|---------|----------------|
| [PyOS](https://github.com/robcox2910/py-os) | Operating systems |
| [Pebble](https://github.com/robcox2910/pebble-lang) | Compilers and programming languages |
| [PyDB](https://github.com/robcox2910/pydb) | Relational databases |
| [PyStack](https://github.com/robcox2910/pystack) | Full-stack integration |
| [PyWeb](https://github.com/robcox2910/pyweb) | HTTP web servers |
| [PyGit](https://github.com/robcox2910/pygit) | Version control |
| [PyNet](https://github.com/robcox2910/pynet) | Networking |
| [PySearch](https://github.com/robcox2910/pysearch) | Full-text search |
| [PyMQ](https://github.com/robcox2910/pymq) | Message queues |

## License

MIT -- see [LICENSE](LICENSE) for details.
