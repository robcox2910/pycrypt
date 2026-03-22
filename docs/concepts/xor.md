# XOR Cipher

## Flipping Switches

XOR is a simple operation: compare two bits. If they're different,
the result is 1. If they're the same, the result is 0.

```
0 XOR 0 = 0  (same → 0)
0 XOR 1 = 1  (different → 1)
1 XOR 0 = 1  (different → 1)
1 XOR 1 = 0  (same → 0)
```

The magic trick: XOR is its own inverse! If you XOR something twice
with the same key, you get back the original:

```
message XOR key = ciphertext
ciphertext XOR key = message  (back to the original!)
```

It's like flipping a light switch: flip once to turn it on (encrypt),
flip again to turn it off (decrypt).

## How It Works in PyCrypt

```python
from pycrypt.xor import xor_encrypt

# Encrypt
ciphertext = xor_encrypt("Hello!", key="secret")
# To decrypt, XOR the bytes again:
from pycrypt.xor import xor_encrypt_bytes
plaintext_bytes = xor_encrypt_bytes(ciphertext, b"secret")
plaintext = plaintext_bytes.decode("utf-8")  # "Hello!"
```

## Why XOR Matters

XOR is the foundation of almost all modern encryption. AES, ChaCha20,
and other real ciphers use XOR at their core. The difference is in how
they generate the key stream.

## What We Test

- Encrypting then decrypting returns the original.
- Different keys produce different ciphertexts.
- The key repeats if shorter than the message.

## Next Up

XOR with a short key that repeats is still weak. We need a way to
turn a password into a long, strong key. Head to
[Key Derivation](key-derivation.md).
