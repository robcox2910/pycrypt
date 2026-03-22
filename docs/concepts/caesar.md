# Caesar Cipher

## The Secret Decoder Ring

Julius Caesar sent secret messages to his generals by shifting each
letter. With a shift of 3:

```
A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓
D E F G H I J K L M N O P Q R S T U V W X Y Z A B C
```

"HELLO" becomes "KHOOR". To decrypt, shift back by 3.

This is the simplest cipher -- a **secret decoder ring** that every
kid can understand. It's also easy to break (only 26 possible shifts),
which teaches us why we need stronger methods.

## How It Works in PyCrypt

```python
from pycrypt.caesar import encrypt, decrypt

secret = encrypt("HELLO WORLD", shift=3)
# "KHOOR ZRUOG"

original = decrypt(secret, shift=3)
# "HELLO WORLD"
```

## Why It's Weak

There are only 26 possible shifts. An attacker can try all 26 in
under a second. Real encryption needs keys that are much, much longer.

## What We Test

- Encrypting shifts letters correctly.
- Decrypting reverses the shift.
- Non-letter characters (spaces, numbers) are left unchanged.
- Wrapping works (Z + 1 = A).

## Next Up

The Caesar cipher shifts letters. What if we worked with individual
**bits** instead? Head to [XOR Cipher](xor.md).
