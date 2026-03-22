# Key Derivation

## From Simple Ingredients to a Gourmet Key

Your password is "pizza123". That's only 8 characters -- way too
short and predictable for a real encryption key. **Key derivation**
takes your simple password and mixes it with salt (random data) and
many rounds of hashing to produce a long, strong key.

Think of it like cooking: you start with simple ingredients (flour,
eggs, sugar) and through a complex recipe, you get a cake. You can't
easily reverse a cake back into flour.

## Why Not Just Use the Password?

1. **Too short** -- passwords are usually 8-20 characters; keys need
   to be 32+ bytes.
2. **Too predictable** -- people use common words; keys should look
   random.
3. **No salt** -- without salt, the same password always produces the
   same key, making rainbow table attacks easy.

## Salt: The Secret Ingredient

A **salt** is random data mixed in before hashing. Even if two users
have the same password, their salts are different, so their keys are
different.

```
password + salt1 → key_A
password + salt2 → key_B  (different key, same password!)
```

## How It Works in PyCrypt

```python
from pycrypt.kdf import derive_key

# Derive a 32-byte key from a password.
key, salt = derive_key("pizza123")

# Later, derive the same key using the stored salt.
same_key, _ = derive_key("pizza123", salt=salt)
assert key == same_key
```

## What We Test

- Same password + same salt = same key.
- Same password + different salt = different key.
- The derived key is the requested length.
- More rounds produce a different key.

## Next Up

We have a strong key. Now let's use it to prove a message hasn't
been tampered with. Head to [HMAC](hmac.md).
