# What Is Cryptography?

## Secret Messages and Tamper-Proof Seals

Since ancient times, people have needed to send secret messages. Roman
generals used the **Caesar cipher** -- shifting each letter by a fixed
number. "HELLO" shifted by 3 becomes "KHOOR". Only someone who knows
the shift can read it.

**Cryptography** is the science of keeping information secret and
proving it hasn't been tampered with. Every time you visit a website
with a padlock icon, send a message on WhatsApp, or pay with a credit
card, cryptography is working behind the scenes.

!!! warning "For learning, not real security"
    PyCrypt exists to teach how these ideas work. The Caesar and XOR
    ciphers and the shared-secret signatures here are easy to break --
    never use them to protect real passwords, messages, or secrets.
    For real projects, use a vetted library like `cryptography`.

## The Three Big Ideas

### 1. Hashing -- The Meat Grinder

A **hash** turns any input into a fixed-size fingerprint. You can't
reverse it (you can't un-grind meat), but the same input always gives
the same fingerprint. Useful for checking if something changed.

```
"Hello" → "185f8db32271fe25..."  (always the same)
"Hello!" → "334d016f755cd6dc..."  (completely different)
```

### 2. Encryption -- The Lockbox

**Encryption** scrambles a message so only someone with the right key
can read it. There are two flavours:

- **Symmetric** -- one key to lock and unlock (like a padlock). Fast,
  but you need to share the key somehow.
- **Asymmetric** -- a public key to lock, a private key to unlock
  (like a mailbox: anyone can drop mail in, only you can open it).

### 3. Signing -- The Wax Seal

A **digital signature** proves who wrote a message and that it wasn't
changed. Like a wax seal on a letter -- you know it's genuine and that
no one opened it. PyCrypt's version is a *shared* seal: you and your
friend both hold the same secret key, so either of you can make the
seal and check it. (Real systems use a private key to sign and a
public key anyone can verify with -- more on that later.)

## Our Building Blocks

| Concept | Analogy | What It Does |
|---------|---------|-------------|
| **Hashing** | Meat grinder | One-way fingerprints (can't reverse) |
| **Caesar Cipher** | Secret decoder ring | Shift letters to hide a message |
| **XOR Cipher** | Flip a switch | Fast bit-level encryption |
| **Key Derivation** | Recipe from simple ingredients | Turn a password into a strong key |
| **HMAC** | Tamper-evident seal | Prove a message wasn't changed |
| **Digital Signatures** | Wax seal on a letter | Prove who sent it |

## Let's Start!

Head to [Hashing](concepts/hashing.md) to learn how fingerprints
for data work.
