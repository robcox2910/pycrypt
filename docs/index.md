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

## The Three Big Ideas

### 1. Hashing -- The Meat Grinder

A **hash** turns any input into a fixed-size fingerprint. You can't
reverse it (you can't un-grind meat), but the same input always gives
the same fingerprint. Useful for checking if something changed.

```
"Hello" → "2cf24dba5fb0a30e..."  (always the same)
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
changed. Like a wax seal on a letter -- you can see it's from the
king, and you know no one opened it.

## Our Building Blocks

| Concept | Analogy | What It Does |
|---------|---------|-------------|
| **Hashing** | Meat grinder | One-way fingerprints (can't reverse) |
| **Caesar Cipher** | Secret decoder ring | Shift letters to hide a message |
| **XOR Cipher** | Flip a switch | Fast bit-level encryption |
| **Symmetric Encryption** | Padlock with one key | Same key to lock and unlock |
| **Key Derivation** | Recipe from simple ingredients | Turn a password into a strong key |
| **HMAC** | Tamper-evident seal | Prove a message wasn't changed |
| **Asymmetric Encryption** | Mailbox (public slot, private door) | Different keys to lock and unlock |
| **Digital Signatures** | Wax seal on a letter | Prove who sent it |

## Let's Start!

Head to [Hashing](concepts/hashing.md) to learn how fingerprints
for data work.
