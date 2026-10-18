# Property Testing (Every Key Opens Its Own Lock)

## The Robot Locksmith

Imagine you've built a new kind of lock. How do you check it works?

The usual way: cut one key, lock the box, unlock it, and smile. That's
an **example test**. It's useful, but it only tells you about the one key
you thought of.

Now imagine a robot locksmith. It cuts thousands of keys -- short ones,
long ones, bent ones, weird ones you'd never think of -- and for each one
it checks a single rule:

> Whatever key locks the box must also unlock it.

That rule is a **property**. It doesn't say what any one key looks like.
It says something that must be true for *every* key.

When the robot finds a key that breaks the rule, it doesn't just hand
you a huge, odd-shaped key and walk off. It keeps filing the key down,
bit by bit, checking it still fails each time, until it's as simple as
it can be. That filing-down is called **shrinking**, and it's the best
part: the smallest failing input usually points straight at the bug.

In Python, the robot locksmith is a library called
[Hypothesis](https://hypothesis.readthedocs.io/). PyCrypt's property
tests live in `tests/test_properties.py`, next to the ordinary example
tests.

## A Property from PyCrypt

Every cipher in PyCrypt has a lock and a key: you encrypt with a key and
decrypt with the same key. So every cipher should pass the robot's rule.
Here's the property for the [Caesar cipher](concepts/caesar.md):

```python
def any_text() -> st.SearchStrategy[str]:
    """Make any text at all: empty, emoji, accents, spaces, Chinese, the lot."""
    return st.text()


def any_shift() -> st.SearchStrategy[int]:
    """Make any whole number to shift by: zero, negative, or far above 26."""
    return st.integers()


@given(text=any_text(), shift=any_shift())
def test_caesar_round_trip(text: str, shift: int) -> None:
    """Decrypting with the same shift gives back exactly the text you encrypted."""
    assert decrypt(encrypt(text, shift), shift) == text
```

Line by line:

- **`any_text()` and `any_shift()`** are **strategies**: recipes for
  making random inputs. `st.text()` makes any string at all, and
  `st.integers()` makes any whole number, including 0, -7 and
  4,000,000. Each one is a named function so the test reads like a
  sentence.
- **`@given(text=any_text(), shift=any_shift())`** tells Hypothesis to
  run the test many times (100 in a normal run), each time with a fresh
  `text` and `shift` from those recipes.
- **The docstring** says the rule in plain English. If you can't say the
  rule in one sentence, it probably isn't a good property yet.
- **The `assert`** is the rule itself: lock it, unlock it, and you must
  get back exactly what you started with. This kind of property is
  called a **round-trip**.

Notice what the test *doesn't* say. It never says "HELLO with shift 3
should be KHOOR". It doesn't need to know any answers. It only needs a
rule that's always true.

There's a catch, though. A "cipher" that does nothing at all -- hand back
the message unchanged -- passes every round-trip, because doing nothing
twice still gives you what you started with. **A round-trip alone is
passed by doing nothing**, so each cipher also gets a property that says
it really scrambles something.

PyCrypt has eight more properties, using the same ideas:

| Rule | Test |
|---|---|
| XOR-ing any bytes twice with the same key gives them back | `test_xor_bytes_round_trip` |
| With no zero bytes in the key, XOR changes every byte of the message | `test_xor_changes_every_byte` |
| XOR decrypts any text back to exactly what you encrypted | `test_xor_text_round_trip` |
| Caesar only changes A-Z and a-z, keeps their case, and leaves everything else alone | `test_caesar_leaves_everything_else_alone` |
| Unless the shift is a whole number of laps (0, 26, 52...), Caesar changes every A-Z and a-z letter | `test_caesar_moves_every_english_letter` |
| Our HMAC tag is the same one Python's own `hmac` module makes | `test_hmac_tag_matches_standard_library` |
| A message always passes the check with its own tag | `test_hmac_accepts_its_own_tag` |
| Sneak anything into a signed message, anywhere, and the check fails | `test_hmac_rejects_tampered_message` |

The HMAC one is a **reference check**: instead of a rule, we compare
against something we already trust (the standard library) that was
written a completely different way. If we copied our own code to make
the "right answer", the test could never catch anything.

## Try It Yourself

Let's break the Caesar cipher on purpose and watch the robot find it.

Open `src/pycrypt/caesar.py` and change one line, as if you'd miscounted
the alphabet:

```python
ALPHABET_SIZE = 25  # was 26
```

Run the property tests:

```bash
uv run pytest tests/test_properties.py --no-cov
```

Hypothesis reports this (trimmed to the interesting part):

```
text = 'Z', shift = 0

    @given(text=any_text(), shift=any_shift())
    def test_caesar_round_trip(text: str, shift: int) -> None:
        """Decrypting with the same shift gives back exactly the text you encrypted."""
>       assert decrypt(encrypt(text, shift), shift) == text
E       AssertionError: assert 'A' == 'Z'
E
E         - Z
E         + A
E       Failing test case: test_caesar_round_trip(
E           text='Z',
E           shift=0,  # or any other generated value
E       )
```

Look at how small that is. Hypothesis tried lots of long, messy strings
and big shifts, then shrank the failure all the way down to **one letter
and a shift of zero**. Shifting `Z` by nothing should obviously give `Z`
back, and it gave `A`. With only 25 letters, `Z` has fallen off the end
of the alphabet and wrapped round to the start.

The note `# or any other generated value` means the shift doesn't matter:
every shift fails for `Z`. So the bug is about the letter, not the shift.

It's the round-trip that catches `Z` turning into `A`.
`test_caesar_leaves_everything_else_alone` stays green, because a capital
letter turning into another capital letter is allowed by its rule. (One
more property fails, for a different reason: with a 25-letter alphabet,
a shift of -25 is a whole lap, so `test_caesar_moves_every_english_letter`
finds that `A` stays `A`.) Each property guards a different rule, which
is why we keep all of them.

The example tests also catch this bug: four of them fail. So the property
isn't the only alarm here. What it added is the smallest input, one letter
and a shift of zero, instead of four failures to read through.

Now put the line back to `ALPHABET_SIZE = 26` and run the tests again.
They pass.

!!! tip "Older Hypothesis versions"
    Older versions of Hypothesis print `Falsifying example:` instead of
    `Failing test case:`. It means the same thing.

## A Bug We Found

When we first wrote `test_caesar_round_trip`, it failed on PyCrypt's
real code -- no deliberate bug needed:

```
E       AssertionError: assert 'X' == 'À'
E
E         - À
E         + X
E       Failing test case: test_caesar_round_trip(
E           text='À',
E           shift=0,  # or any other generated value
E       )
```

Encrypt `À` with a shift of **zero**, decrypt it, and you get `X`. The
message was quietly destroyed.

Here's why. The old code decided whether a character was a letter by
asking Python `char.isupper()`. That's true for `A` to `Z`... but it's
also true for `À`, `É`, `Σ` and thousands of other capital letters from
other alphabets. The code then did its A-to-Z arithmetic on `À`, which
isn't in A-to-Z at all, and landed on some unrelated English letter. No shift
could ever bring it back.

The example tests all used messages like `"HELLO WORLD"`. Nobody thought
to try `"Café"`. The robot didn't need to think of it: `st.text()` makes
accented letters all the time.

The fix was to move only the 26 English letters:

```python
if "A" <= char <= "Z":      # was: if char.isupper():
    ...
elif "a" <= char <= "z":    # was: elif char.islower():
    ...
```

Now `À` is treated like a space or a digit: left exactly as it is. The
shrunk input also became two ordinary example tests in
`tests/test_caesar.py`, so this bug can never sneak back in, even if
someone deletes the property.

## Run It Yourself

Run just the property tests (100 examples each, the same every time):

```bash
uv run pytest tests/test_properties.py --no-cov
```

The `--no-cov` turns off the coverage check, which expects the *whole*
test suite to run and would fail on one file.

Run them the long way (2,000 random examples each, different every run)
to hunt for rarer bugs. It takes about 30 seconds:

```bash
uv run pytest tests/test_properties.py --no-cov --hypothesis-profile=thorough
```

The normal run uses a fixed seed, so it tries the same inputs every time
and a passing build means the same thing on every computer. The thorough
run is random, so each time you run it the robot cuts brand-new keys.
Both settings live in `conftest.py` at the top of the project.

## Your Turn

Can you write your own property? A good place to start is
[Hashing](concepts/hashing.md): "whatever text you hash, the SHA-256
fingerprint is always 64 characters long". What's the strategy? What's
the `assert`? Can you break `sha256` on purpose and see what Hypothesis
shrinks it to?
