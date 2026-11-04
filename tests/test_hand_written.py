"""Check PyCrypt really does its own hashing.

The point of PyCrypt is that you can read how each algorithm works, so the
library code must not quietly hand the job to Python's ``hashlib`` or to
``hmac.new``/``hmac.digest``. (The tests still use them, as an answer key.)
"""

from pathlib import Path

SOURCE = Path(__file__).parent.parent / "src" / "pycrypt"
SHORTCUTS = ("import hashlib", "from hashlib", "hmac.new(", "hmac.digest(", "pbkdf2_hmac(")


class TestNoShortcuts:
    """Make sure no library module borrows the real algorithms."""

    def test_source_does_not_call_the_standard_library_hashes(self) -> None:
        """Verify no file under src/pycrypt uses hashlib or hmac's hashing functions."""
        offenders = [
            f"{path.name}: {shortcut}"
            for path in sorted(SOURCE.glob("*.py"))
            for shortcut in SHORTCUTS
            if shortcut in path.read_text(encoding="utf-8")
        ]
        assert offenders == []
