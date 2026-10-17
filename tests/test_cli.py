"""Tests for the ``pycrypt`` demo command."""

import pytest

from pycrypt.cli import main


def test_xor_demo_really_decrypts(capsys: pytest.CaptureFixture[str]) -> None:
    """Regression: the "decrypt" step encrypted the plaintext again instead."""
    main()
    out = capsys.readouterr().out
    xor_section = out.split("3. XOR CIPHER", 1)[1].split("4. HMAC", 1)[0]
    assert "Decrypted:  secret" in xor_section
