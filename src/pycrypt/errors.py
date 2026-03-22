"""Custom exceptions for PyCrypt.

Clear error messages help you understand what went wrong -- especially
important when dealing with secret messages!
"""


class PyCryptError(Exception):
    """Base exception for all PyCrypt errors."""


class VerificationError(PyCryptError):
    """Raise when a signature or HMAC verification fails."""
