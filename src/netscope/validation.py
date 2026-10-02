"""Shared input-validation helpers for NetScope diagnostics."""

from __future__ import annotations


def has_control_characters(value: str) -> bool:
    """Reject control characters that can corrupt reports or tool arguments."""
    return any(ord(character) < 32 or ord(character) == 127 for character in value)
