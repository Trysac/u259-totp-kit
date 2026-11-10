"""Behavior tests for the public API of totp_kit."""

from __future__ import annotations

import pytest

import totp_kit


def test_normalize_trims_and_lowercases() -> None:
    assert totp_kit.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        totp_kit.normalize(value)


def test_version_is_semver() -> None:
    parts = totp_kit.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
