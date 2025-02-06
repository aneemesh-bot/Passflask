# tests/test_leaks.py

import pytest
from pathlib import Path
from services.leaks import check_leaks

def test_check_leaks_positive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that check_leaks returns True for a password that exists in the leaked file.
    """
    leaked_file: Path = tmp_path / "leaked_passwords.txt"
    leaked_file.write_text("leakedPass\nanotherLeakedPass")
    monkeypatch.setattr("builtins.open", lambda filename, mode: open(leaked_file, mode))
    assert check_leaks("leakedPass") is True

def test_check_leaks_negative(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Verify that check_leaks returns False for a password not present in the leaked file.
    """
    leaked_file: Path = tmp_path / "leaked_passwords.txt"
    leaked_file.write_text("leakedPass\nanotherLeakedPass")
    monkeypatch.setattr("builtins.open", lambda filename, mode: open(leaked_file, mode))
    assert check_leaks("safePassword") is False
