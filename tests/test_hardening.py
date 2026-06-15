"""Tests for hardened error handling and edge cases in PANHOUND."""
from __future__ import annotations

import io
import sys
import pytest

from panhound.core import scan_text, scan_path, scan_paths, luhn_valid
from panhound.cli import main, _validate_paths


# ---------------------------------------------------------------------------
# core.py edge cases
# ---------------------------------------------------------------------------

def test_scan_text_empty_string():
    """Empty input must return an empty list, not raise."""
    assert scan_text("") == []


def test_scan_text_only_whitespace():
    """Whitespace-only input must return an empty list."""
    assert scan_text("   \n\t  \n") == []


def test_scan_text_non_string_raises():
    """Non-string input must raise TypeError, not AttributeError/crash."""
    with pytest.raises(TypeError, match="must be a str"):
        scan_text(None)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="must be a str"):
        scan_text(12345)  # type: ignore[arg-type]


def test_scan_path_missing_file():
    """scan_path on a non-existent path must return [], not raise."""
    result = scan_path("/no/such/file/at/all.txt")
    assert result == []


def test_scan_paths_empty_list():
    """scan_paths with no paths must return [] without error."""
    assert scan_paths([]) == []


def test_luhn_valid_short_input():
    """luhn_valid must handle very short strings gracefully."""
    assert not luhn_valid("1")
    assert not luhn_valid("12")


# ---------------------------------------------------------------------------
# cli.py path validation
# ---------------------------------------------------------------------------

def test_validate_paths_missing_returns_error():
    """_validate_paths must return an error string for non-existent paths."""
    msg = _validate_paths(["/no/such/path/xyz"])
    assert msg is not None
    assert "not found" in msg


def test_validate_paths_stdin_marker_ok():
    """'-' (stdin marker) must not be treated as a missing path."""
    assert _validate_paths(["-"]) is None


def test_cli_missing_path_exits_2(capsys):
    """CLI must exit 2 and print to stderr when a path does not exist."""
    rc = main(["scan", "/definitely/does/not/exist/xyz"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "not found" in err


def test_cli_no_subcommand_exits_2(capsys):
    """CLI with no subcommand must exit 2 (usage error)."""
    rc = main([])
    assert rc == 2


def test_cli_clean_dir_returns_0(tmp_path, capsys):
    """A directory with no card data must exit 0."""
    (tmp_path / "notes.txt").write_text("This has no sensitive data at all.")
    rc = main(["scan", str(tmp_path)])
    assert rc == 0


def test_cli_leaky_text_exits_1(tmp_path, capsys):
    """A file containing a valid PAN must cause exit 1."""
    (tmp_path / "data.txt").write_text("card: 4111 1111 1111 1111")
    rc = main(["scan", "--format", "json", str(tmp_path)])
    assert rc == 1


# ---------------------------------------------------------------------------
# integrations/webhook.py
# ---------------------------------------------------------------------------

def test_webhook_bad_scheme(capsys):
    """webhook.main must reject URLs without http/https and exit 2."""
    import integrations.webhook as wh
    sys.argv = ["webhook.py", "--url", "ftp://example.com"]
    rc = wh.main()
    assert rc == 2


def test_webhook_malformed_header(capsys, monkeypatch):
    """webhook.main must reject --header values with no colon and exit 2."""
    import integrations.webhook as wh
    import argparse

    # Patch parse_args to inject our controlled args
    class _FakeArgs:
        url = "https://example.com"
        header = ["BadHeaderWithNoColon"]

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args",
                        lambda self, *a, **kw: _FakeArgs())
    rc = wh.main()
    assert rc == 2
    err = capsys.readouterr().err
    assert "Key: Value" in err or "form" in err


def test_webhook_empty_stdin_exits_2(capsys, monkeypatch):
    """webhook.main must exit 2 when stdin is empty."""
    import integrations.webhook as wh
    import argparse

    class _FakeArgs:
        url = "https://example.com"
        header = []

    monkeypatch.setattr(argparse.ArgumentParser, "parse_args",
                        lambda self, *a, **kw: _FakeArgs())
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    rc = wh.main()
    assert rc == 2
    err = capsys.readouterr().err
    assert "empty" in err
