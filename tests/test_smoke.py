"""Smoke tests for PANHOUND. No network access."""
import json
import os
import subprocess
import sys

import pytest

from panhound import (
    TOOL_NAME,
    TOOL_VERSION,
    luhn_valid,
    detect_brand,
    mask_pan,
    scan_text,
    scan_path,
)
from panhound.cli import main

DEMO_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                        "demos", "01-basic")
DEMO_FILE = os.path.join(DEMO_DIR, "checkout_fixture.json")


def test_metadata():
    assert TOOL_NAME == "panhound"
    assert TOOL_VERSION.count(".") == 2


def test_luhn():
    assert luhn_valid("4111111111111111")      # visa test number
    assert luhn_valid("5500000000000004")      # mastercard test number
    assert luhn_valid("378282246310005")       # amex test number
    assert not luhn_valid("1234567812345670")   # fails checksum
    assert not luhn_valid("")
    assert not luhn_valid("abc")


def test_detect_brand():
    assert detect_brand("4111111111111111") == "visa"
    assert detect_brand("5500000000000004") == "mastercard"
    assert detect_brand("378282246310005") == "amex"
    assert detect_brand("123") is None


def test_mask_keeps_bin_and_last4():
    masked = mask_pan("4111111111111111")
    assert masked.startswith("411111")
    assert masked.endswith("1111")
    assert "*" in masked
    # the raw middle must not survive
    assert "4111111111111111" != masked


def test_scan_text_basic():
    findings = scan_text("pay with 4111 1111 1111 1111 cvv: 123")
    kinds = sorted(f.kind for f in findings)
    assert "pan" in kinds
    assert "cvv" in kinds
    pan = next(f for f in findings if f.kind == "pan")
    assert pan.brand == "visa"
    # context is redacted - no raw PAN leaks into output
    assert "4111111111111111" not in pan.context


def test_decoys_not_flagged():
    # phone number, order id, luhn-invalid 16-digit -> no findings
    text = ("phone +1 555 0100 2034 order ORD-20240131-998877 "
            "bogus 1234567812345670 ts 2024-01-31T14:55:02Z")
    findings = scan_text(text)
    assert findings == []


def test_scan_demo_file():
    findings = scan_path(DEMO_FILE)
    pans = [f for f in findings if f.kind == "pan"]
    cvvs = [f for f in findings if f.kind == "cvv"]
    brands = sorted(f.brand for f in pans)
    assert brands == ["amex", "mastercard", "visa"]
    assert len(cvvs) == 1
    # nothing in the demo's decoy block should be flagged
    assert all("1234567812345670" not in f.context for f in findings)


def test_cli_exit_code_and_json(capsys):
    rc = main(["scan", "--format", "json", DEMO_DIR])
    assert rc == 1  # leaks found -> CI gate fails
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["tool"] == "panhound"
    assert payload["summary"]["total"] == 4
    assert payload["summary"]["pan"] == 3
    assert payload["summary"]["cvv"] == 1
    # masked values only - no raw PAN in serialized output
    assert "4111111111111111" not in out


def test_cli_clean_exit_zero(tmp_path, capsys):
    clean = tmp_path / "clean.txt"
    clean.write_text("nothing sensitive here, just code and prose.")
    rc = main(["scan", str(clean)])
    assert rc == 0
    assert "clean" in capsys.readouterr().out.lower()


def test_no_pan_filter(capsys):
    rc = main(["scan", "--no-pan", "--format", "json", DEMO_DIR])
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["pan"] == 0
    assert payload["summary"]["cvv"] == 1
    assert rc == 1


def test_module_entrypoint_version():
    root = os.path.dirname(os.path.dirname(__file__))
    res = subprocess.run(
        [sys.executable, "-m", "panhound", "--version"],
        capture_output=True, text=True, cwd=root,
    )
    assert res.returncode == 0
    assert TOOL_VERSION in res.stdout
