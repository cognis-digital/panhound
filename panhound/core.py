"""Core detection engine for PANHOUND.

Detects Primary Account Numbers (PANs) and adjacent CVVs in arbitrary text.
A PAN is reported only when it (a) has a plausible length, (b) matches a known
BIN/brand prefix, and (c) passes the Luhn checksum -- this keeps false
positives (phone numbers, order IDs, timestamps) low.

Pure standard library.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, asdict
from typing import Iterable, Iterator, List, Optional

# ---------------------------------------------------------------------------
# Brand / BIN definitions: (brand, valid_length_set, compiled_prefix_regex)
# Prefix patterns operate on the *digits only* form of the candidate.
# ---------------------------------------------------------------------------
_BRAND_RULES = [
    ("visa", {13, 16, 19}, re.compile(r"^4")),
    ("mastercard", {16}, re.compile(r"^(5[1-5]|2(2[2-9]|[3-6]\d|7[01]|720))")),
    ("amex", {15}, re.compile(r"^3[47]")),
    ("discover", {16, 19}, re.compile(r"^(6011|65|64[4-9]|622)")),
    ("diners", {14, 16}, re.compile(r"^(36|30[0-5]|38|39)")),
    ("jcb", {16, 19}, re.compile(r"^35(2[89]|[3-8]\d)")),
]

# A candidate PAN: 13-19 digits, optionally grouped by single spaces or hyphens.
# We require the grouping to be consistent-ish by allowing digit runs separated
# by at most one space/hyphen, and bound the whole thing with non-digit edges.
_CANDIDATE_RE = re.compile(
    r"(?<![\d.])(\d[ -]?){12,18}\d(?![\d.])"
)

# CVV: a standalone 3-4 digit number that is *labeled* as a security code.
# We only flag labeled CVVs to avoid matching every 3-digit number on earth.
_CVV_RE = re.compile(
    r"(?i)\b(cvv2?|cvc2?|cvn|cid|security[\s_-]?code|card[\s_-]?verification)\b"
    r"\s*[:=]?\s*[\"']?(\d{3,4})[\"']?"
)

_DEFAULT_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__",
                      ".venv", "venv", ".mypy_cache", ".pytest_cache", "dist",
                      "build", ".idea", ".tox"}

_BINARY_SNIFF = 4096


@dataclass
class Finding:
    """A single leak finding."""
    kind: str            # "pan" or "cvv"
    brand: str           # card brand, or "" for cvv
    masked: str          # redacted value safe to log
    path: str            # source file path ("<text>" for in-memory scans)
    line: int            # 1-based line number
    col: int             # 1-based column
    length: int          # digit length of the matched value
    context: str         # redacted surrounding line

    def to_dict(self) -> dict:
        return asdict(self)


def luhn_valid(digits: str) -> bool:
    """Return True if ``digits`` (string of 0-9) passes the Luhn checksum."""
    if not digits or not digits.isdigit():
        return False
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = ord(ch) - 48
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def detect_brand(digits: str) -> Optional[str]:
    """Return the card brand for ``digits`` if length+prefix match a rule."""
    n = len(digits)
    for brand, lengths, prefix_re in _BRAND_RULES:
        if n in lengths and prefix_re.match(digits):
            return brand
    return None


def mask_pan(digits: str) -> str:
    """PCI-style mask: keep first 6 (BIN) and last 4, redact the middle."""
    if len(digits) <= 10:
        # short values (or CVVs): keep last digit pattern minimal
        return "*" * len(digits)
    return digits[:6] + "*" * (len(digits) - 10) + digits[-4:]


def _redact_line(line: str) -> str:
    """Redact any PAN-like and labeled-CVV substrings from a context line."""
    out = line
    for m in _CANDIDATE_RE.finditer(line):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if 13 <= len(digits) <= 19 and detect_brand(digits) and luhn_valid(digits):
            out = out.replace(raw, mask_pan(digits))
    out = _CVV_RE.sub(lambda mm: mm.group(0).replace(mm.group(2), "*" * len(mm.group(2))), out)
    return out.strip()[:200]


def scan_text(text: str, path: str = "<text>") -> List[Finding]:
    """Scan a string and return a list of :class:`Finding`."""
    findings: List[Finding] = []
    # Precompute line offsets for line/col mapping.
    line_starts = [0]
    for m in re.finditer(r"\n", text):
        line_starts.append(m.end())

    def locate(pos: int):
        # binary-ish search over line_starts
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        line_no = lo + 1
        col = pos - line_starts[lo] + 1
        line_end = text.find("\n", line_starts[lo])
        if line_end == -1:
            line_end = len(text)
        return line_no, col, text[line_starts[lo]:line_end]

    # --- PANs ---
    for m in _CANDIDATE_RE.finditer(text):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if not (13 <= len(digits) <= 19):
            continue
        brand = detect_brand(digits)
        if not brand:
            continue
        if not luhn_valid(digits):
            continue
        line_no, col, line_text = locate(m.start())
        findings.append(Finding(
            kind="pan",
            brand=brand,
            masked=mask_pan(digits),
            path=path,
            line=line_no,
            col=col,
            length=len(digits),
            context=_redact_line(line_text),
        ))

    # --- labeled CVVs ---
    for m in _CVV_RE.finditer(text):
        code = m.group(2)
        line_no, col, line_text = locate(m.start())
        findings.append(Finding(
            kind="cvv",
            brand="",
            masked="*" * len(code),
            path=path,
            line=line_no,
            col=col,
            length=len(code),
            context=_redact_line(line_text),
        ))

    return findings


def _looks_binary(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(_BINARY_SNIFF)
    except OSError:
        return True
    return b"\x00" in chunk


def scan_path(path: str) -> List[Finding]:
    """Scan a single file path. Returns [] for unreadable/binary files."""
    if _looks_binary(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    return scan_text(text, path=path)


def _iter_files(root: str, skip_dirs: Iterable[str]) -> Iterator[str]:
    skip = set(skip_dirs)
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            yield os.path.join(dirpath, name)


def scan_paths(paths: Iterable[str],
               skip_dirs: Optional[Iterable[str]] = None) -> List[Finding]:
    """Walk and scan multiple files/directories."""
    skip = _DEFAULT_SKIP_DIRS if skip_dirs is None else set(skip_dirs)
    results: List[Finding] = []
    for p in paths:
        for fpath in _iter_files(p, skip):
            results.extend(scan_path(fpath))
    return results


def findings_to_dicts(findings: Iterable[Finding]) -> List[dict]:
    """Convert findings to plain dicts (for JSON serialization)."""
    return [f.to_dict() for f in findings]
