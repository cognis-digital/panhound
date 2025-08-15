"""Command-line interface for PANHOUND.

Examples
--------
  # Scan a directory, human-readable table (exit 1 if anything found):
  panhound scan ./src ./logs

  # Emit JSON for a CI gate / piping into jq:
  panhound scan --format json . | jq '.findings[].brand'

  # Scan stdin (e.g. a log stream):
  cat app.log | panhound scan -

  # Only fail CI on Luhn-valid PANs, ignore labeled CVVs:
  panhound scan --no-cvv ./fixtures
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from panhound import TOOL_NAME, TOOL_VERSION
from panhound.core import Finding, scan_paths, scan_text, findings_to_dicts


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="PANHOUND - scan code, logs and fixtures for leaked "
                    "PANs (Luhn+BIN validated) and CVVs. A PCI cardholder-"
                    "data leak scanner for use as a CI gate.",
        epilog="Exit code is 0 when clean, 1 when leaks are found, 2 on usage "
               "error -- so it drops straight into a CI pipeline.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version",
                   version="%(prog)s " + TOOL_VERSION)
    sub = p.add_subparsers(dest="command", metavar="command")

    scan = sub.add_parser(
        "scan",
        help="scan files/dirs (or '-' for stdin) for leaked card data",
        description="Recursively scan the given paths for leaked cardholder "
                    "data. Use '-' to read from stdin.",
    )
    scan.add_argument("paths", nargs="+",
                      help="files or directories to scan; '-' reads stdin")
    scan.add_argument("--format", choices=("table", "json"), default="table",
                      help="output format (default: table)")
    scan.add_argument("--no-pan", action="store_true",
                      help="do not report PAN findings")
    scan.add_argument("--no-cvv", action="store_true",
                      help="do not report labeled-CVV findings")
    scan.add_argument("--quiet", "-q", action="store_true",
                      help="suppress the table; still sets the exit code")
    return p


def _filter(findings: List[Finding], no_pan: bool, no_cvv: bool) -> List[Finding]:
    out = []
    for f in findings:
        if f.kind == "pan" and no_pan:
            continue
        if f.kind == "cvv" and no_cvv:
            continue
        out.append(f)
    return out


def _render_table(findings: List[Finding]) -> str:
    if not findings:
        return "PANHOUND: clean - no cardholder data detected."
    rows = [("KIND", "BRAND", "MASKED", "LOCATION", "CONTEXT")]
    for f in findings:
        loc = "{}:{}:{}".format(f.path, f.line, f.col)
        rows.append((f.kind.upper(), f.brand or "-", f.masked, loc,
                     f.context[:60]))
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = []
    for idx, r in enumerate(rows):
        line = "  ".join(c.ljust(widths[i]) for i, c in enumerate(r))
        lines.append(line.rstrip())
        if idx == 0:
            lines.append("  ".join("-" * widths[i] for i in range(len(widths))))
    pans = sum(1 for f in findings if f.kind == "pan")
    cvvs = sum(1 for f in findings if f.kind == "cvv")
    lines.append("")
    lines.append("PANHOUND: {} finding(s) -- {} PAN, {} CVV.".format(
        len(findings), pans, cvvs))
    return "\n".join(lines)


def _render_json(findings: List[Finding]) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "summary": {
            "total": len(findings),
            "pan": sum(1 for f in findings if f.kind == "pan"),
            "cvv": sum(1 for f in findings if f.kind == "cvv"),
        },
        "findings": findings_to_dicts(findings),
    }
    return json.dumps(payload, indent=2)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    findings: List[Finding] = []
    if args.paths == ["-"] or "-" in args.paths:
        text = sys.stdin.read()
        findings.extend(scan_text(text, path="<stdin>"))
        real_paths = [p for p in args.paths if p != "-"]
        if real_paths:
            findings.extend(scan_paths(real_paths))
    else:
        findings.extend(scan_paths(args.paths))

    findings = _filter(findings, args.no_pan, args.no_cvv)
    findings.sort(key=lambda f: (f.path, f.line, f.col))

    if args.format == "json":
        print(_render_json(findings))
    elif not args.quiet:
        print(_render_table(findings))

    return 1 if findings else 0
