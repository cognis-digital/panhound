#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import sys
import urllib.request


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--header", action="append", default=[],
                    help="Extra header in 'Key: Value' form")
    args = ap.parse_args()

    # Validate the URL has a supported scheme before making a network call.
    if not args.url.startswith(("http://", "https://")):
        print("webhook: error: --url must start with http:// or https://",
              file=sys.stderr)
        return 2

    # Validate and parse extra headers before touching the network.
    parsed_headers: list[tuple[str, str]] = []
    for h in args.header:
        if ":" not in h:
            print(
                "webhook: error: --header {!r} is not in 'Key: Value' form".format(h),
                file=sys.stderr,
            )
            return 2
        k, _, v = h.partition(":")
        k, v = k.strip(), v.strip()
        if not k:
            print(
                "webhook: error: --header {!r} has an empty key".format(h),
                file=sys.stderr,
            )
            return 2
        parsed_headers.append((k, v))

    payload = sys.stdin.read().encode("utf-8")
    if not payload:
        print("webhook: error: stdin is empty — nothing to POST", file=sys.stderr)
        return 2

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in parsed_headers:
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
