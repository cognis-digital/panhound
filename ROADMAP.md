# PANHOUND — Roadmap

## Now (v0.1.x)
- Stable `scan` CLI (table / JSON), CI fail-gate, MCP server, demo scenarios.

## Next (v0.2)
- Expand the rule/heuristic set and connectors.
- Niche focus: PCI-DSS Req 3 has no good open-source 'cardholder data leak' scanner; Luhn + BIN-range validation kills the false-positive problem that makes secret scanners noisy for card data. CI gate + MCP makes it a one-line PR check..

## Later (v1.0)
- PyPI release, plugin API, Pro tier + commercial support (licensing@cognis.digital).

Open an issue or PR to shape priorities — see [CONTRIBUTING.md](CONTRIBUTING.md).
