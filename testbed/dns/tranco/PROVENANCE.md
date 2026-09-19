# Tranco snapshot provenance

This directory vendors a fixed snapshot of the Tranco top-sites list so the DNS-hierarchy
zones are reconstructible bit-for-bit offline (CLAUDE.md §2: reproducible constructions).

| Field | Value |
|---|---|
| File | `tranco_JZNVY_top100k.csv` |
| List ID | `JZNVY` (permanent) |
| List page | https://tranco-list.eu/list/JZNVY |
| Download URL | https://tranco-list.eu/download/JZNVY/100000 |
| Rows | 100000 (top 100k, trimmed from the full 1M list) |
| Format | `rank,domain` (no header) |
| Downloaded (UTC) | 2026-09-19 |
| SHA-256 | `a8678f2e626ab61a04c6bbdcf678d70f530f53517d026998db9dc040fd43d7e3` |

TLD distribution in this snapshot (top 100k): `.com` 45507, `.net` 6302, `.org` 4500,
`.ru` 3596, `.de` 2076, … — ample `.com`/`.org` for the default 1000-domain hierarchy
(500 each) and up to ~9000 domains before `.org` runs short (then the generator fills the
shortfall from `.com`, logged in `MANIFEST.json`).

## Citing Tranco

Le Pochat, Van Goethem, Tajalizadehkhoob, Korczyński, Joosen. *Tranco: A Research-Oriented
Top Sites Ranking Hardened Against Manipulation.* NDSS 2019.
Permanent lists are archival and citable via their list ID / DOI at https://tranco-list.eu.

## Regenerating the snapshot (not on the default path)

`generate_zones.py --fetch-list <ID>` will re-download a pinned list ID over the network.
The default run reads only the vendored CSV above — no network required.
