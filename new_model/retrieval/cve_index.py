"""Live-CVE correlation layer (the "known/existing vulnerability" half).

Builds a local, queryable index from the ICS Advisory Project CSV
(github.com/icsadvprj/ICS-Advisory-Project) so component/vendor/product lookups
stay current WITHOUT retraining the model. Keeping CVE knowledge in retrieval —
not in weights — is the design that stops "existing vulnerabilities" going stale.

Index is plain JSON: vendor/product -> list of advisories (CVE, CWE, CVSS).
Lookup is exact + substring on normalized vendor/product strings. Swap in a
vector store later for fuzzy component matching; the interface stays the same.

Usage:
  python cve_index.py build --csv ICS-CERT_ADV.csv --out index.json
  python cve_index.py lookup --index index.json --product "OpenPLC"
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import defaultdict
from typing import Dict, List

# Tolerant column resolution — the ICS Advisory CSV headers vary by release.
COLS = {
    "vendor": ["Vendor", "vendor"],
    "product": ["Product", "product"],
    "cve": ["CVE", "CVE Number", "cve"],
    "cwe": ["CWE", "CWE Number", "cwe"],
    "cvss": ["CVSS", "CVSS v3", "CVSS_Score", "cvss"],
    "advisory": ["ICS Advisory", "Advisory", "Advisory ID", "title"],
}


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def _pick(row: dict, names: List[str]) -> str:
    for n in names:
        if n in row and row[n]:
            return row[n]
    return ""


def build(csv_path: str, out_path: str) -> dict:
    index: Dict[str, List[dict]] = defaultdict(list)
    n = 0
    with open(csv_path, newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            vendor = _pick(row, COLS["vendor"])
            product = _pick(row, COLS["product"])
            adv = {
                "vendor": vendor,
                "product": product,
                "cve": _pick(row, COLS["cve"]),
                "cwe": _pick(row, COLS["cwe"]),
                "cvss": _pick(row, COLS["cvss"]),
                "advisory": _pick(row, COLS["advisory"]),
            }
            for key in {_norm(vendor), _norm(product), _norm(f"{vendor} {product}")}:
                if key:
                    index[key].append(adv)
            n += 1
    payload = {"_count_rows": n, "index": index}
    with open(out_path, "w") as fh:
        json.dump(payload, fh)
    print(f"indexed {n} advisory rows into {len(index)} component keys -> {out_path}")
    return payload


def load(index_path: str) -> dict:
    with open(index_path) as fh:
        return json.load(fh)["index"]


def lookup(index: dict, query: str, limit: int = 20) -> List[dict]:
    """Union of exact + substring matches so a product query also surfaces
    vendor-wide advisories (better recall for correlation), deduped by CVE."""
    q = _norm(query)
    hits: List[dict] = list(index.get(q, []))
    for key, advs in index.items():
        if key == q:
            continue
        if q in key or key in q:
            hits.extend(advs)
    seen, out = set(), []
    for a in hits:
        if a["cve"] in seen:
            continue
        seen.add(a["cve"])
        out.append(a)
    return out[:limit]


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--csv", required=True)
    b.add_argument("--out", default="index.json")
    l = sub.add_parser("lookup")
    l.add_argument("--index", default="index.json")
    l.add_argument("--product", required=True)
    args = ap.parse_args()

    if args.cmd == "build":
        build(args.csv, args.out)
    else:
        for a in lookup(load(args.index), args.product):
            print(f"{a['cve']:16} {a['cwe']:10} CVSS={a['cvss']:5} "
                  f"{a['vendor']} / {a['product']}")


if __name__ == "__main__":
    main()
