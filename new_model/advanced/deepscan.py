"""Deep analysis CLI — chains the beyond-frontier capabilities on a target dir:

    symbolic proof  →  verified repair  →  termination  →  variant hunt  →  KG

For each program: prove which safety properties are VIOLATED (with witnesses),
synthesize and re-verify a patch for each, prove which loops cannot terminate
(CWE-835 — a PLC scan-cycle / watchdog hazard), hunt the whole corpus for
structural variants of every proven bug, and record everything in the persistent
KG so the next scan starts smarter.

Run:
  python deepscan.py --target ../baseline/data/sample
  python deepscan.py --target /path/to/st_dir --kg kg.json
"""
from __future__ import annotations

import argparse
import os
import sys

BASE = os.path.dirname(os.path.dirname(__file__))
for sub in ("baseline", "advanced"):
    sys.path.insert(0, os.path.join(BASE, sub))

import ingest                 # noqa: E402  baseline
import knowledge_graph as kgmod  # noqa: E402
import repair                 # noqa: E402
import symbolic               # noqa: E402
import termination            # noqa: E402
import variant_hunt           # noqa: E402


def run(target: str, kg_path: str | None = None):
    cfg = {"ingest": {"dataset": "sample", "dataset_path": target}}
    programs = ingest.load(cfg)
    kg = kgmod.KnowledgeGraph.load(kg_path) if kg_path and os.path.exists(kg_path) \
        else kgmod.KnowledgeGraph()

    proven = []   # (program, SymbolicResult)
    for p in programs:
        for r in symbolic.check(p):
            if r.status == "violated":
                proven.append((p, r))

    print(f"=== PROVEN VIOLATIONS ({len(proven)}) ===")
    patches = []
    for p, r in proven:
        print(f"  {p.pid}:{r.line}  {r.proof()}")
        pt = repair.synthesize(p, r.cwe, r.line)
        if pt:
            patches.append((p, pt))
        # record seed signature into the KG
        sig = variant_hunt.seed_signature(p, r.line)
        if sig:
            kg.add_finding(f"{p.pid}:{r.line}", sig.key(), r.cwe, "")

    print(f"\n=== VERIFIED REPAIRS ({sum(1 for _, pt in patches if pt.verified)}/"
          f"{len(patches)}) ===")
    for p, pt in patches:
        print(f"  {p.pid}:{pt.line}  {pt.cwe}  verified={pt.verified} — {pt.rationale}")

    print("\n=== NON-TERMINATION (CWE-835 loop / scan-cycle hazards) ===")
    infinite = []
    for p in programs:
        for r in termination.check(p):
            if r.status == "infinite":
                infinite.append((p, r))
                print(f"  {p.pid}:{r.line}  {r.render()}")
    if not infinite:
        print("  none proven infinite")

    print("\n=== VARIANT HUNT (clones of each proven bug across corpus) ===")
    seen_sigs = set()
    for p, r in proven:
        sig = variant_hunt.seed_signature(p, r.line)
        if not sig or sig.key() in seen_sigs:
            continue
        seen_sigs.add(sig.key())
        hits = variant_hunt.hunt(sig, programs)
        print(f"  seed {sig.key()}: {len(hits)} unguarded variant(s)")
        for h in hits:
            print(f"     {h.pid}:{h.line}  {h.snippet}")

    print("\n=== KNOWLEDGE GRAPH ===")
    for pat, n in kg.recurring_patterns(min_count=2):
        print(f"  recurring: {pat}  x{n}")
    if kg_path:
        kg.save(kg_path)
        print(f"  persisted -> {kg_path}")
    return proven, patches, infinite


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=os.path.join(BASE, "baseline", "data", "sample"))
    ap.add_argument("--kg", help="path to persist/load the knowledge graph JSON")
    args = ap.parse_args()
    run(args.target, args.kg)


if __name__ == "__main__":
    main()
