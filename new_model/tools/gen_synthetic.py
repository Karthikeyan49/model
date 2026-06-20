"""Generate synthetic labeled IEC 61131-3 ST programs to enrich the test corpus.

Useful before PLC-BEAD is available: exercises the pipeline with more variety and
both vulnerable and clean cases. Output is in baseline format (*.st + labels.json),
so it drops straight into ingest. DEFENSIVE: these are buggy-but-inert templates
for detector testing, not exploits.

Usage:
  python gen_synthetic.py --out ../baseline/data/synth --n 40 --seed 7
"""
from __future__ import annotations

import argparse
import json
import os
import random

# Each template: (builder(rng) -> source, label or None). Label line is computed
# from the fixed template layout.
def _oob(rng):
    n = rng.randint(2, 9)
    src = (f"PROGRAM oob_{rng.randint(0,9999)}\n"
           "VAR\n"
           f"  arr : ARRAY[0..{n}] OF INT;\n"
           "  i : INT;\n"
           "END_VAR\n"
           f"arr[i + {rng.randint(1,5)}] := 1;\n"
           "END_PROGRAM\n")
    return src, {"line": 6, "cwe": "CWE-787", "severity": "high"}


def _divzero(rng):
    src = (f"PROGRAM div_{rng.randint(0,9999)}\n"
           "VAR\n"
           "  a : REAL;\n"
           "  b : REAL;\n"
           "END_VAR\n"
           "b := a / 0;\n"
           "END_PROGRAM\n")
    return src, {"line": 6, "cwe": "CWE-369", "severity": "medium"}


def _clean(rng):
    k = rng.randint(1, 9)
    src = (f"PROGRAM clean_{rng.randint(0,9999)}\n"
           "VAR\n"
           f"  x : INT := {k};\n"
           f"  y : INT := {k + 1};\n"
           "END_VAR\n"
           "x := y + 1;\n"
           "END_PROGRAM\n")
    return src, None


TEMPLATES = [_oob, _divzero, _clean]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=40)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    os.makedirs(args.out, exist_ok=True)
    labels = {}
    counts = {"vuln": 0, "clean": 0}
    for i in range(args.n):
        builder = rng.choice(TEMPLATES)
        src, label = builder(rng)
        name = f"synth_{i:04d}.st"
        with open(os.path.join(args.out, name), "w") as fh:
            fh.write(src)
        labels[name] = [label] if label else []
        counts["vuln" if label else "clean"] += 1

    with open(os.path.join(args.out, "labels.json"), "w") as fh:
        json.dump(labels, fh, indent=2)
    print(f"generated {args.n} programs ({counts['vuln']} vuln, {counts['clean']} clean) "
          f"-> {args.out}")


if __name__ == "__main__":
    main()
