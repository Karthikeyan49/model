"""Phase 5 — false-positive hardening sweep.

The single number that decides usability is precision at the recall you need.
This sweeps the hybrid (Arm C) across severity-floor operating points, builds the
precision/recall/FP-rate curve, and picks the floor that meets target recall with
the lowest false-positive rate. Run after the real backends are wired.

Usage:
  python sweep.py --config config.yaml
"""
from __future__ import annotations

import argparse
import copy

import yaml

import analyzer
import eval as evalmod
import ingest
import triage
import verify

FLOORS = ["info", "low", "medium", "high", "critical"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()
    with open(args.config) as fh:
        base_cfg = yaml.safe_load(fh)

    programs = ingest.load(base_cfg)
    _, evalset = ingest.holdout_split(
        programs, base_cfg["ingest"]["holdout_seed"], base_cfg["ingest"]["holdout_frac"]
    )

    # Compute candidate findings once; only the scoring floor changes per row.
    analyzer_findings = analyzer.analyze(evalset, base_cfg)
    triaged = triage.triage_candidates(analyzer_findings, evalset, base_cfg)

    target = base_cfg["eval"]["target_recall"]
    print(f"Held-out eval: {len(evalset)} programs | target recall {target}\n")
    print("| Severity floor | Precision | Recall | F1 | FP/prog |")
    print("|----------------|-----------|--------|----|---------|")

    rows = []
    for floor in FLOORS:
        cfg = copy.deepcopy(base_cfg)
        cfg["eval"]["severity_floor"] = floor
        hybrid = verify.verify(triaged, cfg)
        r = evalmod.score("C", hybrid, evalset, cfg)
        rows.append((floor, r))
        print(f"| {floor:14} | {r.precision:.2f}      | {r.recall:.2f}   | "
              f"{r.f1:.2f} | {r.fp_rate:.2f}    |")

    # Pick the floor meeting target recall with the lowest FP-rate (then best precision).
    qualifying = [(f, r) for f, r in rows if r.recall >= target]
    if qualifying:
        best_floor, best = min(qualifying, key=lambda x: (x[1].fp_rate, -x[1].precision))
        print(f"\n**Operating point:** floor='{best_floor}' meets recall>={target} "
              f"at precision={best.precision:.2f}, FP/prog={best.fp_rate:.2f}.")
    else:
        print(f"\n**No floor meets target recall {target}.** Improve grounding/triage "
              "recall before tightening precision — do not ship below target recall.")


if __name__ == "__main__":
    main()
