"""Orchestrator: run arms A / B / C on the held-out split and print the table.

  Arm A = frontier free-scan (triage.free_scan)
  Arm B = analyzer only (analyzer.analyze)
  Arm C = hybrid: analyzer candidates -> LLM triage -> verify

Usage:
  python run.py --config config.yaml
"""
from __future__ import annotations

import argparse

import yaml

import analyzer
import eval as evalmod
import ingest
import report
import triage
import verify


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config.yaml")
    args = ap.parse_args()
    with open(args.config) as fh:
        cfg = yaml.safe_load(fh)

    programs = ingest.load(cfg)
    _, evalset = ingest.holdout_split(
        programs, cfg["ingest"]["holdout_seed"], cfg["ingest"]["holdout_frac"]
    )
    print(f"[ingest] {len(programs)} programs, {len(evalset)} in held-out eval split")

    # Arm B: analyzer only
    analyzer_findings = analyzer.analyze(evalset, cfg)
    print(f"[arm B] analyzer produced {len(analyzer_findings)} findings")

    # Arm A: frontier free-scan
    frontier_findings = triage.free_scan(evalset, cfg)
    print(f"[arm A] frontier free-scan produced {len(frontier_findings)} findings")

    # Arm C: hybrid = triage analyzer candidates, then verify (drop ungrounded)
    triaged = triage.triage_candidates(analyzer_findings, evalset, cfg)
    hybrid_findings = verify.verify(triaged, cfg)
    print(f"[arm C] hybrid kept {len(hybrid_findings)} findings after triage+verify")

    results = [
        evalmod.score("A", frontier_findings, evalset, cfg),
        evalmod.score("B", analyzer_findings, evalset, cfg),
        evalmod.score("C", hybrid_findings, evalset, cfg),
    ]
    table = evalmod.table(results, cfg)
    print("\n" + table + "\n")

    path = report.write_report(results, table, cfg)
    print(f"[report] written to {path}")


if __name__ == "__main__":
    main()
