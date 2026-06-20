"""Regression gate — stop silent quality decay between model/data versions.

Detection quality can regress invisibly when you change a prompt, swap a base
model, or add training data. This gate freezes a golden set of expected verdicts
and FAILS (non-zero exit) if the current pipeline drops below committed thresholds
on recall, precision, or false-positive rate, or loses a previously-found bug.

Wire it into CI so no change ships that quietly makes the detector worse — the
"evaluation discipline" that the plan names as a core moat.

Golden file (JSON):
  {
    "min_recall": 0.8, "min_precision": 0.7, "max_fp_per_prog": 0.5,
    "must_find": [ {"pid": "arr_oob_1.st", "cwe": "CWE-787"}, ... ]
  }
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from typing import List

# schema lives in baseline/; make it importable whether run as module or CLI.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "baseline"))
from schema import ArmResult, Finding


@dataclass
class GateResult:
    passed: bool
    failures: List[str]
    metrics: dict


def evaluate(result: ArmResult, findings: List[Finding], golden: dict) -> GateResult:
    failures: List[str] = []

    if result.recall < golden.get("min_recall", 0.0):
        failures.append(f"recall {result.recall:.3f} < min {golden['min_recall']}")
    if result.precision < golden.get("min_precision", 0.0):
        failures.append(f"precision {result.precision:.3f} < min {golden['min_precision']}")
    if "max_fp_per_prog" in golden and result.fp_rate > golden["max_fp_per_prog"]:
        failures.append(f"fp/prog {result.fp_rate:.3f} > max {golden['max_fp_per_prog']}")

    found = {(f.pid, f.cwe) for f in findings}
    for must in golden.get("must_find", []):
        key = (must["pid"], must["cwe"])
        if key not in found:
            failures.append(f"regression: lost finding {key[0]} {key[1]}")

    metrics = {"recall": result.recall, "precision": result.precision,
               "f1": result.f1, "fp_rate": result.fp_rate,
               "tp": result.tp, "fp": result.fp, "fn": result.fn}
    return GateResult(passed=not failures, failures=failures, metrics=metrics)


def render(gate: GateResult) -> str:
    head = "PASS" if gate.passed else "FAIL"
    lines = [f"[regression gate] {head}",
             "  metrics: " + ", ".join(f"{k}={v}" for k, v in gate.metrics.items())]
    for f in gate.failures:
        lines.append(f"  ✗ {f}")
    return "\n".join(lines)


def main() -> None:
    """CLI: scores the bundled sample set against a golden file and exits non-zero
    on regression so CI can gate on it."""
    base = os.path.join(os.path.dirname(__file__), "..", "baseline")
    sys.path.insert(0, base)
    import analyzer, eval as evalmod, ingest, triage, verify  # noqa: E402

    ap = argparse.ArgumentParser()
    ap.add_argument("--golden", required=True)
    ap.add_argument("--config", default=os.path.join(base, "config.yaml"))
    args = ap.parse_args()

    import yaml
    with open(args.config) as fh:
        cfg = yaml.safe_load(fh)
    cfg["ingest"]["dataset_path"] = os.path.join(base, cfg["ingest"]["dataset_path"])
    with open(args.golden) as fh:
        golden = json.load(fh)

    # The golden set is the whole corpus under test (not a holdout split).
    evalset = ingest.load(cfg)
    cands = verify.verify(triage.triage_candidates(
        analyzer.analyze(evalset, cfg), evalset, cfg), cfg)
    result = evalmod.score("C", cands, evalset, cfg)
    gate = evaluate(result, cands, golden)
    print(render(gate))
    sys.exit(0 if gate.passed else 1)


if __name__ == "__main__":
    main()
