"""Advanced pipeline orchestrator — chains the research-grounded techniques into
one flow on top of the baseline's grounded candidates:

    candidates (analyzer+verify)
        │
        ├─ self-consistency vote  ──► per-finding LLM confidence
        ├─ dataflow taint         ──► reachability True/False/None
        ▼
    ensemble fusion (analyzer + llm + reachability + severity)
        ▼
    conformal calibration on a calibration split  ──► FP-bounded threshold
        ▼
    EMIT (>= threshold)   +   ABSTAIN (< threshold, for human review)

Runs fully on mock backends. Swap MockScorer/mock sampler for real LLM calls and
the same flow holds.

CLI:
  python pipeline.py --target ../baseline/data/sample --alpha 0.1
"""
from __future__ import annotations

import argparse
import os
import sys

BASE = os.path.dirname(os.path.dirname(__file__))
for sub in ("baseline", "advanced"):
    sys.path.insert(0, os.path.join(BASE, sub))

import analyzer            # noqa: E402  baseline
import ingest              # noqa: E402  baseline
import verify              # noqa: E402  baseline

import conformal           # noqa: E402
import dataflow            # noqa: E402
import ensemble            # noqa: E402
import selfconsistency as sc  # noqa: E402


def run(target: str, alpha: float = 0.1, n_samples: int = 7, cal_frac: float = 0.5):
    cfg = {
        "ingest": {"dataset": "sample", "dataset_path": target,
                   "holdout_seed": 1337, "holdout_frac": 0.5},
        "analyzer": {"binary": "none", "mock_if_missing": True},
        "eval": {"severity_floor": "low"},
    }
    programs = ingest.load(cfg)

    # 1. grounded candidates from the deterministic analyzer
    candidates = verify.verify(analyzer.analyze(programs, cfg), cfg)

    # 2. self-consistency confidence (N stochastic votes)
    sampler = sc.make_mock_sampler()
    results = sc.vote(candidates, programs, sampler, n_samples=n_samples)
    llm_conf = {(r.finding.pid, r.finding.line, r.finding.cwe): r.confidence
                for r in results}

    # 3. dataflow taint reachability as an independent signal
    def reach_of(f, p):
        return dataflow.is_reachable(p, f.cwe, f.line)

    # 4. ensemble fusion -> single confidence per finding
    fused = ensemble.fuse(candidates, programs, llm_conf, reachability_of=reach_of)
    scored = ensemble.to_scored(fused)

    # 5. conformal calibration: split scored set, calibrate FP-bounded threshold
    #    (here we self-calibrate on a labeled split using the programs' labels)
    labeled = []
    by_pid = {p.pid: p for p in programs}
    for s in scored:
        p = by_pid[s.finding.pid]
        is_true = any(l.line == s.finding.line and l.cwe == s.finding.cwe
                      for l in p.labels)
        labeled.append((s, is_true))
    cut = max(1, int(len(labeled) * cal_frac))
    cal = [(s.confidence, t) for s, t in labeled[:cut]]
    test = [s for s, _ in labeled[cut:]] or [s for s, _ in labeled]

    threshold = conformal.calibrate(cal, alpha=alpha)
    emitted, abstained = conformal.apply(test, threshold)
    return {
        "n_candidates": len(candidates),
        "threshold": threshold,
        "emitted": emitted,
        "abstained": abstained,
        "fused": fused,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=os.path.join(BASE, "baseline", "data", "sample"))
    ap.add_argument("--alpha", type=float, default=0.1, help="target FP fraction")
    ap.add_argument("--n-samples", type=int, default=7)
    args = ap.parse_args()
    out = run(args.target, alpha=args.alpha, n_samples=args.n_samples)
    t = out["threshold"]
    print(f"candidates={out['n_candidates']}")
    print(f"conformal: alpha={t.alpha} threshold={t.threshold:.3f} "
          f"cal_fp={t.achieved_fp} coverage={t.coverage} n_cal={t.n_cal}")
    print(f"EMITTED ({len(out['emitted'])}):")
    for s in sorted(out["emitted"], key=lambda x: -x.confidence):
        print(f"  {s.finding.pid}:{s.finding.line} {s.finding.cwe} "
              f"conf={s.confidence:.3f}")
    print(f"ABSTAINED for review ({len(out['abstained'])}):")
    for s in out["abstained"]:
        print(f"  {s.finding.pid}:{s.finding.line} {s.finding.cwe} "
              f"conf={s.confidence:.3f}")


if __name__ == "__main__":
    main()
