"""Confidence scoring interface — the foundation for the advanced layers.

Traditional pipelines emit a hard yes/no per finding. Every advanced technique
here (conformal abstention, self-consistency, ensembling) instead needs a
*calibrated confidence* in [0,1] per finding. This module defines that interface
plus a deterministic mock so the whole advanced stack runs and tests with zero
backends.

Real scorers wrap the LLM:
  - token-logprob of the "real" verdict, or
  - agreement frequency across N samples (see selfconsistency.py).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from schema import Finding, Program


@dataclass
class ScoredFinding:
    finding: Finding
    confidence: float            # P(finding is a true vulnerability), 0..1


class ConfidenceScorer(Protocol):
    def score(self, finding: Finding, program: Program) -> float: ...


class MockScorer:
    """Deterministic scorer for tests/smoke-runs.

    Uses the program's ground-truth labels as a noisy oracle: true findings get
    high confidence, false ones low, with a deterministic per-finding jitter so
    calibration/abstention logic has a realistic spread to work on.
    """

    def __init__(self, true_mean: float = 0.82, false_mean: float = 0.35,
                 spread: float = 0.12):
        self.true_mean, self.false_mean, self.spread = true_mean, false_mean, spread

    def _jitter(self, finding: Finding) -> float:
        h = hashlib.sha256(f"{finding.pid}:{finding.line}:{finding.cwe}".encode())
        # map first 4 bytes -> [-1, 1]
        v = int.from_bytes(h.digest()[:4], "big") / 0xFFFFFFFF
        return (v * 2 - 1) * self.spread

    def score(self, finding: Finding, program: Program) -> float:
        is_true = any(
            l.line == finding.line and l.cwe == finding.cwe for l in program.labels
        )
        base = self.true_mean if is_true else self.false_mean
        return max(0.0, min(1.0, base + self._jitter(finding)))


def score_all(findings, programs, scorer: ConfidenceScorer):
    by_pid = {p.pid: p for p in programs}
    out = []
    for f in findings:
        p = by_pid.get(f.pid)
        if p is None:
            continue
        out.append(ScoredFinding(f, scorer.score(f, p)))
    return out
