"""Self-consistency — sample the triage verdict N times, aggregate by majority.

Research-grounded and deliberately chosen over flashier alternatives: a 2026
controlled study found multi-agent *debate* significantly UNDERPERFORMS simple
self-consistency majority voting at equal compute (arXiv 2511.07784), and LLMs
"cannot self-correct reasoning yet" (arXiv 2310.01798). So the highest-yield,
lowest-risk technique is N-sample majority voting — and it doubles as a free
confidence signal: confidence = fraction of samples that say "real".

A `Sampler` returns a bool verdict for one stochastic pass; in production wire it
to the LLM at temperature>0. The mock sampler is deterministic-but-noisy for tests.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, List

from schema import Finding, Program
from scoring import ScoredFinding

# A sampler: (finding, program, sample_index) -> verdict bool
Sampler = Callable[[Finding, Program, int], bool]


@dataclass
class ConsistencyResult:
    finding: Finding
    confidence: float            # fraction of samples voting "real"
    votes_real: int
    n_samples: int


def make_mock_sampler(true_rate: float = 0.85, false_rate: float = 0.3) -> Sampler:
    """Each sample votes 'real' with prob true_rate if the finding matches a label,
    else false_rate. Deterministic per (finding, sample) via hashing."""
    def sampler(f: Finding, p: Program, i: int) -> bool:
        is_true = any(l.line == f.line and l.cwe == f.cwe for l in p.labels)
        rate = true_rate if is_true else false_rate
        h = hashlib.sha256(f"{f.pid}:{f.line}:{f.cwe}:{i}".encode()).digest()
        u = int.from_bytes(h[:4], "big") / 0xFFFFFFFF
        return u < rate
    return sampler


def vote(findings: List[Finding], programs: List[Program], sampler: Sampler,
         n_samples: int = 5, accept: float = 0.5) -> List[ConsistencyResult]:
    by_pid = {p.pid: p for p in programs}
    out: List[ConsistencyResult] = []
    for f in findings:
        p = by_pid.get(f.pid)
        if p is None:
            continue
        votes = sum(1 for i in range(n_samples) if sampler(f, p, i))
        out.append(ConsistencyResult(f, votes / n_samples, votes, n_samples))
    return out


def to_scored(results: List[ConsistencyResult]) -> List[ScoredFinding]:
    """Bridge to the conformal/ensemble layers which consume ScoredFinding."""
    return [ScoredFinding(r.finding, r.confidence) for r in results]
