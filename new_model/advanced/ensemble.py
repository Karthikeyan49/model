"""Weighted multi-signal fusion.

The hybrid's precision comes from combining independent signals, not from any one
model. This fuses, per finding, calibrated evidence from:

  - analyzer grounding   (deterministic SAST said so)
  - LLM confidence       (self-consistency vote fraction)
  - reachability         (dataflow taint path exists)
  - severity prior       (higher severity -> slightly higher prior)

into a single confidence, which then feeds conformal abstention. Weights are
explicit and tunable on the calibration split (later: learn them via logistic
regression on calibration labels — interface stays the same).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional

from schema import Finding, Program
from scoring import ScoredFinding

DEFAULT_WEIGHTS = {
    "analyzer": 0.30,
    "llm": 0.40,
    "reachability": 0.20,
    "severity": 0.10,
}

_SEV_PRIOR = {"info": 0.2, "low": 0.4, "medium": 0.6, "high": 0.8, "critical": 1.0}


@dataclass
class FusedFinding:
    finding: Finding
    confidence: float
    components: dict


def fuse(findings: List[Finding], programs: List[Program],
         llm_conf: dict, weights: Optional[dict] = None,
         reachability_of: Optional[Callable[[Finding, Program], Optional[bool]]] = None
         ) -> List[FusedFinding]:
    """llm_conf: {(pid,line,cwe): confidence} from self-consistency.
    reachability_of: callable returning True/False/None (dataflow)."""
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    by_pid = {p.pid: p for p in programs}
    out: List[FusedFinding] = []
    for f in findings:
        p = by_pid.get(f.pid)
        if p is None:
            continue
        key = (f.pid, f.line, f.cwe)
        comp = {
            "analyzer": 1.0 if f.grounded else 0.0,
            "llm": float(llm_conf.get(key, 0.5)),
            "severity": _SEV_PRIOR.get(f.severity, 0.6),
        }
        reach = reachability_of(f, p) if reachability_of else None
        # None -> neutral 0.5; True -> 1.0; False -> 0.0 (strong FP signal)
        comp["reachability"] = 0.5 if reach is None else (1.0 if reach else 0.0)

        conf = sum(w[k] * comp[k] for k in w) / sum(w.values())
        out.append(FusedFinding(f, round(conf, 4), comp))
    return out


def to_scored(fused: List[FusedFinding]) -> List[ScoredFinding]:
    return [ScoredFinding(x.finding, x.confidence) for x in fused]
