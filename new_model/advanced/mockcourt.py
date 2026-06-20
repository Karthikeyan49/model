"""Mock-court multi-agent verifier (optional, evidence-aware).

Three roles examine a candidate finding (grounded in MAVUL multi-agent contextual
reasoning, arXiv 2510.00317, and the Mock-Court approach, arXiv 2505.10961):

  - PROSECUTOR : argues the finding is a real, reachable vulnerability.
  - DEFENSE    : argues it is benign / guarded / unreachable (false positive).
  - JUDGE      : weighs both with the evidence and returns a calibrated verdict.

HONEST CAVEAT (kept in code on purpose): controlled studies show debate-style
multi-agent setups often do not beat plain self-consistency at equal compute, and
can cascade errors. So this is an OPTIONAL high-cost path for hard/ambiguous cases
(e.g. ones self-consistency leaves near the decision boundary), not the default.

The roles here are mock-deterministic; wire each to an LLM call in production.
Crucially, the DEFENSE consumes real evidence (dataflow reachability), so it can
override an over-eager prosecutor — that grounding is what makes it more than
theatre.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from schema import Finding, Program
from scoring import ScoredFinding


@dataclass
class Ruling:
    finding: Finding
    confidence: float
    verdict: str                 # "real" | "dismissed"
    rationale: str


def _prosecution_strength(f: Finding, program: Program) -> float:
    # Higher when grounded by a deterministic analyzer and higher severity.
    base = 0.6 if f.grounded else 0.4
    bonus = {"critical": 0.3, "high": 0.2, "medium": 0.1}.get(f.severity, 0.0)
    return min(1.0, base + bonus)


def _defense_strength(f: Finding, program: Program,
                      reachable: Optional[bool]) -> float:
    # Defense is strong when there's evidence of guarding/unreachability.
    if reachable is False:
        return 0.85
    if "guarded" in f.explanation:
        return 0.6
    return 0.25


def adjudicate(findings: List[Finding], programs: List[Program],
               reachability_of=None) -> List[Ruling]:
    """reachability_of: optional callable(finding, program) -> bool|None
    supplying ground evidence to the defense (e.g. from dataflow.py)."""
    by_pid = {p.pid: p for p in programs}
    rulings: List[Ruling] = []
    for f in findings:
        p = by_pid.get(f.pid)
        if p is None:
            continue
        reachable = reachability_of(f, p) if reachability_of else None
        pros = _prosecution_strength(f, p)
        deff = _defense_strength(f, p, reachable)
        # Judge: normalise the two advocacy strengths into P(real).
        conf = pros / (pros + deff) if (pros + deff) else 0.5
        verdict = "real" if conf >= 0.5 else "dismissed"
        rationale = (f"prosecution={pros:.2f} vs defense={deff:.2f}"
                     + (f", reachable={reachable}" if reachable is not None else ""))
        rulings.append(Ruling(f, round(conf, 3), verdict, rationale))
    return rulings


def to_scored(rulings: List[Ruling]) -> List[ScoredFinding]:
    return [ScoredFinding(r.finding, r.confidence) for r in rulings
            if r.verdict == "real"]
