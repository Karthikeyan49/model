"""Shared data structures for the Phase 1 hybrid baseline.

Everything in the pipeline speaks these types so arms A/B/C are comparable.
A "finding" is a claimed vulnerability at a location; a "label" is ground truth.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Program:
    """One IEC 61131-3 Structured Text program under test."""
    pid: str
    path: str
    source: str
    # Ground-truth vulnerabilities: list of (line, cwe) the program is known to have.
    labels: list["Label"] = field(default_factory=list)


@dataclass
class Label:
    line: int
    cwe: str
    severity: str = "medium"


@dataclass
class Finding:
    """A claimed issue produced by an arm (analyzer, LLM, or hybrid)."""
    pid: str
    line: int
    cwe: str
    severity: str = "medium"
    source: str = "unknown"        # analyzer | llm | hybrid | frontier
    grounded: bool = False         # backed by a deterministic analyzer location?
    explanation: str = ""
    fix: str = ""

    def sev_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 1)


@dataclass
class Verdict:
    """LLM triage decision about a single candidate finding."""
    is_real: bool
    severity: str
    why: str
    fix: str


@dataclass
class ArmResult:
    """Scored output of one experiment arm over the held-out set."""
    arm: str                       # "A" | "B" | "C"
    findings: list[Finding]
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    fp_rate: float = 0.0           # false positives per program
    tp: int = 0
    fp: int = 0
    fn: int = 0


def severity_at_least(sev: str, floor: str) -> bool:
    return SEVERITY_ORDER.get(sev, 1) >= SEVERITY_ORDER.get(floor, 0)
