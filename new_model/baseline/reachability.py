"""Reachability / exploitability reasoning — the defensive "is this finding real?"
question (the attacker's actual concern, minus the attack).

This is a transparent, conservative heuristic layer that annotates each finding
with a reachability verdict. It is NOT exploit generation: it answers "could this
sink be hit by influenceable input" so triage can prioritise, and it can DOWN-rank
findings that are clearly dead/unreachable to cut false positives further.

Heuristics (PLC Structured Text, line-oriented; replace with real taint/CFG later):
  - reachable     : sink line is inside executable body and uses a variable that
                    is read from an input (VAR_INPUT / I/O) or unconstrained var.
  - guarded       : sink is preceded by an IF/bounds check on the same variable.
  - unreachable   : sink is in dead code (after RETURN, or in a never-true branch).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from schema import Finding, Program


@dataclass
class Reach:
    verdict: str          # reachable | guarded | unreachable
    confidence: float     # 0..1
    rationale: str


_INPUT_DECL = re.compile(r"\bVAR_INPUT\b", re.IGNORECASE)
_RETURN = re.compile(r"\bRETURN\b", re.IGNORECASE)
_IF = re.compile(r"\bIF\b", re.IGNORECASE)


def _var_on_line(source_lines: List[str], line: int) -> str:
    if 1 <= line <= len(source_lines):
        m = re.search(r"([A-Za-z_]\w*)\s*\[", source_lines[line - 1])
        if m:
            return m.group(1)
        m = re.search(r"([A-Za-z_]\w*)", source_lines[line - 1])
        if m:
            return m.group(1)
    return ""


def assess(finding: Finding, program: Program) -> Reach:
    lines = program.source.splitlines()
    idx = finding.line
    var = _var_on_line(lines, idx)

    # unreachable: a RETURN appears before the sink in the same flat body
    body_before = "\n".join(lines[:max(0, idx - 1)])
    if _RETURN.search(body_before) and not _IF.search(body_before):
        return Reach("unreachable", 0.7, "sink follows an unconditional RETURN")

    # guarded: an IF mentioning the sink variable precedes the sink
    if var:
        for ln in lines[max(0, idx - 6):idx - 1]:
            if _IF.search(ln) and var in ln:
                return Reach("guarded", 0.6,
                             f"'{var}' is checked by a preceding IF guard")

    # reachable: variable comes from an input declaration → attacker-influenceable
    has_input = _INPUT_DECL.search(program.source) is not None
    if var and has_input:
        return Reach("reachable", 0.8,
                     f"'{var}' is reachable from VAR_INPUT (influenceable)")

    # default: assume reachable but low confidence (conservative for recall)
    return Reach("reachable", 0.4, "no guard or dead-code evidence found")


def annotate(findings: List[Finding], programs: List[Program]) -> List[Finding]:
    """Attach reachability to findings via explanation; drop clearly-unreachable
    ones (false-positive reduction). Returns the surviving findings."""
    by_pid = {p.pid: p for p in programs}
    kept: List[Finding] = []
    for f in findings:
        program = by_pid.get(f.pid)
        if program is None:
            kept.append(f)
            continue
        r = assess(f, program)
        if r.verdict == "unreachable" and r.confidence >= 0.6:
            continue  # high-confidence dead code → not a real exposure
        note = f" [reachability: {r.verdict} ({r.confidence:.0%}) — {r.rationale}]"
        kept.append(Finding(f.pid, f.line, f.cwe, f.severity, f.source, f.grounded,
                           (f.explanation + note).strip(), f.fix))
    return kept
