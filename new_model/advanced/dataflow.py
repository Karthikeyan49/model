"""Lightweight intraprocedural taint/dataflow reachability for IEC 61131-3 ST.

Upgrades baseline/reachability.py's line heuristics with real def-use + taint
propagation, so the "is it reachable?" verdict has an actual data path behind it.
This is the grounding that lets the verifier (mockcourt) and conformal layer trust
a reachability signal instead of a guess.

Model (approximate, but real):
  - SOURCES  : variables declared in VAR_INPUT (+ I/O) are tainted (attacker/field
               influenceable).
  - PROPAGATE: `lhs := rhs;` taints lhs if any variable in rhs is tainted.
  - SANITIZE : a variable compared in a preceding `IF ... THEN` guard (bounds/!=0)
               is treated as sanitized within the guarded region (approximated as
               the rest of the body).
  - SINKS    : array index `name[expr]` (CWE-787) and division `_ / expr`
               (CWE-369). A sink is REACHABLE iff a tainted, unsanitized variable
               flows into its expression.

Returns the verdict plus the taint path for explainability.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set

from schema import Program

_VAR_INPUT = re.compile(r"\bVAR_INPUT\b(.*?)\bEND_VAR\b", re.IGNORECASE | re.DOTALL)
_IDENT = re.compile(r"[A-Za-z_]\w*")
_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*:=\s*(.+?);")
_IF = re.compile(r"\bIF\b(.+?)\bTHEN\b", re.IGNORECASE)
_INDEX = re.compile(r"([A-Za-z_]\w*)\s*\[([^\]]*)\]")
_DIV = re.compile(r"/\s*([^;]+)")

_KEYWORDS = {"if", "then", "else", "end_if", "and", "or", "not", "true", "false",
             "mod", "to", "do", "while", "for", "return"}


@dataclass
class TaintResult:
    reachable: bool
    cwe: Optional[str]
    path: List[str] = field(default_factory=list)
    rationale: str = ""


def _idents(expr: str) -> Set[str]:
    return {m.group(0) for m in _IDENT.finditer(expr)
            if m.group(0).lower() not in _KEYWORDS and not m.group(0).isdigit()}


def _sources(program: Program) -> Set[str]:
    tainted: Set[str] = set()
    for block in _VAR_INPUT.findall(program.source):
        for line in block.splitlines():
            m = re.match(r"\s*([A-Za-z_]\w*)\s*:", line)
            if m:
                tainted.add(m.group(1))
    return tainted


def analyze(program: Program) -> List[TaintResult]:
    lines = program.source.splitlines()
    tainted = _sources(program)
    sanitized: Set[str] = set()
    origin = {v: [f"VAR_INPUT:{v}"] for v in tainted}
    results: List[TaintResult] = []

    for raw in lines:
        # guards sanitize the variables they constrain
        gm = _IF.search(raw)
        if gm:
            for v in _idents(gm.group(1)):
                sanitized.add(v)

        # taint propagation through assignment
        am = _ASSIGN.match(raw)
        if am:
            lhs, rhs = am.group(1), am.group(2)
            rhs_taint = [v for v in _idents(rhs) if v in tainted and v not in sanitized]
            if rhs_taint:
                tainted.add(lhs)
                origin[lhs] = origin.get(rhs_taint[0], [rhs_taint[0]]) + [f"{lhs}:={rhs.strip()}"]

        # sinks
        for sink_re, cwe, kind in ((_INDEX, "CWE-787", "index"), (_DIV, "CWE-369", "divisor")):
            for m in sink_re.finditer(raw):
                expr = m.group(2) if kind == "index" else m.group(1)
                flow = [v for v in _idents(expr) if v in tainted and v not in sanitized]
                if flow:
                    path = origin.get(flow[0], [flow[0]]) + [f"sink({kind}):{raw.strip()}"]
                    results.append(TaintResult(
                        True, cwe, path,
                        f"tainted '{flow[0]}' reaches {kind} without sanitization"))
                elif kind == "index" and _idents(expr):
                    results.append(TaintResult(
                        False, cwe, [], "index vars are constant or sanitized"))
    return results


def is_reachable(program: Program, cwe: str, line: Optional[int] = None) -> Optional[bool]:
    """Convenience for the verifier: does a reachable taint path exist for `cwe`?
    Returns True/False, or None if the analysis has no opinion."""
    res = [r for r in analyze(program) if r.cwe == cwe]
    if not res:
        return None
    if any(r.reachable for r in res):
        return True
    return False
