"""Symbolic bounded model-checking with concrete witnesses — proof-carrying findings.

This is a capability a frontier LLM structurally cannot provide: a *sound* decision
(for the supported fragment) that a safety property is violated, accompanied by a
concrete witness input that triggers it. An LLM can guess "this looks out of
bounds"; this module PROVES it by reasoning over the index/divisor constraints and
emits a counterexample the owner can replay. Defensive: the witness is a test input
demonstrating the bug to fix, not an exploit.

Supported fragment (IEC 61131-3 ST, intraprocedural, linear in one variable):
  - SAFETY PROPERTY 1 (CWE-787): every `arr[expr]` index stays within the array's
    declared [lo, hi].
  - SAFETY PROPERTY 2 (CWE-369): no `_ / expr` has a feasible zero divisor.

Method: sound interval analysis over a single index/divisor variable, intersected
with IF-guard constraints. If the feasible index interval escapes [lo, hi] (or the
divisor interval contains 0), the property is VIOLATED and we return the extremal
witness value. Otherwise SAFE for this fragment. Anything outside the fragment ->
UNKNOWN (never a false "safe").
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from schema import Program

# Default integer domain for an unconstrained INT (IEC 61131-3 INT is 16-bit).
INT_MIN, INT_MAX = -32768, 32767

_ARRAY_DECL = re.compile(r"([A-Za-z_]\w*)\s*:\s*ARRAY\s*\[\s*(-?\d+)\s*\.\.\s*(-?\d+)\s*\]",
                         re.IGNORECASE)
_INDEX = re.compile(r"([A-Za-z_]\w*)\s*\[\s*([^\]]+?)\s*\]")
_DIV = re.compile(r"/\s*([A-Za-z_]\w*|\d+)")
_GUARD = re.compile(r"\bIF\b(.+?)\bTHEN\b", re.IGNORECASE)
_CMP = re.compile(r"([A-Za-z_]\w*)\s*(<=|>=|<>|<|>|=)\s*(-?\d+)")
_LINEAR = re.compile(r"^\s*([A-Za-z_]\w*)\s*([+\-])\s*(\d+)\s*$")


@dataclass
class Interval:
    lo: int
    hi: int

    def intersect(self, other: "Interval") -> "Interval":
        return Interval(max(self.lo, other.lo), min(self.hi, other.hi))

    def empty(self) -> bool:
        return self.lo > self.hi

    def shift(self, c: int) -> "Interval":
        return Interval(self.lo + c, self.hi + c)


@dataclass
class SymbolicResult:
    cwe: str
    line: int
    status: str                       # violated | safe | unknown
    witness: Optional[Dict[str, int]] = None     # concrete input that triggers it
    constraints: List[str] = field(default_factory=list)
    rationale: str = ""

    def proof(self) -> str:
        if self.status == "violated":
            return (f"PROOF {self.cwe}@{self.line}: witness {self.witness} "
                    f"violates [{'; '.join(self.constraints)}] — {self.rationale}")
        return f"{self.status.upper()} {self.cwe}@{self.line}: {self.rationale}"


def _guards(source: str) -> Tuple[Dict[str, Interval], Dict[str, set]]:
    """Conjoin all IF-guard comparisons into a per-variable feasible interval, plus
    a set of values each variable is guarded to be NOT equal to (from `<>`).
    `<>` can't narrow an interval, so it's tracked separately and used by the
    division-by-zero check (which only needs to know whether 0 is excluded)."""
    domains: Dict[str, Interval] = {}
    excluded: Dict[str, set] = {}
    for g in _GUARD.findall(source):
        for var, op, num in _CMP.findall(g):
            k = int(num)
            cur = domains.get(var, Interval(INT_MIN, INT_MAX))
            if op == "<":
                cur = cur.intersect(Interval(INT_MIN, k - 1))
            elif op == "<=":
                cur = cur.intersect(Interval(INT_MIN, k))
            elif op == ">":
                cur = cur.intersect(Interval(k + 1, INT_MAX))
            elif op == ">=":
                cur = cur.intersect(Interval(k, INT_MAX))
            elif op == "=":
                cur = cur.intersect(Interval(k, k))
            elif op == "<>":
                excluded.setdefault(var, set()).add(k)
            domains[var] = cur
    return domains, excluded


def _arrays(source: str) -> Dict[str, Tuple[int, int]]:
    return {m.group(1): (int(m.group(2)), int(m.group(3)))
            for m in _ARRAY_DECL.finditer(source)}


def _linear(expr: str) -> Optional[Tuple[str, int]]:
    """Parse `var`, `var + c`, `var - c` -> (var, c). None if not supported."""
    expr = expr.strip()
    m = _LINEAR.match(expr)
    if m:
        c = int(m.group(3)) * (1 if m.group(2) == "+" else -1)
        return m.group(1), c
    if re.fullmatch(r"[A-Za-z_]\w*", expr):
        return expr, 0
    return None


def check(program: Program, witness_domain: Tuple[int, int] = (INT_MIN, INT_MAX)
          ) -> List[SymbolicResult]:
    src = program.source
    arrays = _arrays(src)
    guards, excluded = _guards(src)
    results: List[SymbolicResult] = []
    base = Interval(*witness_domain)

    for i, line in enumerate(src.splitlines(), 1):
        # --- array bounds property ---
        for m in _INDEX.finditer(line):
            arr, expr = m.group(1), m.group(2)
            if arr not in arrays:
                continue
            lo, hi = arrays[arr]
            lin = _linear(expr)
            if lin is None:
                results.append(SymbolicResult("CWE-787", i, "unknown",
                               rationale=f"non-linear index '{expr}'"))
                continue
            var, c = lin
            dom = base.intersect(guards.get(var, Interval(INT_MIN, INT_MAX)))
            idx_iv = dom.shift(c)
            cons = [f"{var}∈[{dom.lo},{dom.hi}]", f"index={var}+{c}", f"bounds=[{lo},{hi}]"]
            if idx_iv.lo < lo:
                wv = lo - 1 - c  # var value making index = lo-1 (just below)
                results.append(SymbolicResult("CWE-787", i, "violated", {var: max(dom.lo, wv)},
                               cons, f"index can be {idx_iv.lo} < {lo}"))
            elif idx_iv.hi > hi:
                wv = hi + 1 - c
                results.append(SymbolicResult("CWE-787", i, "violated", {var: min(dom.hi, wv)},
                               cons, f"index can be {idx_iv.hi} > {hi}"))
            else:
                results.append(SymbolicResult("CWE-787", i, "safe", None, cons,
                               f"index ⊆ [{lo},{hi}]"))
        # --- division-by-zero property ---
        for m in _DIV.finditer(line):
            d = m.group(1)
            if d.isdigit() or (d.startswith("-") and d[1:].isdigit()):
                if int(d) == 0:
                    results.append(SymbolicResult("CWE-369", i, "violated", {"divisor": 0},
                                   ["literal 0"], "constant zero divisor"))
                continue
            dom = base.intersect(guards.get(d, Interval(INT_MIN, INT_MAX)))
            zero_excluded = 0 in excluded.get(d, set())
            cons = [f"{d}∈[{dom.lo},{dom.hi}]"] + (["d<>0"] if zero_excluded else [])
            if (dom.lo <= 0 <= dom.hi) and not zero_excluded:
                results.append(SymbolicResult("CWE-369", i, "violated", {d: 0}, cons,
                               "divisor interval contains 0"))
            else:
                results.append(SymbolicResult("CWE-369", i, "safe", None, cons,
                               "0 excluded from divisor domain"))
    return results
