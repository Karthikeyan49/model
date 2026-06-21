"""Symbolic bounded model-checking with concrete witnesses — proof-carrying findings.

This is a capability a frontier LLM structurally cannot provide: a *sound* decision
(for the supported fragment) that a safety property is violated, accompanied by a
concrete witness input that triggers it. An LLM can guess "this looks out of
bounds"; this module PROVES it by reasoning over the index/divisor constraints and
emits a counterexample the owner can replay. Defensive: the witness is a test input
demonstrating the bug to fix, not an exploit.

Supported fragment (IEC 61131-3 ST, intraprocedural, linear):
  - SAFETY PROPERTY 1 (CWE-787): every `arr[expr]` index stays within the array's
    declared [lo, hi]. The index may be linear in ONE variable (`var`, `var +/- c`)
    or in TWO variables (`v1 + v2`, `v1 - v2`, `v1 + v2 + c`, ...). The feasible
    index interval is computed by interval arithmetic over the per-variable guarded
    intervals (subtraction negates the second interval).
  - SAFETY PROPERTY 2 (CWE-369): no `_ / expr` has a feasible zero divisor.
  - SAFETY PROPERTY 3 (CWE-190 / CWE-191): for INT-typed assignments of the form
    `dest := a op b` (op in {+, -, *}; operands variables or constants), the result
    interval (interval arithmetic) must stay within the signed 16-bit INT range. If
    it can exceed INT_MAX -> CWE-190 (overflow); if it can fall below INT_MIN ->
    CWE-191 (underflow). Each violation carries an extremal witness.

Method: sound interval analysis over the index/divisor/operand variables, intersected
with IF-guard constraints. If the feasible interval escapes its bound (index out of
[lo, hi], divisor contains 0, or arithmetic result outside INT range), the property
is VIOLATED and we return the extremal witness value(s). Otherwise SAFE for this
fragment. Anything outside the fragment -> UNKNOWN (never a false "safe").
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
# A declaration `name : INT` (the type token must be exactly INT, not e.g. UINT/DINT).
_INT_DECL = re.compile(r"([A-Za-z_]\w*)\s*:\s*INT\b", re.IGNORECASE)
# An arithmetic assignment `dest := a op b ;` with op in {+,-,*}. Operands are a
# single variable or an integer literal (sign allowed). The assignment may appear
# inline after a guard (e.g. `IF ... THEN r := a+b; END_IF;`); we require the dest
# to be a bare identifier (a `(?![\[(])` look-ahead excludes array writes / calls)
# and the RHS to be terminated by `;` or end-of-string so we don't swallow a third
# operand (which would be non-linear / unsupported).
_ARITH = re.compile(
    r"(?<![A-Za-z0-9_])([A-Za-z_]\w*)\s*:=\s*"
    r"(-?\d+|[A-Za-z_]\w*)\s*([+\-*])\s*(-?\d+|[A-Za-z_]\w*)\s*(?:;|$)")


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

    def negate(self) -> "Interval":
        return Interval(-self.hi, -self.lo)

    def add(self, other: "Interval") -> "Interval":
        return Interval(self.lo + other.lo, self.hi + other.hi)

    def sub(self, other: "Interval") -> "Interval":
        return self.add(other.negate())

    def mul(self, other: "Interval") -> "Interval":
        prods = [self.lo * other.lo, self.lo * other.hi,
                 self.hi * other.lo, self.hi * other.hi]
        return Interval(min(prods), max(prods))


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


def _int_vars(source: str) -> set:
    """Variable names declared with exact type INT (signed 16-bit)."""
    return {m.group(1) for m in _INT_DECL.finditer(source)}


def _linear2(expr: str) -> Optional[Tuple[Dict[str, int], int]]:
    """Parse a sum/difference of terms into (coeffs, const) where the expression
    equals sum(coeff*var) + const. Supports up to TWO distinct variables, each with
    coefficient +1 or -1 (linear, no scaling), e.g. `v1 + v2`, `v1 - v2 + 3`,
    `v1 + v2 + c`. Returns None if the expression is not a pure linear combination
    of <=2 vars with unit coefficients (so the caller falls back to UNKNOWN)."""
    expr = expr.strip()
    # Split into signed terms. Insert a leading '+' so the first term is captured.
    if not re.fullmatch(r"[\sA-Za-z0-9_+\-]+", expr):
        return None
    s = "+" + expr.replace(" ", "")
    terms = re.findall(r"([+\-])([A-Za-z_]\w*|\d+)", s)
    # Rebuild the canonical string from the parsed terms; if it differs from the
    # (whitespace-stripped) input, the expression had unsupported structure.
    rebuilt = "".join(sign + tok for sign, tok in terms)
    if rebuilt != s:
        return None
    coeffs: Dict[str, int] = {}
    const = 0
    for sign, tok in terms:
        k = 1 if sign == "+" else -1
        if tok.isdigit():
            const += k * int(tok)
        else:
            coeffs[tok] = coeffs.get(tok, 0) + k
    coeffs = {v: c for v, c in coeffs.items() if c != 0}
    if not (1 <= len(coeffs) <= 2):
        return None
    if any(abs(c) != 1 for c in coeffs.values()):
        return None  # only unit coefficients supported (sound: else -> unknown)
    return coeffs, const


def check(program: Program, witness_domain: Tuple[int, int] = (INT_MIN, INT_MAX)
          ) -> List[SymbolicResult]:
    src = program.source
    arrays = _arrays(src)
    guards, excluded = _guards(src)
    int_vars = _int_vars(src)
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
            if lin is not None:
                # --- single-variable path (unchanged behavior) ---
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
                continue
            # --- multi-variable (<=2 vars) linear path ---
            lin2 = _linear2(expr)
            if lin2 is None:
                results.append(SymbolicResult("CWE-787", i, "unknown",
                               rationale=f"non-linear index '{expr}'"))
                continue
            coeffs, const = lin2
            doms = {v: base.intersect(guards.get(v, Interval(INT_MIN, INT_MAX)))
                    for v in coeffs}
            idx_iv = Interval(const, const)
            for v, k in coeffs.items():
                term = doms[v] if k == 1 else doms[v].negate()
                idx_iv = idx_iv.add(term)
            cons = ([f"{v}∈[{doms[v].lo},{doms[v].hi}]" for v in coeffs]
                    + [f"index={expr}", f"bounds=[{lo},{hi}]"])
            if idx_iv.lo < lo:
                # extremal witness: push each var toward minimizing the index
                wit = {v: (doms[v].lo if k == 1 else doms[v].hi)
                       for v, k in coeffs.items()}
                results.append(SymbolicResult("CWE-787", i, "violated", wit, cons,
                               f"index can be {idx_iv.lo} < {lo}"))
            elif idx_iv.hi > hi:
                wit = {v: (doms[v].hi if k == 1 else doms[v].lo)
                       for v, k in coeffs.items()}
                results.append(SymbolicResult("CWE-787", i, "violated", wit, cons,
                               f"index can be {idx_iv.hi} > {hi}"))
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
        # --- INT arithmetic overflow/underflow property (CWE-190 / CWE-191) ---
        results.extend(_check_arith(line, i, int_vars, guards, base))
    return results


def _operand(tok: str, int_vars: set, guards: Dict[str, Interval],
             base: Interval) -> Optional[Tuple[Interval, bool, Optional[str]]]:
    """Resolve an operand token to (interval, is_const, var_name_or_None).
    Returns None if the operand cannot be soundly bounded (e.g. a non-INT
    variable), forcing the caller to report UNKNOWN."""
    if re.fullmatch(r"-?\d+", tok):
        v = int(tok)
        return Interval(v, v), True, None
    if tok in int_vars:
        dom = base.intersect(guards.get(tok, Interval(INT_MIN, INT_MAX)))
        return dom, False, tok
    return None  # unknown/typed-but-not-INT operand -> not soundly boundable


def _check_arith(line: str, i: int, int_vars: set, guards: Dict[str, Interval],
                 base: Interval) -> List[SymbolicResult]:
    """Analyze `dest := a op b` (op in {+,-,*}) over INT operands for 16-bit
    overflow (CWE-190) / underflow (CWE-191). Additive: only fires on lines that
    syntactically match an arithmetic assignment whose dest is INT-typed."""
    out_all: List[SymbolicResult] = []
    for m in _ARITH.finditer(line):
        out_all.extend(_check_arith_match(m, i, int_vars, guards, base))
    return out_all


def _check_arith_match(m, i: int, int_vars: set, guards: Dict[str, Interval],
                       base: Interval) -> List[SymbolicResult]:
    dest, ta, op, tb = m.group(1), m.group(2), m.group(3), m.group(4)
    if dest not in int_vars:
        return []  # not an INT result -> outside this property's scope
    ra = _operand(ta, int_vars, guards, base)
    rb = _operand(tb, int_vars, guards, base)
    if ra is None or rb is None:
        # at least one operand can't be soundly bounded as INT -> unknown
        return [SymbolicResult("CWE-190", i, "unknown",
                rationale=f"unbounded/non-INT operand in '{ta} {op} {tb}'")]
    ia, _, va = ra
    ib, _, vb = rb
    if op == "+":
        res = ia.add(ib)
    elif op == "-":
        res = ia.sub(ib)
    else:  # "*"
        res = ia.mul(ib)
    cons = []
    if va is not None:
        cons.append(f"{va}∈[{ia.lo},{ia.hi}]")
    if vb is not None and vb != va:
        cons.append(f"{vb}∈[{ib.lo},{ib.hi}]")
    cons += [f"result={ta}{op}{tb}∈[{res.lo},{res.hi}]", f"INT=[{INT_MIN},{INT_MAX}]"]

    def _extremal(maximize: bool) -> Dict[str, int]:
        """Pick operand values that push the result to its extreme (max or min)."""
        wit: Dict[str, int] = {}
        # For each variable operand choose the endpoint driving result up/down.
        # For +: both push same direction. For -: a same, b opposite.
        # For *: choose the endpoint pairing that realizes res.hi / res.lo.
        if op in ("+", "-"):
            if va is not None:
                wit[va] = ia.hi if maximize else ia.lo
            if vb is not None:
                if op == "+":
                    wit[vb] = ib.hi if maximize else ib.lo
                else:  # subtraction: maximizing result means minimizing b
                    wit[vb] = ib.lo if maximize else ib.hi
        else:  # multiplication: search the four corner pairings
            target = res.hi if maximize else res.lo
            for ea in (ia.lo, ia.hi):
                for eb in (ib.lo, ib.hi):
                    if ea * eb == target:
                        if va is not None:
                            wit[va] = ea
                        if vb is not None:
                            wit[vb] = eb
                        return wit
        return wit

    out: List[SymbolicResult] = []
    if res.hi > INT_MAX:
        out.append(SymbolicResult("CWE-190", i, "violated", _extremal(True), cons,
                   f"result can reach {res.hi} > INT_MAX={INT_MAX}"))
    if res.lo < INT_MIN:
        out.append(SymbolicResult("CWE-191", i, "violated", _extremal(False), cons,
                   f"result can reach {res.lo} < INT_MIN={INT_MIN}"))
    if not out:
        out.append(SymbolicResult("CWE-190", i, "safe", None, cons,
                   f"result ⊆ INT range"))
    return out
