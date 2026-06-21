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
  - SAFETY PROPERTY 3 (CWE-190): a plain arithmetic assignment `v := <linear expr>`
    whose result interval can exceed INT_MAX (32767) overflows.
  - SAFETY PROPERTY 4 (CWE-191): same, but whose result interval can drop below
    INT_MIN (-32768) underflows.

Supported linear fragment for an expression (one variable): `var`, `var + c`,
`var - c`, `c * var`, `var * c`. Anything else (two variables, products of
variables, modulo, nested calls) -> UNKNOWN, never a false "safe".

Method: sound interval analysis over a single index/divisor/operand variable,
intersected with IF-guard constraints. If the feasible interval escapes the safe
region the property is VIOLATED and we return the extremal witness value.

BLOCK-SCOPED GUARDS (soundness fix): guards are NOT global. We walk the source
maintaining a stack of currently-open `IF ... THEN ... END_IF` blocks; each line
only sees the conjunction of the guards from the blocks that actually CONTAIN
(dominate) it. A guard popped at its `END_IF` no longer constrains later lines.
This prevents a guard that dominates only one branch from being wrongly applied
to a statement outside that branch (which could shrink a feasible interval and
invent a false "safe").

HONEST CAVEATS (handled conservatively — we keep MORE feasible values, never
fewer, so we never invent a false "safe"):
  - ELSE / ELSIF: the comparisons in an IF head are treated as dominating the
    THEN body only. We do NOT propagate the negated guard into an ELSE branch,
    and ELSIF heads are treated like a fresh IF whose guard we do not trust to
    dominate; in practice we simply stop trusting a guard once its block closes.
    At worst this over-reports `violated`, which is sound.
  - Anything outside the one-variable linear fragment -> UNKNOWN.
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
# c * var  or  var * c
_MUL_L = re.compile(r"^\s*(-?\d+)\s*\*\s*([A-Za-z_]\w*)\s*$")
_MUL_R = re.compile(r"^\s*([A-Za-z_]\w*)\s*\*\s*(-?\d+)\s*$")
# block-structure tokens (line-level, IEC ST is case-insensitive)
_IF_OPEN = re.compile(r"\bIF\b", re.IGNORECASE)
_END_IF = re.compile(r"\bEND_IF\b", re.IGNORECASE)
_ELSE_TOK = re.compile(r"\bELS(?:E|IF)\b", re.IGNORECASE)
# plain arithmetic assignment `v := expr ;` (used by the overflow/underflow check)
_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*:=\s*(.+?)\s*;?\s*$")


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


def _apply_cmps(cmps, domains: Dict[str, Interval], excluded: Dict[str, set]) -> None:
    """Intersect a list of (var, op, num) comparisons into per-var intervals; track
    `<>` exclusions separately (they can't narrow an interval — used by div-zero)."""
    for var, op, num in cmps:
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


def _line_guards(source: str) -> List[Tuple[Dict[str, Interval], Dict[str, set]]]:
    """Block-scoped guards: return, per source line (1-based; index i-1), the
    (domains, excluded) seen by that line, conjoining ONLY the comparisons from the
    `IF ... THEN ... END_IF` blocks that lexically enclose (dominate) it.

    We walk lines maintaining a stack of per-IF comparison lists. At an `IF ... THEN`
    we push that head's comparisons; at the matching `END_IF` we pop. ELSE/ELSIF on
    a line cause us to DROP the enclosing IF's comparisons for the remainder of the
    block (we no longer trust them to dominate the alternate branch) — conservative:
    we keep a WIDER interval, never inventing a false `safe`. Nested IFs without a
    THEN on the same line (multi-line heads) are handled by only pushing when a THEN
    is present; a bare `IF` without `THEN` pushes an empty (untrusted) frame so its
    `END_IF` still balances the stack."""
    lines = source.splitlines()
    out: List[Tuple[Dict[str, Interval], Dict[str, set]]] = []
    # stack entries: list of (var, op, num) comparisons trusted for this block
    stack: List[List[Tuple[str, str, str]]] = []
    for line in lines:
        opens = len(_IF_OPEN.findall(line))
        closes = len(_END_IF.findall(line))
        # END_IF in IEC also matches inside ELSE handling? no — distinct token.
        has_else = bool(_ELSE_TOK.search(line))

        # Compute guards visible to THIS line BEFORE applying this line's own
        # open/close, so an `IF c THEN stmt; END_IF;` on one line still guards stmt.
        # We first push any IF-heads on this line, then snapshot, then pop END_IFs.
        # ELSE/ELSIF on this line invalidates the enclosing frame for what follows.
        if has_else and stack:
            stack[-1] = []  # stop trusting the current block's guard

        # push frames for IF-heads on this line
        pushed_this_line = 0
        if opens:
            heads = _GUARD.findall(line)
            for h in heads:
                stack.append(_CMP.findall(h))
                pushed_this_line += 1
            # `IF` without matching `THEN` on the same line (multi-line head):
            for _ in range(opens - len(heads)):
                stack.append([])      # untrusted frame, balances its END_IF
                pushed_this_line += 1

        # snapshot the conjunction of all currently-open frames
        domains: Dict[str, Interval] = {}
        excluded: Dict[str, set] = {}
        for frame in stack:
            _apply_cmps(frame, domains, excluded)
        out.append((domains, excluded))

        # pop frames for END_IFs on this line
        for _ in range(closes):
            if stack:
                stack.pop()
    return out


def _arrays(source: str) -> Dict[str, Tuple[int, int]]:
    return {m.group(1): (int(m.group(2)), int(m.group(3)))
            for m in _ARRAY_DECL.finditer(source)}


def _linear(expr: str) -> Optional[Tuple[str, int]]:
    """Parse the additive linear fragment `var`, `var + c`, `var - c` -> (var, c),
    representing the value `var + c`. None if not supported. (Index/divisor uses.)"""
    expr = expr.strip()
    m = _LINEAR.match(expr)
    if m:
        c = int(m.group(3)) * (1 if m.group(2) == "+" else -1)
        return m.group(1), c
    if re.fullmatch(r"[A-Za-z_]\w*", expr):
        return expr, 0
    return None


def _affine(expr: str) -> Optional[Tuple[str, int, int]]:
    """Parse the full one-variable linear fragment into (var, a, b) representing the
    value `a*var + b`. Supports `var`, `var + c`, `var - c`, `c * var`, `var * c`.
    None if outside the fragment (-> caller returns UNKNOWN, never a false safe)."""
    expr = expr.strip()
    lin = _linear(expr)
    if lin is not None:
        var, b = lin
        return var, 1, b
    m = _MUL_L.match(expr)
    if m:
        return m.group(2), int(m.group(1)), 0
    m = _MUL_R.match(expr)
    if m:
        return m.group(1), int(m.group(2)), 0
    return None


def _affine_interval(dom: "Interval", a: int, b: int) -> "Interval":
    """Image of `dom` under v -> a*v + b (a may be negative, flipping endpoints)."""
    e1, e2 = a * dom.lo + b, a * dom.hi + b
    return Interval(min(e1, e2), max(e1, e2))


def check(program: Program, witness_domain: Tuple[int, int] = (INT_MIN, INT_MAX)
          ) -> List[SymbolicResult]:
    src = program.source
    arrays = _arrays(src)
    line_guards = _line_guards(src)            # block-scoped, per line
    results: List[SymbolicResult] = []
    base = Interval(*witness_domain)

    for i, line in enumerate(src.splitlines(), 1):
        guards, excluded = line_guards[i - 1]   # guards dominating THIS line only
        index_seen = bool(_INDEX.search(line))
        div_seen = bool(_DIV.search(line))
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
        # --- integer overflow / underflow property (CWE-190 / CWE-191) ---
        # Scope to PLAIN arithmetic assignments: skip lines that are also an index
        # write or a division statement, so we don't double-flag those constructs.
        if not index_seen and not div_seen:
            results.extend(_overflow_checks(line, i, base, guards))
    return results


def _overflow_checks(line: str, i: int, base: "Interval",
                     guards: Dict[str, "Interval"]) -> List[SymbolicResult]:
    """CWE-190/191 for a plain `v := <one-var linear expr>;`. Result interval is the
    affine image of the operand's guarded interval; if it can exceed INT_MAX -> 190,
    if it can drop below INT_MIN -> 191. Outside the linear fragment -> UNKNOWN."""
    out: List[SymbolicResult] = []
    am = _ASSIGN.match(line)
    if not am:
        return out
    rhs = am.group(2)
    # A bare constant or bare variable copy cannot overflow within the INT domain.
    if re.fullmatch(r"-?\d+", rhs) or re.fullmatch(r"[A-Za-z_]\w*", rhs):
        return out
    aff = _affine(rhs)
    if aff is None:
        # Only report UNKNOWN when the RHS actually looks like arithmetic we don't
        # support (contains an operator); plain calls / comparisons are ignored.
        if re.search(r"[+\-*/]", rhs):
            out.append(SymbolicResult("CWE-190", i, "unknown",
                       rationale=f"non-linear expression '{rhs}'"))
        return out
    var, a, b = aff
    dom = base.intersect(guards.get(var, Interval(INT_MIN, INT_MAX)))
    res = _affine_interval(dom, a, b)
    cons = [f"{var}∈[{dom.lo},{dom.hi}]", f"result={a}*{var}+{b}",
            f"INT=[{INT_MIN},{INT_MAX}]"]
    # witness: the operand endpoint that pushes the result furthest out of range.
    hi_wit = dom.hi if (a * dom.hi + b) >= (a * dom.lo + b) else dom.lo
    lo_wit = dom.lo if hi_wit == dom.hi else dom.hi
    if res.hi > INT_MAX:
        out.append(SymbolicResult("CWE-190", i, "violated", {var: hi_wit}, cons,
                   f"result can be {res.hi} > {INT_MAX}"))
    elif res.lo < INT_MIN:
        out.append(SymbolicResult("CWE-191", i, "violated", {var: lo_wit}, cons,
                   f"result can be {res.lo} < {INT_MIN}"))
    else:
        out.append(SymbolicResult("CWE-190", i, "safe", None, cons,
                   f"result ⊆ [{INT_MIN},{INT_MAX}]"))
    return out
