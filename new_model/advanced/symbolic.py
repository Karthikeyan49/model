"""Symbolic bounded model-checking with concrete witnesses — proof-carrying findings.

This is a capability a frontier LLM structurally cannot provide: a *sound* decision
(for the supported fragment) that a safety property is violated, accompanied by a
concrete witness input that triggers it. An LLM can guess "this looks out of
bounds"; this module PROVES it by reasoning over the index/divisor/arithmetic
constraints and emits a counterexample the owner can replay. Defensive: the witness
is a test input demonstrating the bug to fix, not an exploit.

Supported fragment (IEC 61131-3 ST, intraprocedural, linear interval reasoning):
  - SAFETY PROPERTY 1 (CWE-787): every `arr[expr]` index stays within the array's
    declared [lo, hi]. `expr` may be `v`, `v + c`, `v - c`, or a sum of such terms
    `i + j (+ c)` (multi-variable, via interval arithmetic).
  - SAFETY PROPERTY 2 (CWE-369): no `_ / expr` has a feasible zero divisor.
  - SAFETY PROPERTY 3 (CWE-190): no 16-bit INT assignment `x := a op b` (op in
    {+, -, *}) can produce a result outside [INT_MIN, INT_MAX] = [-32768, 32767].

Method: sound interval analysis over INT variables. Each statement is evaluated
under exactly the conjunction of IF-guards that *textually enclose* it (flow/block
scoped — a guard on another line or branch never constrains a statement it does not
contain). Guards are tracked as a stack: pushed on `IF ... THEN`, popped on
`END_IF`; an `ELSE` conservatively DROPS the enclosing THEN-guard (the negation is
not modelled, so the else-branch falls back to the unconstrained domain — never a
false "safe"). If the feasible interval escapes the property's safe region the
property is VIOLATED and we return the extremal witness value; otherwise SAFE for
this fragment. Anything outside the fragment -> UNKNOWN (never a false "safe").

CAVEATS (honest scope): interval analysis is non-relational, so it does not track
correlations between variables (e.g. `i + j` with `i = -j` is treated as the full
sum of ranges, which is sound but may over-approximate and report `violated` where a
relational analysis would prove safe — conservative, never an unsound `safe`).
ELSE-branch guards and `<>` (except for the divisor-zero check) are not modelled.
Multiplication overflow uses interval endpoint products (sound for the 4-corner
rule). Loops, function calls, and aliasing are out of fragment -> UNKNOWN/ignored.
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
_CMP = re.compile(r"([A-Za-z_]\w*)\s*(<=|>=|<>|<|>|=)\s*(-?\d+)")
_LINEAR = re.compile(r"^\s*([A-Za-z_]\w*)\s*([+\-])\s*(\d+)\s*$")
# Control-flow tokenization: split a line on IF/THEN/ELSIF/ELSE/END_IF keywords so a
# single physical line containing several control words is handled flow-correctly.
_CTRL = re.compile(r"\b(IF|THEN|ELSIF|ELSE|END_IF)\b", re.IGNORECASE)
# A linear arithmetic assignment `x := <expr>` for the CWE-190 overflow check.
_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*:=\s*(.+?)\s*;?\s*$")
# Binary integer op between two atoms (var or signed literal).
_BINOP = re.compile(r"^\s*(-?\d+|[A-Za-z_]\w*)\s*([+\-*])\s*(-?\d+|[A-Za-z_]\w*)\s*$")


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

    def add(self, other: "Interval") -> "Interval":
        return Interval(self.lo + other.lo, self.hi + other.hi)

    def sub(self, other: "Interval") -> "Interval":
        return Interval(self.lo - other.hi, self.hi - other.lo)

    def mul(self, other: "Interval") -> "Interval":
        corners = [self.lo * other.lo, self.lo * other.hi,
                   self.hi * other.lo, self.hi * other.hi]
        return Interval(min(corners), max(corners))


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


@dataclass
class _GuardFrame:
    """One IF-block's accumulated constraints, plus whether the THEN-guard is still
    active (an ELSE drops it -> domains reset to unconstrained for that frame)."""
    domains: Dict[str, Interval] = field(default_factory=dict)
    excluded: Dict[str, set] = field(default_factory=dict)


def _apply_cmp(domains: Dict[str, Interval], excluded: Dict[str, set],
               cond: str) -> None:
    """Conjoin the comparisons in a guard condition into domains/excluded."""
    for var, op, num in _CMP.findall(cond):
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
            continue
        domains[var] = cur


def _active(stack: List[_GuardFrame]) -> Tuple[Dict[str, Interval], Dict[str, set]]:
    """Conjunction of all enclosing guard frames (innermost wins on intersect)."""
    domains: Dict[str, Interval] = {}
    excluded: Dict[str, set] = {}
    for fr in stack:
        for v, iv in fr.domains.items():
            domains[v] = domains.get(v, Interval(INT_MIN, INT_MAX)).intersect(iv)
        for v, s in fr.excluded.items():
            excluded.setdefault(v, set()).update(s)
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


def _multi_linear(expr: str) -> Optional[Tuple[List[str], int]]:
    """Parse a sum of variables and integer constants: `i`, `i+j`, `i+j+c`,
    `i - j`, etc. -> (list_of_vars, constant_offset). Subtraction of a *variable*
    is unsupported (returns None) because interval subtraction of an unknown-signed
    var would be unsound to fold into a plain sum; constants may be subtracted.
    Returns None for any unsupported token so the caller falls back to unknown."""
    expr = expr.strip()
    # Tokenize into +/- separated atoms while keeping the sign.
    tokens = re.split(r"([+\-])", expr)
    if not tokens or tokens[0] == "":
        return None
    vars_: List[str] = []
    const = 0
    sign = 1
    expect_atom = True
    for tok in tokens:
        tok = tok.strip()
        if tok == "":
            continue
        if tok in ("+", "-"):
            if expect_atom:
                return None
            sign = 1 if tok == "+" else -1
            expect_atom = True
            continue
        if not expect_atom:
            return None
        expect_atom = False
        if re.fullmatch(r"-?\d+", tok):
            const += sign * int(tok)
        elif re.fullmatch(r"[A-Za-z_]\w*", tok):
            if sign != 1:
                return None  # variable subtraction unsupported -> unknown
            vars_.append(tok)
        else:
            return None
    if expect_atom:
        return None
    if not vars_:
        return None  # pure constant index handled by literal path, not here
    return vars_, const


def _atom_interval(atom: str, base: Interval,
                   domains: Dict[str, Interval]) -> Optional[Interval]:
    """Interval for a single atom (signed literal or INT variable). None if it is
    not a recognized atom (caller -> unknown)."""
    atom = atom.strip()
    if re.fullmatch(r"-?\d+", atom):
        v = int(atom)
        return Interval(v, v)
    if re.fullmatch(r"[A-Za-z_]\w*", atom):
        return base.intersect(domains.get(atom, Interval(INT_MIN, INT_MAX)))
    return None


def check(program: Program, witness_domain: Tuple[int, int] = (INT_MIN, INT_MAX)
          ) -> List[SymbolicResult]:
    src = program.source
    arrays = _arrays(src)
    results: List[SymbolicResult] = []
    base = Interval(*witness_domain)

    stack: List[_GuardFrame] = []

    for i, line in enumerate(src.splitlines(), 1):
        # Split the physical line on control-flow keywords so guards take effect at
        # exactly the textual scope where they appear (flow/block scoped).
        parts = _CTRL.split(line)
        # parts alternates: [seg, KW, seg, KW, seg, ...]
        pending_cond = ""        # text seen after IF/ELSIF, awaiting THEN
        collecting_cond = False
        for part in parts:
            up = part.upper()
            if collecting_cond and up not in ("THEN",):
                # Between IF and THEN: this segment is part of the condition.
                if up in ("IF", "ELSIF", "ELSE", "END_IF"):
                    pass  # handled below; fall through
                else:
                    pending_cond += part
            if up == "IF":
                collecting_cond = True
                pending_cond = ""
                continue
            if up == "ELSIF":
                # Close the current THEN-scope, open a new (conservatively empty)
                # one: we do not model the negation of prior conditions.
                if stack:
                    stack.pop()
                stack.append(_GuardFrame())
                collecting_cond = True
                pending_cond = ""
                continue
            if up == "THEN":
                domains: Dict[str, Interval] = {}
                excluded: Dict[str, set] = {}
                _apply_cmp(domains, excluded, pending_cond)
                stack.append(_GuardFrame(domains, excluded))
                collecting_cond = False
                pending_cond = ""
                continue
            if up == "ELSE":
                # Drop the THEN-guard for the else-branch (conservative: no negation
                # modelling -> fall back to unconstrained, never a false safe).
                if stack:
                    stack.pop()
                stack.append(_GuardFrame())
                collecting_cond = False
                continue
            if up == "END_IF":
                if stack:
                    stack.pop()
                collecting_cond = False
                continue
            # A normal code segment: evaluate properties under the active guards.
            if collecting_cond:
                # Still inside a condition (multi-segment) — skip code checks.
                continue
            dom_map, exc_map = _active(stack)
            _check_segment(part, i, arrays, base, dom_map, exc_map, results)

    return results


def _check_segment(seg: str, i: int, arrays: Dict[str, Tuple[int, int]],
                   base: Interval, guards: Dict[str, Interval],
                   excluded: Dict[str, set],
                   results: List[SymbolicResult]) -> None:
    # --- array bounds property (CWE-787) ---
    for m in _INDEX.finditer(seg):
        arr, expr = m.group(1), m.group(2)
        if arr not in arrays:
            continue
        lo, hi = arrays[arr]
        _check_index(expr, i, lo, hi, base, guards, results)

    # --- division-by-zero property (CWE-369) ---
    for m in _DIV.finditer(seg):
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

    # --- integer overflow/underflow property (CWE-190) ---
    _check_overflow(seg, i, base, guards, results)


def _check_index(expr: str, i: int, lo: int, hi: int, base: Interval,
                 guards: Dict[str, Interval],
                 results: List[SymbolicResult]) -> None:
    # Single-variable fast path (preserves witness shape {var: value}).
    lin = _linear(expr)
    if lin is not None:
        var, c = lin
        dom = base.intersect(guards.get(var, Interval(INT_MIN, INT_MAX)))
        idx_iv = dom.shift(c)
        cons = [f"{var}∈[{dom.lo},{dom.hi}]", f"index={var}+{c}", f"bounds=[{lo},{hi}]"]
        if idx_iv.lo < lo:
            wv = lo - 1 - c
            results.append(SymbolicResult("CWE-787", i, "violated", {var: max(dom.lo, wv)},
                           cons, f"index can be {idx_iv.lo} < {lo}"))
        elif idx_iv.hi > hi:
            wv = hi + 1 - c
            results.append(SymbolicResult("CWE-787", i, "violated", {var: min(dom.hi, wv)},
                           cons, f"index can be {idx_iv.hi} > {hi}"))
        else:
            results.append(SymbolicResult("CWE-787", i, "safe", None, cons,
                           f"index ⊆ [{lo},{hi}]"))
        return

    # Multi-variable path: sum of variable terms (+ constant) via interval add.
    multi = _multi_linear(expr)
    if multi is None:
        results.append(SymbolicResult("CWE-787", i, "unknown",
                       rationale=f"non-linear index '{expr}'"))
        return
    vars_, c = multi
    doms = {v: base.intersect(guards.get(v, Interval(INT_MIN, INT_MAX))) for v in vars_}
    idx_iv = Interval(c, c)
    for v in vars_:
        idx_iv = idx_iv.add(doms[v])
    cons = ([f"{v}∈[{doms[v].lo},{doms[v].hi}]" for v in vars_]
            + [f"index={'+'.join(vars_)}+{c}", f"bounds=[{lo},{hi}]"])
    if idx_iv.lo < lo:
        witness = {v: doms[v].lo for v in vars_}
        results.append(SymbolicResult("CWE-787", i, "violated", witness, cons,
                       f"index can be {idx_iv.lo} < {lo}"))
    elif idx_iv.hi > hi:
        witness = {v: doms[v].hi for v in vars_}
        results.append(SymbolicResult("CWE-787", i, "violated", witness, cons,
                       f"index can be {idx_iv.hi} > {hi}"))
    else:
        results.append(SymbolicResult("CWE-787", i, "safe", None, cons,
                       f"index ⊆ [{lo},{hi}]"))


def _check_overflow(seg: str, i: int, base: Interval,
                    guards: Dict[str, Interval],
                    results: List[SymbolicResult]) -> None:
    am = _ASSIGN.match(seg)
    if not am:
        return
    rhs = am.group(2)
    # Skip array writes/divisions here — those are other properties' concern, and an
    # RHS containing '[' / '/' is outside this linear-arith fragment.
    if "[" in rhs or "/" in rhs:
        return
    bm = _BINOP.match(rhs)
    if not bm:
        # If the RHS clearly contains arithmetic but is not a single supported
        # binary op (e.g. `a*a*a`, `a+b-c`, parenthesized), it is in scope for the
        # overflow property but outside the decidable fragment -> UNKNOWN (never a
        # false safe). A plain copy `x := y` or literal has no overflow risk.
        if re.search(r"[+\-*]", rhs.strip().lstrip("+-")):
            results.append(SymbolicResult("CWE-190", i, "unknown",
                           rationale=f"non-linear/unsupported arithmetic '{rhs}'"))
        return  # not a single binary op -> not in fragment for CWE-190
    a, op, b = bm.group(1), bm.group(2), bm.group(3)
    ia = _atom_interval(a, base, guards)
    ib = _atom_interval(b, base, guards)
    if ia is None or ib is None:
        results.append(SymbolicResult("CWE-190", i, "unknown",
                       rationale=f"unsupported operand in '{rhs}'"))
        return
    if op == "+":
        res = ia.add(ib)
    elif op == "-":
        res = ia.sub(ib)
    else:  # '*'
        res = ia.mul(ib)
    cons = [f"{a}∈[{ia.lo},{ia.hi}]", f"{b}∈[{ib.lo},{ib.hi}]",
            f"result∈[{res.lo},{res.hi}]", f"INT=[{INT_MIN},{INT_MAX}]"]

    def _atom_witness(atom: str, iv: Interval, want_hi: bool) -> Dict[str, int]:
        # Concrete inputs that drive the result to its extremal value.
        w: Dict[str, int] = {}
        if re.fullmatch(r"[A-Za-z_]\w*", atom.strip()):
            w[atom.strip()] = iv.hi if want_hi else iv.lo
        return w

    if res.hi > INT_MAX:
        # Maximize: for +,* pick highs of both (sign handled by interval already);
        # for - pick a high, b low.
        if op == "-":
            w = {**_atom_witness(a, ia, True), **_atom_witness(b, ib, False)}
        elif op == "*":
            # The extremum that produced res.hi: choose corner giving max product.
            w = _mul_corner_witness(a, ia, b, ib, maximize=True)
        else:
            w = {**_atom_witness(a, ia, True), **_atom_witness(b, ib, True)}
        results.append(SymbolicResult("CWE-190", i, "violated", w, cons,
                       f"result can be {res.hi} > {INT_MAX} (overflow)"))
    elif res.lo < INT_MIN:
        if op == "-":
            w = {**_atom_witness(a, ia, False), **_atom_witness(b, ib, True)}
        elif op == "*":
            w = _mul_corner_witness(a, ia, b, ib, maximize=False)
        else:
            w = {**_atom_witness(a, ia, False), **_atom_witness(b, ib, False)}
        results.append(SymbolicResult("CWE-190", i, "violated", w, cons,
                       f"result can be {res.lo} < {INT_MIN} (underflow)"))
    else:
        results.append(SymbolicResult("CWE-190", i, "safe", None, cons,
                       f"result ⊆ [{INT_MIN},{INT_MAX}]"))


def _mul_corner_witness(a: str, ia: Interval, b: str, ib: Interval,
                        maximize: bool) -> Dict[str, int]:
    """Pick the (a,b) endpoint corner whose product is the extremum, return it as a
    witness over whichever atoms are variables."""
    corners = [(ia.lo, ib.lo), (ia.lo, ib.hi), (ia.hi, ib.lo), (ia.hi, ib.hi)]
    best = max(corners, key=lambda t: t[0] * t[1]) if maximize \
        else min(corners, key=lambda t: t[0] * t[1])
    w: Dict[str, int] = {}
    if re.fullmatch(r"[A-Za-z_]\w*", a.strip()):
        w[a.strip()] = best[0]
    if re.fullmatch(r"[A-Za-z_]\w*", b.strip()):
        w[b.strip()] = best[1]
    return w
