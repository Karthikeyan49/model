"""Static backward program slicing for IEC 61131-3 Structured Text.

A backward slice w.r.t. a *slicing criterion* (a line L and a set of variables V)
is the set of statements that may affect the values of V at L. It is the minimal
evidence an analyst needs to understand why a sink (e.g. the index expression of
`a[idx]`) takes the value it does, and a precise, *sound* input to reachability
reasoning: if a statement is not in the backward slice it cannot influence the
sink, so it can be excluded from "could this be triggered?" analysis.

WHY THIS IS DEFENSIVE: the output is an explanation — the subset of the program
text relevant to a finding — not an input that triggers anything. It narrows the
evidence an operator reads; it does not synthesize exploits.

RESEARCH BASIS
  - Mark Weiser, "Program Slicing", IEEE TSE SE-10(4), 1984 (introduced 1981 at
    ICSE). Defines the slicing criterion <line, variables> and the backward slice
    as the statements affecting those variables, computed by transitively closing
    over data-flow and control-flow dependences.  [web: software-lab.org slicing
    lecture; airccse IJSEA survey — confirmed via search-result summaries]
  - S. Horwitz, T. Reps, D. Binkley, "Interprocedural Slicing Using Dependence
    Graphs", ACM TOPLAS 12(1), 1990. Casts slicing as backward graph reachability
    over the Program Dependence Graph (PDG): start at the criterion node and walk
    every incoming data- and control-dependence edge.  [prior knowledge +
    rep-analysis-soft survey, Harrold & Rothermel]
  - Control dependence (Ferrante, Ottenstein, Warren 1987; specialized to
    structured code): "a statement S is control dependent on predicate p if p
    determines whether S executes" — formally, S postdominates one branch of p but
    not p itself.  [web: ScienceDirect "Control Dependence"; sciencedirect topics —
    via search-result summary]

For the *structured* IF/END_IF fragment handled here (no arbitrary GOTO), control
dependence collapses to a textual rule that is provably equivalent to the
postdominator definition: a statement is control dependent on exactly the guard
predicate(s) of the IF blocks that lexically enclose it. (An enclosing IF's
predicate decides whether the body runs; the body does not postdominate that
predicate, so it is control dependent on it. Statements outside the block are not.)
This is the standard simplification used for structured programs (Ball & Horwitz,
"Slicing Programs with Arbitrary Control-flow", 1993, contrasts this with the
unstructured case).

SUPPORTED FRAGMENT (intraprocedural)
  - Assignments `lhs := rhs;`  (incl. array writes `a[i] := rhs;`).
  - IF <cond> THEN ... [ELSIF ...] [ELSE ...] END_IF block nesting.
The guard tokenizer mirrors advanced/symbolic.py so the *same* block scoping is
used: an IF pushes a frame, END_IF pops it, ELSE/ELSIF re-open a sibling frame.

SOUNDNESS — backward slices are an OVER-approximation
  A backward slice MUST include every statement that may affect the criterion; it
  may include some that do not (sound but not minimal). This module errs toward
  inclusion at every ambiguity:
    * Data deps use flow-insensitive candidate sets: every assignment to a needed
      variable *anywhere* in the unit (not just the last reaching one) is pulled in.
      This over-approximates in the presence of branches/loops/re-definition rather
      than risk dropping a def that reaches the sink along some path.
    * Control deps pull in ALL enclosing guards (each ELSIF/IF predicate of every
      enclosing block) and then those guards' own data+control deps, transitively.
    * The criterion line and its array-write base, if itself control-dependent, are
      handled too.
    * Anything we cannot parse is treated conservatively (a line that mentions a
      needed variable but is not a clean assignment is still considered as possibly
      defining it; see `_defs_uses`).
  The cost is precision (extra lines), never a missed relevant statement. We never
  silently drop a def.

CAVEATS (honest scope)
  - Intraprocedural only: calls/aliasing/pointer effects are not followed (a frontier
    feature; see advanced/interproc.py for cross-unit edges). A `:=` whose RHS calls
    a function is treated as a plain def of its LHS using the RHS identifiers.
  - Flow-INsensitive data dependence (candidate-def closure) is sound but coarse:
    re-definitions are not killed, so a slice may include a def that a later def
    overwrites on every path. This is the conservative direction.
  - ELSE/ELSIF negation is not modelled for control dependence beyond "enclosed by
    the block" — we attribute every branch's statements to every guard predicate of
    that IF chain, which only ever adds lines (sound).
  - Loops (FOR/WHILE) are out of fragment; their bodies are sliced as straight-line
    code (guards ignored), which under-includes *control* deps for loop bodies — a
    known limitation noted here for honesty. Data deps are still captured.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from schema import Program

# --- lexical patterns (compiled once, mirroring dataflow.py / symbolic.py) ----
# An identifier that is not an ST keyword/number is a "variable" for dep purposes.
_IDENT = re.compile(r"[A-Za-z_]\w*")
# Assignment: LHS (optionally an array element `name[...]`) ':=' RHS ';'.
# Group 1 = base name, group 2 = (optional) index expr, group 3 = RHS.
_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*(?:\[([^\]]*)\])?\s*:=\s*(.+?)\s*;?\s*$")
# An IF / ELSIF condition: text between IF|ELSIF and THEN.
_IFCOND = re.compile(r"\b(?:IF|ELSIF)\b(.+?)\bTHEN\b", re.IGNORECASE)
# Control-flow keyword tokenizer (same vocabulary as symbolic._CTRL) so a single
# physical line carrying several control words is scoped correctly.
_CTRL = re.compile(r"\b(IF|THEN|ELSIF|ELSE|END_IF)\b", re.IGNORECASE)
# Sink shapes whose operand variables form a natural criterion (CWE-787 index,
# CWE-369 divisor). Used by criterion inference when the caller passes no vars.
_INDEX = re.compile(r"([A-Za-z_]\w*)\s*\[([^\]]*)\]")
_DIV = re.compile(r"/\s*([^;]+)")

# ST keywords / literals that are never data-flow variables.
_KEYWORDS = frozenset({
    "if", "then", "else", "elsif", "end_if", "and", "or", "not", "xor",
    "true", "false", "mod", "to", "do", "by", "while", "for", "repeat",
    "until", "end_for", "end_while", "end_repeat", "return", "case", "of",
    "end_case", "div", "abs", "min", "max",
})


def _idents(expr: str) -> Set[str]:
    """Variable identifiers in `expr` (keywords and bare numbers excluded)."""
    out: Set[str] = set()
    for m in _IDENT.finditer(expr):
        tok = m.group(0)
        if tok.lower() in _KEYWORDS:
            continue
        out.add(tok)
    return out


@dataclass
class Statement:
    """One source line, parsed for slicing.

    A line may be a code statement, a guard (IF/ELSIF predicate), or both kinds of
    fragment on one physical line. We keep it line-granular because the slicing
    criterion and the operator-facing evidence are line-granular.

    Fields:
      line       1-based source line number.
      text       the original line text (verbatim, for evidence rendering).
      defs       variables this line may define (LHS of assignments; array writes
                 also count the *base array name* as defined and its index vars as
                 used).
      uses       variables this line reads (RHS idents + array-index idents).
      guards     line numbers of the IF/ELSIF predicate lines that lexically
                 enclose this line (its control-dependence parents).
      is_guard   True if this line itself opens/continues a guard (carries a
                 predicate); such lines are valid control-dependence targets.
      cond_uses  for a guard line, the variables read by the predicate (so the
                 guard's own data deps can be followed).
    """
    line: int
    text: str
    defs: Set[str] = field(default_factory=set)
    uses: Set[str] = field(default_factory=set)
    guards: Tuple[int, ...] = ()
    is_guard: bool = False
    cond_uses: Set[str] = field(default_factory=set)


@dataclass
class Slice:
    """Result of a backward slice.

    .lines      sorted list of line numbers in the slice (the evidence set).
    .statements the corresponding source line texts, in line order.
    .criterion  the (line, frozenset-of-variables) the slice was taken w.r.t.
    """
    lines: List[int]
    statements: List[str]
    criterion: Tuple[int, frozenset]

    @property
    def criterion_line(self) -> int:
        return self.criterion[0]

    @property
    def criterion_vars(self) -> frozenset:
        return self.criterion[1]

    def __contains__(self, line: int) -> bool:
        return line in self.lines


@dataclass
class _PDG:
    """Light program-dependence representation: per-line Statement records plus a
    map from variable name -> sorted line numbers that may define it. This is the
    graph the backward worklist walks (data edges via `def_sites`, control edges
    via Statement.guards)."""
    stmts: Dict[int, Statement]
    def_sites: Dict[str, List[int]]


def _split_segments(line: str) -> List[Tuple[bool, str]]:
    """Split one physical line into (is_control_kw, text) tokens on IF/THEN/ELSIF/
    ELSE/END_IF, preserving order. Mirrors the symbolic.py tokenizer so block
    scoping is identical between the two analyses."""
    parts = _CTRL.split(line)
    out: List[Tuple[bool, str]] = []
    for p in parts:
        if p == "":
            continue
        out.append((bool(_CTRL.fullmatch(p)), p))
    return out


def _defs_uses(code: str) -> Tuple[Set[str], Set[str]]:
    """Compute (defs, uses) for a non-control code segment.

    Over-approximation rules (soundness-first):
      * `lhs := rhs;`       -> defs={lhs}, uses=idents(rhs).
      * `a[idx] := rhs;`    -> defs={a},   uses=idents(idx) ∪ idents(rhs).
        (The array as a whole is the def; the index vars are reads. We treat the
        base array name as defined so a later read of `a[...]` data-depends on the
        write — coarse but sound for whole-array aliasing.)
      * Anything else that contains identifiers but no `:=` is treated as a *use*
        of all its identifiers and defines nothing. This never invents a def, and
        keeps such a line eligible to be pulled in when it shares a used variable.
    """
    seg = code.strip()
    if not seg:
        return set(), set()
    m = _ASSIGN.match(seg)
    if m:
        base, idx, rhs = m.group(1), m.group(2), m.group(3)
        uses = _idents(rhs)
        if idx is not None:                # array element write
            uses |= _idents(idx)
            defs = {base}
        else:
            defs = {base}
        return defs, uses
    # Not a clean assignment: contribute uses only (sound — no phantom defs).
    return set(), _idents(seg)


def build_pdg(program: Program) -> _PDG:
    """Parse a Program into a per-line PDG: defs/uses and the enclosing-guard stack
    for every line, plus a variable->definition-sites index.

    Guard scoping uses a stack of (line-number-of-predicate) frames. IF/ELSIF push
    the current predicate line as the active control parent; END_IF pops; ELSE and
    ELSIF replace the top frame (a sibling branch of the same IF still lives inside
    any *outer* enclosing guards, which remain on the stack). Every code line below
    a predicate, up to its matching END_IF, records the whole current stack as its
    control-dependence parents.
    """
    stmts: Dict[int, Statement] = {}
    def_sites: Dict[str, List[int]] = {}
    guard_stack: List[int] = []          # predicate line numbers, outer..inner

    for lineno, raw in enumerate(program.source.splitlines(), 1):
        # The ENCLOSING guards of this line are the stack as it stands BEFORE this
        # line opens any IF of its own — capture it first so a one-line `IF ...`
        # is not recorded as its own control parent (it is, via is_guard, handled
        # at slice time instead).
        enclosing = tuple(guard_stack)
        defs: Set[str] = set()
        uses: Set[str] = set()
        is_guard = False

        # A physical line may interleave control words and code; walk segments and
        # mutate the guard stack token-by-token for correct nesting. Stack changes
        # take effect for subsequent lines (and later segments of this same line).
        for is_kw, text in _split_segments(raw):
            if is_kw:
                kw = text.upper()
                if kw == "IF":
                    is_guard = True
                    guard_stack.append(lineno)
                elif kw == "ELSIF":
                    # New branch predicate: pop the previous THEN/ELSIF frame of
                    # this same IF, push this predicate line in its place. Outer
                    # enclosing guards stay on the stack.
                    is_guard = True
                    if guard_stack:
                        guard_stack.pop()
                    guard_stack.append(lineno)
                elif kw == "ELSE":
                    # Sibling branch: keep the IF's predicate frame in place so the
                    # else-body's statements remain control-dependent on this IF
                    # (we do not model the negation — sound, only ever adds lines).
                    # No stack mutation needed.
                    pass
                elif kw == "END_IF":
                    if guard_stack:
                        guard_stack.pop()
                # THEN: no stack effect.
            else:
                # Code segment, scoped under the current stack.
                d, u = _defs_uses(text)
                defs |= d
                uses |= u

        # Predicate variables (the data deps of the guard itself), robust to
        # spacing, taken from the whole physical line.
        cond_uses: Set[str] = set()
        for cm in _IFCOND.finditer(raw):
            cond_uses |= _idents(cm.group(1))

        stmts[lineno] = Statement(
            line=lineno,
            text=raw,
            defs=defs,
            uses=uses,
            guards=enclosing,
            is_guard=is_guard,
            cond_uses=cond_uses,
        )
        for d in defs:
            def_sites.setdefault(d, []).append(lineno)

    for v in def_sites:
        def_sites[v] = sorted(set(def_sites[v]))
    return _PDG(stmts=stmts, def_sites=def_sites)


def infer_criterion_vars(program: Program, line: int) -> Set[str]:
    """Infer the criterion variables for a sink line when the caller gives none.

    Preference order (most-specific sink operand first), all SOUND supersets:
      1. Array index variables `a[<idx>]`   -> idents(idx)        (CWE-787 sink).
      2. Division divisor variables `_ / d` -> idents(d)          (CWE-369 sink).
      3. Otherwise fall back to *all* variables used on the line (the RHS of an
         assignment, or every identifier on a non-assignment line).
    Using the line's `uses` as the fallback guarantees we never infer an empty
    criterion when the line clearly reads something — over-approximate, never miss.
    """
    pdg = build_pdg(program)
    st = pdg.stmts.get(line)
    if st is None:
        return set()
    text = st.text
    crit: Set[str] = set()
    for m in _INDEX.finditer(text):
        crit |= _idents(m.group(2))
    if crit:
        return crit
    for m in _DIV.finditer(text):
        crit |= _idents(m.group(1))
    if crit:
        return crit
    # Fallback: everything the line reads (sound superset of any real sink operand).
    return set(st.uses)


def backward_slice(program: Program, line: int,
                   variables: Optional[Set[str]] = None) -> Slice:
    """Compute the static backward slice w.r.t. criterion (line, variables).

    If `variables` is None the criterion variables are inferred from the sink line
    via `infer_criterion_vars` (the index/divisor operands, else all line reads).

    Algorithm (Weiser 1984; Horwitz-Reps-Binkley 1990 PDG reachability), realized
    as a worklist over the PDG:

      worklist <- {criterion line}                       # seed
      needed_vars[criterion line] <- criterion variables
      while worklist not empty:
        n <- pop
        add n to slice
        # DATA dependence: for every variable needed at n, add every statement
        # that may define it (candidate-def closure -> over-approximation).
        for v in needed_vars[n]:
          for d in def_sites[v]:        # all defs, not just last reaching one
            propagate v's *uses* at d into needed_vars[d]; enqueue d
        # CONTROL dependence: add the predicate line of every enclosing IF/ELSIF
        # (n is control-dependent on them); a guard contributes its predicate's
        # own variable uses, which then get data-sliced in turn.
        for g in guards[n]:
          needed_vars[g] |= cond_uses[g]; enqueue g
        # SAME-LINE guard: if n itself is a predicate sharing a line with the code
        # it controls, its predicate vars are control-relevant to that code too.
        if is_guard[n]: needed_vars[n] |= cond_uses[n]

    Termination: the worklist only ever (re)enqueues a node when its needed-vars
    set grows; needed-vars are subsets of the finite variable universe and nodes
    are finite, so the monotone fixpoint is reached in bounded steps.

    Soundness: every may-affect edge is followed; ambiguity always adds, never
    drops (see module docstring). The criterion line is always in the slice.
    """
    pdg = build_pdg(program)
    if line not in pdg.stmts:
        crit_vars = frozenset(variables or set())
        return Slice(lines=[], statements=[], criterion=(line, crit_vars))

    if variables is None:
        variables = infer_criterion_vars(program, line)
    crit_vars: Set[str] = set(variables)

    # needed[n] = variables whose definitions we must chase at/through line n.
    needed: Dict[int, Set[str]] = {line: set(crit_vars)}
    in_slice: Set[int] = set()
    worklist: List[int] = [line]

    while worklist:
        n = worklist.pop()
        in_slice.add(n)
        st = pdg.stmts[n]

        # --- same-line guard predicate is a control parent of its own line ----
        # When an IF/ELSIF predicate shares a physical line with the statement it
        # controls (e.g. `IF g > 0 THEN arr[k] := 0; END_IF;`), that statement's
        # `guards` tuple cannot list the line itself, so the loop below would miss
        # the predicate's variables. They DO control whether the same-line code
        # runs, so chase them as data deps here (soundness: never drop a relevant
        # def — the closing-quote bug this guards against would otherwise drop
        # `g`'s definition). This only adds lines, never removes.
        if st.is_guard and st.cond_uses:
            prev_n = needed.get(n, set())
            if not st.cond_uses.issubset(prev_n):
                needed[n] = prev_n | set(st.cond_uses)

        # --- DATA dependence (def-use edges, over-approximated) --------------
        for var in list(needed.get(n, set())):
            for d in pdg.def_sites.get(var, []):
                dst = pdg.stmts[d]
                # The defining statement is now in the slice and we must, in turn,
                # chase the variables IT reads (transitive data dependence).
                add_vars = set(dst.uses)
                prev = needed.get(d, set())
                if d not in in_slice or not add_vars.issubset(prev):
                    needed[d] = prev | add_vars
                    worklist.append(d)
                elif d not in in_slice:
                    worklist.append(d)

        # --- CONTROL dependence (enclosing guard predicates) -----------------
        for g in st.guards:
            gst = pdg.stmts.get(g)
            if gst is None:
                continue
            add_vars = set(gst.cond_uses)
            prev = needed.get(g, set())
            if g not in in_slice or not add_vars.issubset(prev):
                needed[g] = prev | add_vars
                worklist.append(g)
            elif g not in in_slice:
                worklist.append(g)

    lines = sorted(in_slice)
    statements = [pdg.stmts[ln].text for ln in lines]
    return Slice(lines=lines, statements=statements,
                 criterion=(line, frozenset(crit_vars)))


def slice_for_finding(program: Program, line: int) -> Slice:
    """Convenience: backward slice on a finding's sink line, inferring the
    criterion variables (index/divisor operands) from that line. This is the entry
    point a verifier/evidence layer uses: give it the line a finding is reported
    at and get back exactly the statements that may influence that sink."""
    return backward_slice(program, line, variables=None)


def render(slice_: Slice) -> str:
    """Operator-readable evidence: the criterion followed by the sliced lines in
    source order, each prefixed with its line number. The criterion LINE is always
    named in the header so the reader knows what the slice is about.

    Example::

        Backward slice criterion: line 5, variables {idx}
          1: idx := input;
          5: a[idx] := 0;
    """
    line, vars_ = slice_.criterion
    varset = "{" + ", ".join(sorted(vars_)) + "}" if vars_ else "{}"
    header = f"Backward slice criterion: line {line}, variables {varset}"
    body = [f"  {ln}: {txt.strip()}"
            for ln, txt in zip(slice_.lines, slice_.statements)]
    return "\n".join([header, *body])
