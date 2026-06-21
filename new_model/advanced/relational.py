"""Relational (octagon / difference-bound) refinement of the symbolic checker.

The interval (box) domain in ``symbolic.py`` is *non-relational*: it tracks one
range per variable and loses every correlation *between* variables. For a
multi-variable array index ``a[i+j]`` it must add the full ranges of ``i`` and
``j``, so a guard such as ``IF i+j <= 9 THEN ...`` — which bounds the *sum* but
neither operand alone — cannot be exploited, and a genuinely-safe access is
over-approximated to ``violated`` (a false positive). ``symbolic.py`` documents
exactly this caveat:

    "interval analysis is non-relational, so it does not track correlations
    between variables (e.g. ``i + j`` with ``i = -j`` is treated as the full sum
    of ranges, which is sound but may over-approximate and report ``violated``
    where a relational analysis would prove safe — conservative, never an
    unsound ``safe``)."

This module is the complementary RELATIONAL refinement that removes *those
specific* false positives, and ONLY those, soundly.

CONCEPT — a lightweight octagon / difference-bound abstract domain.
  The octagon domain (Miné 2006, "The Octagon Abstract Domain", Higher-Order and
  Symbolic Computation 19(1):31-100; arXiv:cs/0703084; HAL hal-00136639) tracks
  conjunctions of constraints of the restricted form  (±x ±y <= c)  — strictly
  more expressive than intervals (which are only the unary  ±x <= c  facets) and
  strictly cheaper/less precise than general polyhedra. Per the paper, octagons
  are encoded in a Difference-Bound Matrix (DBM) by *splitting* each variable V
  into a positive form V+ and a negative form V- (so a binary octagon constraint
  becomes a single difference constraint over the doubled variable set), and a
  Floyd-Warshall-style *strong closure* propagates the constraints to their
  tightest sound form. We do not need the full O(n^3) closure for the one query
  this refinement makes ("what is the tightest interval for v1+v2?"), so we
  implement a small, targeted constraint store with exactly the derivations that
  query needs (a sound under-set of closure — see SOUNDNESS below).

WHAT WE PARSE (re-extracted from the program source, so refine() is self
contained, mirroring symbolic.py's block-scoping idea — ONLY guards that
*textually enclose* the indexed statement contribute). Supported guard atoms,
each a facet of an octagon constraint:
    v1 + v2 <= c      v1 + v2 >= c        (binary upper / lower sum bound)
    v1 - v2 <= c      v1 - v2 >= c        (binary difference bound)
    v1 <= c   v1 >= c   v1 = c            (unary / interval facets)
    v1 = v2   v1 = -v2                    (equalities: each is two <= facets)

SOUNDNESS (this is the whole point — the refinement may only ever turn a
``violated`` into ``safe`` when it can PROVE the index in-bounds):
  * Every supported guard atom is an over-approximation of the concrete set of
    states reaching the statement (it is a *necessary* condition: the program
    actually tested it and took the THEN branch), so the conjunction we build is
    a sound over-approximation of the reachable states at that point.
  * ``bound_sum`` returns an interval that PROVABLY contains v1+v2 in every such
    reachable state (it is derived only by adding/intersecting constraints that
    are individually entailed — never by assuming an unproven correlation). If it
    cannot tighten past the box bound it returns ``None`` and we change nothing.
  * We DOWNGRADE a CWE-787 ``violated`` to ``safe`` only when that proven
    super-interval for the index is itself a subset of the array's declared
    ``[lo, hi]``. If the proven interval is *not* a subset — even by one — we
    leave the result UNCHANGED. We therefore can only *remove* a false positive;
    we can never introduce a false ``safe``. A real out-of-bounds access has no
    enclosing relation that bounds it inside ``[lo, hi]`` (otherwise it would not
    be out of bounds), so it is provably left ``violated``.
  * Anything we cannot parse or cannot prove is left exactly as the (sound) box
    analysis produced it. Refinement is monotone toward precision only.

CAVEATS (honest scope): we only refine multi-variable CWE-787 sum indices
``a[v1+v2(+c)]`` (the documented box false-positive class). Single-variable
indices, other CWEs, ``unknown`` and ``safe`` results, and indices with three or
more variables or variable subtraction are passed through untouched. ELSE-branch
negation is not modelled (matching symbolic.py); guards reached only through an
ELSE contribute nothing, which is sound (it can only keep a result ``violated``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import symbolic
from symbolic import INT_MAX, INT_MIN, Interval, SymbolicResult

# --- compiled patterns (style mirrors symbolic.py) ---------------------------

# Reuse symbolic.py's array-declaration shape so bounds parsing is identical.
_ARRAY_DECL = re.compile(
    r"([A-Za-z_]\w*)\s*:\s*ARRAY\s*\[\s*(-?\d+)\s*\.\.\s*(-?\d+)\s*\]",
    re.IGNORECASE)
_INDEX = re.compile(r"([A-Za-z_]\w*)\s*\[\s*([^\]]+?)\s*\]")
# Control-flow tokenization (same keyword set / intent as symbolic.py).
_CTRL = re.compile(r"\b(IF|THEN|ELSIF|ELSE|END_IF)\b", re.IGNORECASE)
# Split a guard condition into its AND-conjoined atoms (we model only AND).
_AND = re.compile(r"\bAND\b", re.IGNORECASE)

_VAR = r"[A-Za-z_]\w*"
# Binary octagon facets:  v1 + v2 OP c   and   v1 - v2 OP c
_BIN_SUM = re.compile(
    rf"^\s*({_VAR})\s*\+\s*({_VAR})\s*(<=|>=|=)\s*(-?\d+)\s*$")
_BIN_DIFF = re.compile(
    rf"^\s*({_VAR})\s*-\s*({_VAR})\s*(<=|>=|=)\s*(-?\d+)\s*$")
# Unary facets:  v OP c
_UNARY = re.compile(rf"^\s*({_VAR})\s*(<=|>=|=)\s*(-?\d+)\s*$")
# Variable equalities:  v1 = v2   and   v1 = -v2
_EQ_VAR = re.compile(rf"^\s*({_VAR})\s*=\s*({_VAR})\s*$")
_EQ_NEG = re.compile(rf"^\s*({_VAR})\s*=\s*-\s*({_VAR})\s*$")
# Multi-variable sum index  v1 + v2 (+ ... ) (+ c): reuse symbolic.py's parser.
_multi_linear = symbolic._multi_linear  # noqa: SLF001  (intentional reuse)


# --- octagon / DBM-style constraint store ------------------------------------

@dataclass
class Octagon:
    """A tiny relational store of octagon constraints over a fixed variable set.

    Per Miné 2006 an octagon is a conjunction of facets ``(±x ±y <= c)`` encoded
    in a difference-bound matrix over the *doubled* variable set ``{x+, x-}``.
    We keep the same information in three dictionaries (each holding the tightest
    upper bound seen, i.e. an intersection of facets):

      * ``ub[v]``           : upper bound for  v        (facet ``+v <= c``)
      * ``lb[v]``           : lower bound for  v        (facet ``-v <= -c``)
      * ``sum_ub[(a,b)]``   : upper bound for  a + b    (facet ``+a +b <= c``)
      * ``sum_lb[(a,b)]``   : lower bound for  a + b    (facet ``-a -b <= -c``)
      * ``diff_ub[(a,b)]``  : upper bound for  a - b    (facet ``+a -b <= c``)

    Pair keys are stored canonically (sorted) for the symmetric sum facet and as
    an ordered pair for the antisymmetric difference facet. ``add_*`` always
    keeps the *tighter* of the existing and the new bound (closure never loosens
    a constraint — it only tightens — so taking ``min`` of upper bounds and
    ``max`` of lower bounds is sound).
    """
    ub: Dict[str, int] = field(default_factory=dict)
    lb: Dict[str, int] = field(default_factory=dict)
    sum_ub: Dict[Tuple[str, str], int] = field(default_factory=dict)
    sum_lb: Dict[Tuple[str, str], int] = field(default_factory=dict)
    diff_ub: Dict[Tuple[str, str], int] = field(default_factory=dict)

    @staticmethod
    def _key(a: str, b: str) -> Tuple[str, str]:
        return (a, b) if a <= b else (b, a)

    def add_ub(self, v: str, c: int) -> None:
        self.ub[v] = min(self.ub.get(v, c), c)

    def add_lb(self, v: str, c: int) -> None:
        self.lb[v] = max(self.lb.get(v, c), c)

    def add_sum_ub(self, a: str, b: str, c: int) -> None:
        k = self._key(a, b)
        self.sum_ub[k] = min(self.sum_ub.get(k, c), c)

    def add_sum_lb(self, a: str, b: str, c: int) -> None:
        k = self._key(a, b)
        self.sum_lb[k] = max(self.sum_lb.get(k, c), c)

    def add_diff_ub(self, a: str, b: str, c: int) -> None:
        # a - b <= c
        self.diff_ub[(a, b)] = min(self.diff_ub.get((a, b), c), c)

    def add_diff_lb(self, a: str, b: str, c: int) -> None:
        # a - b >= c   <=>   b - a <= -c
        self.add_diff_ub(b, a, -c)


def _add_atom(oct_: Octagon, atom: str) -> None:
    """Conjoin one supported guard atom into the octagon store.

    Each atom is a *necessary* condition for reaching the THEN branch, so adding
    it (intersection) keeps the store a sound over-approximation of the reachable
    states. Unsupported atoms are ignored (sound: fewer constraints can only
    keep a result ``violated``, never make a false ``safe``).
    """
    atom = atom.strip()

    m = _BIN_SUM.match(atom)
    if m:
        a, b, op, c = m.group(1), m.group(2), m.group(3), int(m.group(4))
        if op in ("<=", "="):
            oct_.add_sum_ub(a, b, c)
        if op in (">=", "="):
            oct_.add_sum_lb(a, b, c)
        return

    m = _BIN_DIFF.match(atom)
    if m:
        a, b, op, c = m.group(1), m.group(2), m.group(3), int(m.group(4))
        if op in ("<=", "="):
            oct_.add_diff_ub(a, b, c)
        if op in (">=", "="):
            oct_.add_diff_lb(a, b, c)
        return

    m = _EQ_NEG.match(atom)        # v1 = -v2  <=>  v1 + v2 = 0   (try before _UNARY)
    if m:
        a, b = m.group(1), m.group(2)
        oct_.add_sum_ub(a, b, 0)
        oct_.add_sum_lb(a, b, 0)
        return

    m = _EQ_VAR.match(atom)        # v1 = v2  <=>  v1 - v2 = 0
    if m:
        a, b = m.group(1), m.group(2)
        oct_.add_diff_ub(a, b, 0)
        oct_.add_diff_lb(a, b, 0)
        return

    m = _UNARY.match(atom)
    if m:
        v, op, c = m.group(1), m.group(2), int(m.group(3))
        if op in ("<=", "="):
            oct_.add_ub(v, c)
        if op in (">=", "="):
            oct_.add_lb(v, c)
        return
    # Anything else (ranges with arithmetic on both sides, <, >, <>, 3-var, ...)
    # is intentionally not modelled here -> contributes no constraint.


def parse_constraints(cond: str) -> Octagon:
    """Parse one guard condition (a conjunction of AND-separated atoms) into an
    octagon store. Only AND is modelled; an OR or any unparsed atom simply
    contributes nothing (sound under-approximation of the constraint set)."""
    oct_ = Octagon()
    for atom in _AND.split(cond):
        _add_atom(oct_, atom)
    return oct_


def _merge(into: Octagon, other: Octagon) -> None:
    """Conjoin ``other`` into ``into`` (intersection of constraint sets)."""
    for v, c in other.ub.items():
        into.add_ub(v, c)
    for v, c in other.lb.items():
        into.add_lb(v, c)
    for (a, b), c in other.sum_ub.items():
        into.add_sum_ub(a, b, c)
    for (a, b), c in other.sum_lb.items():
        into.add_sum_lb(a, b, c)
    for (a, b), c in other.diff_ub.items():
        into.add_diff_ub(a, b, c)


# --- the relational query ----------------------------------------------------

def bound_sum(oct_: Octagon, v1: str, v2: str,
              box: Optional[Tuple[Interval, Interval]] = None) -> Optional[Interval]:
    """Tightest SOUND interval for ``v1 + v2`` derivable from the octagon.

    Derivation paths (each step is a sound octagon/DBM closure inference — it
    only ever tightens, never invents a bound; cf. Miné 2006 strong closure):

      1. Direct binary facet:           sum_ub[(v1,v2)] / sum_lb[(v1,v2)].
      2. Unary facets added:            ub[v1]+ub[v2]  (and lb+lb), i.e. the box
         bound — used as a baseline and to tighten paths 1 and 3.
      3. Difference + unary closure:    if ``v1 - v2 <= d`` and ``v2 <= u`` then
         ``v1 + v2 = (v1 - v2) + 2*v2 <= d + 2*u`` (and the symmetric lower
         bound). This is the Floyd-Warshall-style combination of a binary and a
         unary facet through the doubled variable v2+/v2-.

    The result interval is the INTERSECTION of every bound we can prove, so it is
    the tightest sound enclosure available from these paths. Returns ``None``
    when the proven enclosure is no tighter than the supplied ``box`` (or no box
    was supplied and nothing relational was derivable) — meaning the relational
    domain adds nothing and the caller must not change the box verdict.

    ``box`` (optional) is ``(interval_v1, interval_v2)`` from the box analysis;
    when given, its endpoints seed the unary facets so relational and box facts
    are combined, and it defines the "did we actually tighten?" baseline.
    """
    k = Octagon._key(v1, v2)

    # Seed unary bounds from the supplied box (box facts are themselves sound).
    ub: Dict[str, int] = dict(oct_.ub)
    lb: Dict[str, int] = dict(oct_.lb)
    if box is not None:
        b1, b2 = box
        for v, iv in ((v1, b1), (v2, b2)):
            ub[v] = min(ub.get(v, iv.hi), iv.hi)
            lb[v] = max(lb.get(v, iv.lo), iv.lo)

    upper_candidates: List[int] = []
    lower_candidates: List[int] = []

    # Path 1: direct binary sum facet.
    if k in oct_.sum_ub:
        upper_candidates.append(oct_.sum_ub[k])
    if k in oct_.sum_lb:
        lower_candidates.append(oct_.sum_lb[k])

    # Path 2: sum of unary bounds (the box bound, restated relationally).
    if v1 in ub and v2 in ub:
        upper_candidates.append(ub[v1] + ub[v2])
    if v1 in lb and v2 in lb:
        lower_candidates.append(lb[v1] + lb[v2])

    # Path 3: difference facet closed with a unary facet on the subtrahend.
    #   v1 - v2 <= d  and  v2 <= u   =>  v1 + v2 <= d + 2u
    #   v1 - v2 >= d  and  v2 >= l   =>  v1 + v2 >= d + 2l
    if (v1, v2) in oct_.diff_ub and v2 in ub:
        upper_candidates.append(oct_.diff_ub[(v1, v2)] + 2 * ub[v2])
    if (v2, v1) in oct_.diff_ub and v1 in ub:        # v2 - v1 <= d'  symmetric
        upper_candidates.append(oct_.diff_ub[(v2, v1)] + 2 * ub[v1])
    # Lower via the reversed difference: v2 - v1 <= d' => v1 - v2 >= -d'.
    if (v2, v1) in oct_.diff_ub and v2 in lb:
        lower_candidates.append(-oct_.diff_ub[(v2, v1)] + 2 * lb[v2])
    if (v1, v2) in oct_.diff_ub and v1 in lb:
        lower_candidates.append(-oct_.diff_ub[(v1, v2)] + 2 * lb[v1])

    if not upper_candidates and not lower_candidates:
        return None

    hi = min(upper_candidates) if upper_candidates else INT_MAX
    lo = max(lower_candidates) if lower_candidates else INT_MIN
    proven = Interval(lo, hi)

    # Only report if we strictly tightened beyond the pure box bound.
    if box is not None:
        b1, b2 = box
        box_iv = b1.add(b2)
        if proven.lo <= box_iv.lo and proven.hi >= box_iv.hi:
            return None   # no relational improvement -> caller keeps box verdict
    return proven


# --- self-contained array-bounds + guard re-extraction -----------------------

def _arrays(source: str) -> Dict[str, Tuple[int, int]]:
    """Re-parse ARRAY declarations (mirrors symbolic.py._arrays) so refine() is
    self-contained and does not depend on the checker's internal state."""
    return {m.group(1): (int(m.group(2)), int(m.group(3)))
            for m in _ARRAY_DECL.finditer(source)}


def _walk_guards(source: str, target_line: int, indexed_arr: Optional[str],
                 make_then, make_empty, snapshot):
    """Generic control-flow walker mirroring symbolic.py's guard-stack handling.

    Walks every physical line, maintaining a stack of guard FRAMES with exactly
    symbolic.py's discipline: push on ``IF...THEN`` / ``ELSIF``, pop on
    ``END_IF``, and on ``ELSE`` drop the THEN-guard and push an empty frame (the
    negation is not modelled). The frame type is abstract:

      * ``make_then(cond)``  -> a frame for an ``IF cond THEN``/``ELSIF`` guard.
      * ``make_empty()``     -> an empty frame (for ELSE / ELSIF reset).
      * ``snapshot(stack)``  -> called the instant the analysis would evaluate
        the indexed statement, with the LIVE stack; its return value is returned.

    Crucially this handles guards that share a physical line with the indexed
    statement (e.g. ``IF i>=0 THEN IF j>=0 THEN a[i+j]:=1; END_IF; END_IF;``):
    we walk the line's control-flow tokens left-to-right and only snapshot once
    we reach the code segment that actually contains ``a[<index>]`` — so all
    same-line guards textually preceding the access are already on the stack,
    exactly as the checker sees them. If ``indexed_arr`` is None we snapshot at
    the first code segment of the target line (used when only the line is known).
    """
    stack: list = []
    for i, line in enumerate(source.splitlines(), 1):
        parts = _CTRL.split(line)
        pending_cond = ""
        collecting = False
        for part in parts:
            up = part.upper()
            if collecting and up not in ("THEN",):
                if up not in ("IF", "ELSIF", "ELSE", "END_IF"):
                    pending_cond += part
            if up == "IF":
                collecting = True
                pending_cond = ""
            elif up == "ELSIF":
                if stack:
                    stack.pop()
                stack.append(make_empty())
                collecting = True
                pending_cond = ""
            elif up == "THEN":
                stack.append(make_then(pending_cond))
                collecting = False
                pending_cond = ""
            elif up == "ELSE":
                if stack:
                    stack.pop()
                stack.append(make_empty())   # negation not modelled
                collecting = False
            elif up == "END_IF":
                if stack:
                    stack.pop()
                collecting = False
            else:
                # A normal code segment. On the target line, snapshot when this
                # segment holds the indexed access (or unconditionally if no
                # specific array was requested) and the analysis is not mid-cond.
                if i == target_line and not collecting:
                    hit = (indexed_arr is None
                           or _segment_has_index(part, indexed_arr))
                    if hit:
                        return snapshot(stack)
    # Fell through (target line empty / past EOF) -> snapshot the final stack.
    return snapshot(stack)


def _segment_has_index(seg: str, arr: str) -> bool:
    """True if this code segment contains an ``arr[...]`` access."""
    for m in _INDEX.finditer(seg):
        if m.group(1) == arr:
            return True
    return False


def _enclosing_octagon(source: str, target_line: int,
                       indexed_arr: Optional[str] = None) -> Octagon:
    """Octagon of all guards that TEXTUALLY ENCLOSE the indexed statement.

    Mirrors symbolic.py's guard stack and block scoping (see ``_walk_guards``):
    only guards lexically containing the statement contribute, so a guard from a
    sibling branch or another line never leaks in. Same-line preceding guards
    (e.g. ``IF i+j<=9 THEN a[i+j]:=1; END_IF;``) ARE included, which is sound:
    each is a necessary condition for reaching the access.
    """
    def _snap(stack: List[Octagon]) -> Octagon:
        merged = Octagon()
        for fr in stack:
            _merge(merged, fr)
        return merged
    return _walk_guards(source, target_line, indexed_arr,
                        make_then=parse_constraints,
                        make_empty=Octagon,
                        snapshot=_snap)


def _multivar_index_on_line(source: str, line: int,
                            arrays: Dict[str, Tuple[int, int]]
                            ) -> Optional[Tuple[str, int, int, List[str], int]]:
    """If ``line`` contains an array index of the supported multi-variable sum
    shape ``arr[v1 + v2 (+ ... ) (+ c)]``, return
    ``(arr, lo, hi, [vars], const)``; else ``None``.

    Re-derives the index from source so the refinement does not rely on the
    rationale text format. We only accept indices whose variable list has length
    >= 2 (single-variable indices are the box's job, not the relational one)."""
    rows = source.splitlines()
    if not (1 <= line <= len(rows)):
        return None
    for m in _INDEX.finditer(rows[line - 1]):
        arr, expr = m.group(1), m.group(2)
        if arr not in arrays:
            continue
        parsed = _multi_linear(expr)
        if parsed is None:
            continue
        vars_, const = parsed
        if len(vars_) < 2:
            continue
        lo, hi = arrays[arr]
        return arr, lo, hi, vars_, const
    return None


# --- public refinement -------------------------------------------------------

def refine(results: List[SymbolicResult], program) -> List[SymbolicResult]:
    """Relationally refine box-domain results, removing only PROVABLE false
    positives on multi-variable CWE-787 sum indices.

    For each ``CWE-787`` result with ``status == "violated"`` whose line carries
    a supported two-variable sum index ``a[v1 + v2 (+ c)]``:

      1. Re-extract the array bounds and the enclosing guards (octagon) from
         ``program.source`` (self-contained — does not trust the box internals).
      2. Recover the box ranges for ``v1``/``v2`` under those same guards so the
         relational and box facts can be combined (these box ranges are sound).
      3. Ask ``bound_sum`` for the tightest proven interval of ``v1 + v2``,
         shift by the constant ``c`` to get the index interval, and DOWNGRADE to
         ``safe`` IFF that proven interval is a subset of ``[lo, hi]``.

    Every other result — single-variable indices, three-or-more-variable
    indices, other CWEs, and any ``violated`` we cannot prove safe — is returned
    UNCHANGED. The function therefore only ever turns ``violated`` into ``safe``
    (precision), and only with a relational proof of in-boundedness; it can never
    manufacture a false ``safe`` (soundness). See the module docstring.
    """
    src = program.source
    arrays = _arrays(src)
    if not arrays:
        return list(results)

    refined: List[SymbolicResult] = []
    for r in results:
        new_r = _refine_one(r, src, arrays)
        refined.append(new_r if new_r is not None else r)
    return refined


def _refine_one(r: SymbolicResult, src: str,
                arrays: Dict[str, Tuple[int, int]]) -> Optional[SymbolicResult]:
    """Return a refined copy of ``r`` if (and only if) it is a multi-variable
    CWE-787 ``violated`` that a relational proof shows is in-bounds; else None.

    Two variables are handled exactly (the documented box false-positive class).
    For three or more variables we conservatively decline (return None) unless a
    pairwise sum bound provably caps the whole index — but to stay obviously
    sound we simply do not attempt >2-variable proofs here."""
    if r.cwe != "CWE-787" or r.status != "violated":
        return None
    info = _multivar_index_on_line(src, r.line, arrays)
    if info is None:
        return None
    arr, lo, hi, vars_, const = info
    if len(vars_) != 2:
        return None     # only the two-variable sum case is proven here
    v1, v2 = vars_

    oct_ = _enclosing_octagon(src, r.line, indexed_arr=arr)

    # Box ranges for v1/v2 under the same enclosing guards (sound, from the
    # checker's own interval analysis applied to this line's guard scope).
    box_doms = _box_domains_for_line(src, r.line, indexed_arr=arr)
    b1 = box_doms.get(v1, Interval(INT_MIN, INT_MAX))
    b2 = box_doms.get(v2, Interval(INT_MIN, INT_MAX))

    proven_sum = bound_sum(oct_, v1, v2, box=(b1, b2))
    if proven_sum is None:
        return None     # relational domain adds nothing -> keep ``violated``

    idx_iv = proven_sum.shift(const)
    # SOUND DOWNGRADE GATE: only safe if the PROVEN super-interval ⊆ [lo, hi].
    if idx_iv.lo < lo or idx_iv.hi > hi:
        return None     # not provably in-bounds -> leave ``violated`` untouched

    sum_expr = f"{v1}+{v2}" + (f"+{const}" if const else "")
    cons = list(r.constraints) + [
        f"relational: {v1}+{v2}∈[{proven_sum.lo},{proven_sum.hi}]",
        f"index={sum_expr}∈[{idx_iv.lo},{idx_iv.hi}]",
        f"bounds=[{lo},{hi}]",
    ]
    rationale = (
        f"octagon proof: enclosing guard bounds {v1}+{v2} to "
        f"[{proven_sum.lo},{proven_sum.hi}], so index {sum_expr}∈"
        f"[{idx_iv.lo},{idx_iv.hi}] ⊆ [{lo},{hi}] — relational refinement of a "
        f"box-domain false positive (Miné 2006 octagon domain)")
    return SymbolicResult("CWE-787", r.line, "safe", None, cons, rationale)


def _box_domains_for_line(src: str, target_line: int,
                          indexed_arr: Optional[str] = None
                          ) -> Dict[str, Interval]:
    """Recover the checker's interval-domain map active at the indexed statement.

    Reuses symbolic.py's exact ``_GuardFrame`` / ``_apply_cmp`` / ``_active``
    machinery (via the shared ``_walk_guards`` driver) so the relational
    refinement starts from precisely the same sound *box* facts the violation was
    raised against — including any guards on the same physical line that precede
    the access."""
    def _make_then(cond: str) -> "symbolic._GuardFrame":  # noqa: SLF001
        doms: Dict[str, Interval] = {}
        exc: Dict[str, set] = {}
        symbolic._apply_cmp(doms, exc, cond)              # noqa: SLF001
        return symbolic._GuardFrame(doms, exc)            # noqa: SLF001

    def _snap(stack: "List[symbolic._GuardFrame]") -> Dict[str, Interval]:  # noqa: SLF001
        doms, _exc = symbolic._active(stack)              # noqa: SLF001
        return doms

    return _walk_guards(src, target_line, indexed_arr,
                        make_then=_make_then,
                        make_empty=symbolic._GuardFrame,  # noqa: SLF001
                        snapshot=_snap)
