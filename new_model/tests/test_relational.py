"""Tests for the relational (octagon / difference-bound) refinement.

The refinement complements the SOUND box-domain checker in ``symbolic.py`` by
removing the *specific* false positives the box domain documents: multi-variable
sum indices ``a[v1+v2(+c)]`` whose operands are correlated by an enclosing guard
(e.g. ``IF i+j <= 9`` or ``i = -j``). The invariant under test is the same one
``symbolic.py`` upholds — NEVER a false ``safe``:

  * A ``violated`` is downgraded to ``safe`` ONLY when the octagon proves the
    index stays within the array bounds (relational refinement of a true FP).
  * A genuinely out-of-bounds access, or one whose enclosing relation does not
    actually bound the index inside ``[lo, hi]``, stays ``violated``.
  * Single-variable / other-CWE / non-violated results pass through unchanged.

Method follows the brief: build a Program with ``P(s)``, run ``symbolic.check``,
then ``relational.refine``, and assert the status transitions.
"""
import relational
import symbolic
from schema import Program


def P(s):
    return Program("t", "t", s, [])


def _status_by_line(results, cwe="CWE-787"):
    return {r.line: r.status for r in results if r.cwe == cwe}


def _refined(src):
    prog = P(src)
    return relational.refine(symbolic.check(prog), prog)


def _statuses(src, cwe="CWE-787"):
    return [r.status for r in _refined(src) if r.cwe == cwe]


# --- (1) the headline downgrade: IF i+j <= 9 on ARRAY[0..9] proves safe -------

def test_sum_guard_downgrades_to_safe():
    # Box domain reports `violated` (it sums full ranges of i and j); the octagon
    # knows i+j <= 9 (and i,j >= 0), so the index is provably in [0, 9] -> safe.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j <= 9 THEN\n"
           " IF i >= 0 THEN IF j >= 0 THEN a[i+j]:=1; END_IF; END_IF; END_IF;\n")
    box = _status_by_line(symbolic.check(P(src)))
    assert box[6] == "violated"                  # box domain over-approximates
    ref = _status_by_line(_refined(src))
    assert ref[6] == "safe"                      # relational refinement removes FP


def test_sum_guard_single_physical_line():
    # Same proof, all conjoined on one physical line (AND form) -> still safe.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j <= 9 AND i >= 0 AND j >= 0 THEN a[i+j]:=1; END_IF;\n")
    assert _status_by_line(symbolic.check(P(src)))[5] == "violated"
    assert _status_by_line(_refined(src))[5] == "safe"


def test_downgraded_result_carries_relational_rationale():
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j <= 9 AND i >= 0 AND j >= 0 THEN a[i+j]:=1; END_IF;\n")
    safe = [r for r in _refined(src) if r.cwe == "CWE-787" and r.status == "safe"]
    assert safe
    r = safe[0]
    assert r.witness is None                     # safe -> no counterexample
    assert "octagon" in r.rationale.lower()
    assert any("relational" in c for c in r.constraints)


# --- (2) equality i = -j makes the index constant / in-bounds -----------------

def test_equality_negation_proves_index_constant_safe():
    # i = -j  =>  i + j = 0  -> index 0 is in [0, 9] regardless of operand range.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i = -j THEN a[i+j]:=1; END_IF;\n")
    assert _status_by_line(symbolic.check(P(src)))[5] == "violated"
    assert _status_by_line(_refined(src))[5] == "safe"


def test_equality_same_variable_difference_path():
    # i = j with 0 <= i <= 4  =>  i + j in [0, 8]  (difference-facet + unary
    # closure, the octagon path the box domain cannot do) -> safe on [0, 9].
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i = j AND i >= 0 AND i <= 4 THEN a[i+j]:=1; END_IF;\n")
    assert _status_by_line(symbolic.check(P(src)))[5] == "violated"
    assert _status_by_line(_refined(src))[5] == "safe"


def test_sum_guard_with_constant_offset_safe():
    # IF i+j <= 4 (and >=0) then a[i+j+5] in [5, 9] -> safe on [0, 9].
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j <= 4 AND i >= 0 AND j >= 0 THEN a[i+j+5]:=1; END_IF;\n")
    assert _status_by_line(symbolic.check(P(src)))[5] == "violated"
    assert _status_by_line(_refined(src))[5] == "safe"


def test_negative_array_bounds_two_sided_sum_safe():
    # ARRAY[-5..5]; -5 <= i+j <= 5 proves the index in range.
    src = ("VAR\n a:ARRAY[-5..5] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j <= 5 AND i+j >= -5 THEN a[i+j]:=1; END_IF;\n")
    assert _status_by_line(symbolic.check(P(src)))[5] == "violated"
    assert _status_by_line(_refined(src))[5] == "safe"


# --- (3) NO protective relation -> stays violated (no false safe) -------------

def test_no_relation_stays_violated():
    # Unguarded multi-var index: nothing to refine -> remains violated.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n a[i+j]:=1;\n")
    assert _status_by_line(_refined(src))[5] == "violated"


def test_one_sided_sum_upper_only_stays_violated():
    # i+j <= 9 bounds the sum from ABOVE only; with no lower bound the index can
    # be arbitrarily negative -> still out of bounds -> must stay violated.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j <= 9 THEN a[i+j]:=1; END_IF;\n")
    assert _status_by_line(_refined(src))[5] == "violated"


def test_one_sided_sum_lower_only_stays_violated():
    # Symmetric: i+j >= 0 leaves the upper side open -> stays violated.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j >= 0 THEN a[i+j]:=1; END_IF;\n")
    assert _status_by_line(_refined(src))[5] == "violated"


def test_unrelated_relation_stays_violated():
    # A guard on a THIRD variable k does not bound i+j -> stays violated.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT; k:INT;\nEND_VAR\n"
           "IF k <= 3 AND k >= 0 THEN a[i+j]:=1; END_IF;\n")
    assert _status_by_line(_refined(src))[5] == "violated"


# --- (4) genuinely out-of-bounds with a non-protective relation stays violated -

def test_insufficient_sum_bound_stays_violated():
    # i+j <= 20 cannot keep the index within [0, 9] -> a real violation remains.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j <= 20 AND i >= 0 AND j >= 0 THEN a[i+j]:=1; END_IF;\n")
    assert _status_by_line(_refined(src))[5] == "violated"


def test_offbyone_array_bound_stays_violated():
    # Sum proven in [0, 9] but the array is only [0, 8]: index 9 is OOB ->
    # the relational proof must NOT downgrade (off-by-one is a real bug).
    src = ("VAR\n a:ARRAY[0..8] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j <= 9 AND i >= 0 AND j >= 0 THEN a[i+j]:=1; END_IF;\n")
    assert _status_by_line(_refined(src))[5] == "violated"


def test_equality_with_offset_pushing_out_stays_violated():
    # i = -j gives i+j = 0, but a[i+j+12] = a[12] is OOB on [0, 9] -> violated.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i = -j THEN a[i+j+12]:=1; END_IF;\n")
    assert _status_by_line(_refined(src))[5] == "violated"


def test_equality_with_negative_offset_underflow_stays_violated():
    # i = -j gives i+j = 0, but a[i+j-1] = a[-1] underflows [0, 9] -> violated.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i = -j THEN a[i+j-1]:=1; END_IF;\n")
    assert _status_by_line(_refined(src))[5] == "violated"


def test_same_variable_doubling_overflows_stays_violated():
    # a[i+i] with 0 <= i <= 6  =>  i+i in [0, 12]; index 12 is OOB -> violated.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT;\nEND_VAR\n"
           "IF i >= 0 AND i <= 6 THEN a[i+i]:=1; END_IF;\n")
    assert _status_by_line(_refined(src))[5] == "violated"


# --- (5) block-scoping soundness: relation must textually enclose the access ---

def test_relation_in_then_does_not_help_access_in_else():
    # The protective relation is in the THEN branch; the access is in the ELSE
    # branch (negation not modelled) -> the access is NOT proven safe.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j <= 9 AND i >= 0 AND j >= 0 THEN\n x:=1;\n"
           " ELSE\n a[i+j]:=1;\n END_IF;\n")
    assert _status_by_line(_refined(src))[8] in ("violated", "unknown")


def test_relation_closed_before_access_does_not_help():
    # Guard closes with END_IF, THEN a separate identical access -> not covered.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j <= 9 AND i >= 0 AND j >= 0 THEN x:=1; END_IF;\n a[i+j]:=1;\n")
    assert _status_by_line(_refined(src))[6] == "violated"


# --- (6) passthrough: things the refinement must not touch --------------------

def test_single_variable_index_passthrough_unchanged():
    # Single-variable indices are the box domain's job; refine() leaves them be.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n a[idx]:=1;\n")
    before = _status_by_line(symbolic.check(P(src)))
    after = _status_by_line(_refined(src))
    assert before == after
    assert after[5] == "violated"


def test_single_variable_safe_passthrough_unchanged():
    # A box-proven `safe` single-var index stays exactly safe (not re-derived).
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n"
           "IF idx >= 0 AND idx <= 9 THEN a[idx]:=1; END_IF;\n")
    after = _status_by_line(_refined(src))
    assert after[5] == "safe"


def test_other_cwes_passthrough_unchanged():
    # CWE-369 / CWE-190 results are never modified by the array refinement.
    src = ("VAR\n x:INT; y:INT; r:INT;\nEND_VAR\n r:=x/y;\n")
    before = symbolic.check(P(src))
    after = relational.refine(before, P(src))
    b = {(r.cwe, r.line, r.status) for r in before}
    a = {(r.cwe, r.line, r.status) for r in after}
    assert b == a


def test_unknown_index_not_promoted_to_safe():
    # A non-linear multi-var index is `unknown` from the box; refine() must NOT
    # turn an `unknown` into `safe` (only `violated` -> `safe` is permitted).
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n a[i+j*j]:=1;\n")
    statuses = _statuses(src)
    assert "safe" not in statuses
    assert "unknown" in statuses


def test_refine_is_pure_and_length_preserving():
    # refine() returns one result per input result and does not mutate inputs.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i+j <= 9 AND i >= 0 AND j >= 0 THEN a[i+j]:=1; END_IF;\n")
    prog = P(src)
    original = symbolic.check(prog)
    snapshot = [(r.cwe, r.line, r.status) for r in original]
    out = relational.refine(original, prog)
    assert len(out) == len(original)
    # Original list objects are unchanged (refine builds new results).
    assert [(r.cwe, r.line, r.status) for r in original] == snapshot


def test_no_arrays_returns_results_unchanged():
    # No ARRAY decls -> nothing to refine; identity (by value) on the list.
    src = ("VAR\n x:INT; y:INT; r:INT;\nEND_VAR\n r:=x/y;\n")
    prog = P(src)
    before = symbolic.check(prog)
    after = relational.refine(before, prog)
    assert [(r.cwe, r.line, r.status) for r in before] == \
           [(r.cwe, r.line, r.status) for r in after]


# --- (7) unit tests for the octagon store and bound_sum -----------------------

def test_parse_constraints_supported_forms():
    o = relational.parse_constraints(
        "i + j <= 9 AND i - j >= -2 AND k = 3 AND p = -q AND r = s")
    assert o.sum_ub[("i", "j")] == 9
    assert o.lb["k"] == 3 and o.ub["k"] == 3        # k = 3 -> both facets
    assert o.sum_ub[("p", "q")] == 0 and o.sum_lb[("p", "q")] == 0   # p = -q
    # r = s -> r - s in [0, 0] encoded as both directed diff facets <= 0.
    assert o.diff_ub[("r", "s")] == 0 and o.diff_ub[("s", "r")] == 0


def test_bound_sum_direct_sum_facets():
    o = relational.parse_constraints("i + j <= 9 AND i + j >= 2")
    iv = relational.bound_sum(o, "i", "j")
    assert iv is not None and iv.lo == 2 and iv.hi == 9


def test_bound_sum_difference_plus_unary_closure():
    # i - j in [0, 2], j in [1, 3]  =>  i+j = (i-j) + 2j in [0+2, 2+6] = [2, 8].
    o = relational.parse_constraints(
        "i - j <= 2 AND i - j >= 0 AND j <= 3 AND j >= 1")
    iv = relational.bound_sum(o, "i", "j")
    assert iv is not None and iv.lo == 2 and iv.hi == 8


def test_bound_sum_none_when_no_tightening():
    # Empty octagon + a box that the relational domain cannot improve -> None.
    o = relational.Octagon()
    iv = relational.bound_sum(o, "i", "j",
                              box=(symbolic.Interval(0, 5), symbolic.Interval(0, 5)))
    assert iv is None


def test_bound_sum_keeps_tighter_of_relation_and_box():
    # Relation i+j <= 4 is tighter than the box (i,j in [0,9] -> sum<=18).
    o = relational.parse_constraints("i + j <= 4")
    iv = relational.bound_sum(o, "i", "j",
                              box=(symbolic.Interval(0, 9), symbolic.Interval(0, 9)))
    assert iv is not None and iv.hi == 4          # took the relational upper bound
    assert iv.lo == 0                             # took the box lower bound


def test_bound_sum_is_sound_superset_random():
    # SOUNDNESS PROPERTY CHECK: for many concrete (i, j) satisfying the parsed
    # constraints, i+j must lie inside the interval bound_sum claims. This is the
    # core invariant: the relational bound is a true OVER-approximation.
    o = relational.parse_constraints(
        "i + j <= 9 AND i >= 0 AND j >= 0 AND i - j <= 3")
    iv = relational.bound_sum(o, "i", "j")
    assert iv is not None
    checked = 0
    for i in range(0, 12):
        for j in range(0, 12):
            if i + j <= 9 and i >= 0 and j >= 0 and i - j <= 3:
                assert iv.lo <= i + j <= iv.hi    # every feasible point contained
                checked += 1
    assert checked > 0                            # the constraint set is non-empty
