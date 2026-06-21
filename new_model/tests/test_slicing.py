"""Tests for advanced/slicing.py — static backward program slicing for IEC 61131-3
Structured Text.

The invariant under test is SOUNDNESS as an OVER-approximation: a backward slice
must include every statement that may affect the slicing criterion (Weiser 1984;
Horwitz-Reps-Binkley 1990). Tests therefore assert both:
  * INCLUSION — the transitive data-dependence chain of the criterion variables and
    the enclosing control-dependence guards (and the guards' own dependencies) are
    present; and
  * EXCLUSION — statements that demonstrably cannot affect the criterion are absent
    (precision sanity: the slice is not just "the whole program").

Programs are built with the prescribed helper `P`.
"""
import slicing
from schema import Program


def P(s):
    return Program("t", "t", s, [])


# --------------------------------------------------------------------------- #
# (1) Data dependence: transitive defs of the index var IN, unrelated stmts OUT
# --------------------------------------------------------------------------- #

def test_slice_includes_transitive_index_defs_excludes_unrelated():
    # idx is defined from raw; arr[idx] is the sink. `noise`/`other` never feed idx.
    src = (
        "raw := input;\n"        # 1  feeds idx (via line 3)
        "noise := 42;\n"         # 2  UNRELATED
        "idx := raw + 1;\n"      # 3  defines the index variable
        "other := noise * 2;\n"  # 4  UNRELATED (depends only on noise)
        "arr[idx] := 0;\n"       # 5  SINK
    )
    sl = slicing.backward_slice(P(src), 5)
    assert set(sl.lines) == {1, 3, 5}, sl.lines
    # Unrelated statements are excluded.
    assert 2 not in sl
    assert 4 not in sl


def test_multistep_data_chain_includes_all_three():
    # The canonical chain from the brief: a:=input; b:=a+1; arr[b]:=0 -> all three.
    src = (
        "a := input;\n"     # 1
        "b := a + 1;\n"     # 2
        "arr[b] := 0;\n"    # 3
    )
    sl = slicing.slice_for_finding(P(src), 3)
    assert set(sl.lines) == {1, 2, 3}, sl.lines


def test_deep_data_chain_is_fully_transitive():
    # A longer chain must be followed end-to-end (transitive closure).
    src = (
        "x0 := input;\n"    # 1
        "x1 := x0 + 1;\n"   # 2
        "x2 := x1 + 1;\n"   # 3
        "x3 := x2 + 1;\n"   # 4
        "arr[x3] := 0;\n"   # 5
    )
    sl = slicing.backward_slice(P(src), 5)
    assert set(sl.lines) == {1, 2, 3, 4, 5}, sl.lines


def test_divisor_chain_sliced_for_division_sink():
    # Division sink: criterion is the divisor and its transitive defs.
    src = (
        "d0 := input;\n"    # 1
        "d := d0 - 3;\n"    # 2
        "unrel := 7;\n"     # 3  UNRELATED
        "r := 100 / d;\n"   # 4  SINK (divisor d)
    )
    sl = slicing.slice_for_finding(P(src), 4)
    assert set(sl.lines) == {1, 2, 4}, sl.lines
    assert 3 not in sl


# --------------------------------------------------------------------------- #
# (2) Control dependence: enclosing IF guard line + the guard's own deps
# --------------------------------------------------------------------------- #

def test_control_dependence_pulls_in_enclosing_guard():
    # The sink is enclosed by an IF; the guard predicate line must be in the slice.
    src = (
        "IF flag > 0 THEN\n"   # 1  guard (control parent of line 2)
        "  arr[k] := 0;\n"     # 2  SINK
        "END_IF;\n"            # 3
    )
    sl = slicing.backward_slice(P(src), 2)
    assert 1 in sl, sl.lines          # enclosing guard included (control dep)
    assert 2 in sl


def test_control_dependence_pulls_in_guards_own_dependencies():
    # The guard reads `limit`, which is computed from `raw`. Slicing the sink must
    # transitively pull the guard's data dependences (limit, then raw).
    src = (
        "raw := input;\n"          # 1  feeds the guard predicate
        "limit := raw + 2;\n"      # 2  guard's data dependency
        "IF limit < 10 THEN\n"     # 3  guard (control parent of line 5)
        "  v := seed;\n"           # 4  data dependency of the sink's index
        "  arr[v] := 0;\n"         # 5  SINK
        "END_IF;\n"                # 6
    )
    sl = slicing.backward_slice(P(src), 5)
    # Sink data chain: 5 <- 4 (v:=seed). Control: 5 is guarded by 3; 3 reads limit
    # -> 2; 2 reads raw -> 1. All must be present.
    assert set(sl.lines) == {1, 2, 3, 4, 5}, sl.lines
    assert 6 not in sl                 # END_IF defines/uses nothing relevant


def test_nested_guards_both_included():
    # Two enclosing IFs -> both predicate lines are control parents.
    src = (
        "IF a > 0 THEN\n"          # 1  outer guard
        "  IF b > 0 THEN\n"        # 2  inner guard
        "    arr[k] := 0;\n"       # 3  SINK
        "  END_IF;\n"              # 4
        "END_IF;\n"                # 5
    )
    sl = slicing.backward_slice(P(src), 3)
    assert {1, 2, 3}.issubset(set(sl.lines)), sl.lines


def test_guard_does_not_leak_to_statement_after_end_if():
    # A statement AFTER END_IF is not control-dependent on the closed guard.
    src = (
        "IF a > 0 THEN\n"      # 1  guard (does NOT enclose line 4)
        "  noop := 1;\n"       # 2
        "END_IF;\n"            # 3
        "arr[k] := 0;\n"       # 4  SINK, outside the IF, k undefined
    )
    sl = slicing.backward_slice(P(src), 4)
    assert 1 not in sl, sl.lines      # closed guard excluded (sound + precise)
    assert set(sl.lines) == {4}


def test_else_branch_is_control_dependent_on_if_predicate():
    # An else-branch statement is still control-dependent on the IF predicate.
    src = (
        "IF a > 0 THEN\n"      # 1  predicate
        "  p := 1;\n"          # 2  THEN branch (unrelated to the sink)
        "ELSE\n"               # 3
        "  arr[k] := 0;\n"     # 4  SINK in the ELSE branch
        "END_IF;\n"            # 5
    )
    sl = slicing.backward_slice(P(src), 4)
    assert 1 in sl, sl.lines          # IF predicate is a control parent
    assert 2 not in sl                # other branch's body is unrelated
    assert set(sl.lines) == {1, 4}


def test_elsif_branch_control_parent_is_elsif_predicate():
    # The ELSIF predicate (its own line) is the control parent of its branch body,
    # and the predicate's variables are sliced.
    src = (
        "IF a > 0 THEN\n"          # 1
        "  p := 1;\n"              # 2
        "ELSIF cond > 0 THEN\n"    # 3  ELSIF predicate (control parent of line 4)
        "  arr[k] := 0;\n"         # 4  SINK
        "END_IF;\n"                # 5
    )
    sl = slicing.backward_slice(P(src), 4)
    assert 3 in sl, sl.lines          # elsif predicate included
    assert "cond" in slicing.build_pdg(P(src)).stmts[3].cond_uses


def test_same_line_guard_pulls_in_predicate_definition():
    # SOUNDNESS regression: an `IF g > 0 THEN <sink>; END_IF` on ONE physical line
    # must still pull in g's definition — the predicate controls the same-line sink.
    src = (
        "g := sensor;\n"                   # 1  defines the guard variable
        "IF g > 0 THEN arr[k] := 0; END_IF;\n"  # 2  one-line guard + sink
    )
    sl = slicing.slice_for_finding(P(src), 2)
    assert set(sl.lines) == {1, 2}, sl.lines   # line 1 must NOT be dropped


# --------------------------------------------------------------------------- #
# (3) Criterion inference (variables=None)
# --------------------------------------------------------------------------- #

def test_infer_criterion_from_index_variable():
    src = (
        "a := input;\n"     # 1
        "b := a + 1;\n"     # 2
        "arr[b] := 0;\n"    # 3  index var is b
    )
    assert slicing.infer_criterion_vars(P(src), 3) == {"b"}
    sl = slicing.backward_slice(P(src), 3, variables=None)
    assert sl.criterion_vars == frozenset({"b"})


def test_infer_criterion_from_divisor_variable():
    src = "num := input;\nr := num / denom;\n"
    # Divisor `denom` is the criterion (not the dividend `num`).
    assert slicing.infer_criterion_vars(P(src), 2) == {"denom"}


def test_infer_criterion_multivar_index():
    src = "arr[i + j] := 0;\n"
    assert slicing.infer_criterion_vars(P(src), 1) == {"i", "j"}


def test_infer_falls_back_to_line_uses_when_no_sink_shape():
    # No index/divisor on the line -> fall back to all RHS reads (sound superset).
    src = "y := m + c;\n"
    assert slicing.infer_criterion_vars(P(src), 1) == {"m", "c"}


def test_explicit_variables_override_inference():
    # When the caller passes variables, inference is bypassed and those are used.
    src = (
        "p := 1;\n"             # 1  defines p
        "q := 2;\n"             # 2  defines q (the index var of the sink)
        "arr[q] := p;\n"        # 3  sink; index var is q, but we ask for {p}
    )
    sl = slicing.backward_slice(P(src), 3, variables={"p"})
    assert sl.criterion_vars == frozenset({"p"})
    assert 1 in sl                     # p's def pulled in
    # q is not part of the (overridden) criterion -> its def (line 2) is not a data
    # dependency of {p}; only line 3 (the criterion line) and line 1 are required.
    assert set(sl.lines) == {1, 3}, sl.lines


# --------------------------------------------------------------------------- #
# (4) render() — operator-readable evidence
# --------------------------------------------------------------------------- #

def test_render_mentions_criterion_line_and_variables():
    src = "idx := input;\narr[idx] := 0;\n"
    sl = slicing.slice_for_finding(P(src), 2)
    out = slicing.render(sl)
    assert "criterion" in out.lower()
    assert "line 2" in out               # criterion LINE named
    assert "idx" in out                  # criterion variable named


def test_render_lists_sliced_lines_in_order():
    src = (
        "a := input;\n"     # 1
        "b := a + 1;\n"     # 2
        "arr[b] := 0;\n"    # 3
    )
    sl = slicing.slice_for_finding(P(src), 3)
    out = slicing.render(sl)
    lines = out.splitlines()
    # Header first, then the three sliced lines in ascending order with numbers.
    assert lines[0].lower().startswith("backward slice criterion")
    body = lines[1:]
    assert len(body) == 3
    assert body[0].strip().startswith("1:")
    assert body[1].strip().startswith("2:")
    assert body[2].strip().startswith("3:")
    # Verbatim statement text is present for evidence.
    assert "arr[b] := 0;" in body[2]


def test_render_handles_empty_criterion_variables():
    # A line with no readable vars yields an empty criterion; render must not crash.
    src = "arr[0] := 0;\n"               # constant index -> no criterion variables
    sl = slicing.slice_for_finding(P(src), 1)
    out = slicing.render(sl)
    assert "line 1" in out
    assert "{}" in out                   # empty variable set rendered cleanly


# --------------------------------------------------------------------------- #
# (5) Soundness / over-approximation specifics
# --------------------------------------------------------------------------- #

def test_overapproximation_includes_all_candidate_defs():
    # idx is (re)defined on two branches; BOTH candidate defs must be in the slice
    # (flow-insensitive candidate-def closure — never drop a reaching def).
    src = (
        "IF c > 0 THEN\n"      # 1  guard
        "  idx := 1;\n"        # 2  candidate def #1
        "ELSE\n"               # 3
        "  idx := 2;\n"        # 4  candidate def #2
        "END_IF;\n"            # 5
        "arr[idx] := 0;\n"     # 6  SINK
    )
    sl = slicing.backward_slice(P(src), 6)
    # Both ambiguous defs of idx are present; their controlling guard is too.
    assert {2, 4}.issubset(set(sl.lines)), sl.lines
    assert 1 in sl                     # guard controlling the candidate defs


def test_array_write_creates_data_dependence_for_later_read():
    # A whole-array write is treated as a def of the array; a later read of any
    # element data-depends on it (sound over-approximation of element aliasing).
    src = (
        "buf[0] := seed;\n"    # 1  writes buf (def of array `buf`)
        "v := buf[3];\n"       # 2  reads buf -> data-depends on line 1
        "arr[v] := 0;\n"       # 3  SINK on v
    )
    sl = slicing.backward_slice(P(src), 3)
    assert {1, 2, 3}.issubset(set(sl.lines)), sl.lines


def test_criterion_line_always_in_slice():
    # Even with an unknown/empty criterion, the criterion line itself is included.
    src = "arr[7] := 0;\n"
    sl = slicing.backward_slice(P(src), 1)
    assert 1 in sl


def test_slice_is_deterministic():
    src = (
        "a := input;\n"
        "b := a + 1;\n"
        "IF b > 0 THEN arr[b] := 0; END_IF;\n"
    )
    first = slicing.backward_slice(P(src), 3).lines
    second = slicing.backward_slice(P(src), 3).lines
    assert first == second
    assert first == sorted(first)        # always returned sorted


def test_out_of_range_line_returns_empty_slice():
    sl = slicing.backward_slice(P("x := 1;\n"), 99)
    assert sl.lines == []
    assert sl.statements == []
    assert sl.criterion_line == 99


def test_recursive_self_reference_terminates():
    # x := x + 1 references itself; the worklist must reach a fixpoint and stop.
    src = (
        "x := input;\n"     # 1
        "x := x + 1;\n"     # 2  self-referential def
        "arr[x] := 0;\n"    # 3  SINK
    )
    sl = slicing.backward_slice(P(src), 3)
    assert {1, 2, 3}.issubset(set(sl.lines)), sl.lines


def test_slice_lines_match_statements():
    # The .statements list must correspond 1:1, in order, to .lines.
    src = (
        "a := input;\n"     # 1
        "b := a + 1;\n"     # 2
        "arr[b] := 0;\n"    # 3
    )
    sl = slicing.slice_for_finding(P(src), 3)
    raw = src.splitlines()
    assert sl.statements == [raw[ln - 1] for ln in sl.lines]


def test_contains_operator_checks_membership():
    src = "a := input;\narr[a] := 0;\n"
    sl = slicing.slice_for_finding(P(src), 2)
    assert 1 in sl and 2 in sl
    assert 99 not in sl
