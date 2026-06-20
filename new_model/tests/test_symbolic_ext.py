"""Extended symbolic-checker tests: flow-sensitive guard scoping (soundness fix),
CWE-190 integer overflow/underflow, and multi-variable index analysis.

These complement tests/test_beyond_frontier.py. Soundness is the invariant under
test: the checker must NEVER report a false `safe`. When a guard does not textually
enclose a statement, that statement must report `violated` or `unknown`.
"""
import symbolic
from schema import Program


def P(s, pid="t.st"):
    return Program(pid, pid, s, [])


def _statuses(prog, cwe):
    return [r.status for r in symbolic.check(prog) if r.cwe == cwe]


def _results(prog, cwe, status=None):
    return [r for r in symbolic.check(prog)
            if r.cwe == cwe and (status is None or r.status == status)]


# --- (a) flow-sensitivity / block-scoped guards ------------------------------

def test_guard_does_not_leak_to_earlier_unguarded_statement():
    # The SAME index write appears (1) before any guard and (2) fully enclosed by
    # a guard later. The enclosing one is safe; the earlier one must NOT be safe.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n"
           " a[idx+2]:=1;\n"
           "IF idx >= 0 THEN\n IF idx <= 7 THEN a[idx+2]:=1; END_IF; END_IF;\n")
    res = _results(P(src), "CWE-787")
    by_line = {r.line: r.status for r in res}
    assert by_line[5] == "violated"        # unguarded -> proven violated
    assert by_line[7] == "safe"            # enclosed by both guards -> safe


def test_enclosing_nested_guard_yields_safe():
    # Regression: the existing nested-IF enclosing case still proves safe.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n"
           "IF idx >= 0 THEN\n IF idx <= 7 THEN a[idx+2]:=1; END_IF; END_IF;\n")
    statuses = set(_statuses(P(src), "CWE-787"))
    assert "violated" not in statuses and "safe" in statuses


def test_statement_after_end_if_is_no_longer_guarded():
    # Guard closes with END_IF; a following identical statement is out of scope.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n"
           "IF idx >= 0 THEN IF idx <= 7 THEN a[idx+2]:=1; END_IF; END_IF;\n"
           " a[idx+2]:=1;\n")
    by_line = {r.line: r.status for r in _results(P(src), "CWE-787")}
    assert by_line[5] == "safe"
    assert by_line[6] == "violated"        # after END_IF -> guard does not apply


def test_else_branch_does_not_inherit_then_guard():
    # A then-guard must not leak into the ELSE branch.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n"
           "IF idx >= 0 AND idx <= 7 THEN\n a[idx+2]:=1;\n"
           " ELSE\n a[idx+2]:=1;\n END_IF;\n")
    by_line = {r.line: r.status for r in _results(P(src), "CWE-787")}
    assert by_line[6] == "safe"            # THEN branch fully guarded
    assert by_line[8] in ("violated", "unknown")   # ELSE branch NOT safe


def test_div_guard_is_flow_scoped():
    # `y <> 0` guards only the enclosed division; an earlier one stays violated.
    src = ("VAR\n x:INT; y:INT; r:INT;\nEND_VAR\n"
           " r:=x/y;\n"
           "IF y <> 0 THEN r:=x/y; END_IF;\n")
    by_line = {r.line: r.status for r in _results(P(src), "CWE-369")}
    assert by_line[4] == "violated"
    assert by_line[5] == "safe"


# --- (b) CWE-190 integer overflow / underflow --------------------------------

def test_overflow_violated_with_witness():
    src = "VAR\n a:INT; b:INT; x:INT;\nEND_VAR\n x:=a+b;\n"
    viol = _results(P(src), "CWE-190", "violated")
    assert viol and viol[0].witness is not None
    # Witness drives both operands to an extreme that escapes 16-bit range.
    assert "a" in viol[0].witness and "b" in viol[0].witness


def test_underflow_violated_subtraction():
    src = "VAR\n a:INT; b:INT; x:INT;\nEND_VAR\n x:=a-b;\n"
    viol = _results(P(src), "CWE-190", "violated")
    assert viol and viol[0].witness is not None


def test_multiplication_overflow_violated():
    src = "VAR\n a:INT; b:INT; x:INT;\nEND_VAR\n x:=a*b;\n"
    viol = _results(P(src), "CWE-190", "violated")
    assert viol and viol[0].witness is not None


def test_overflow_safe_when_fully_guarded():
    # Both operands bounded so a+b stays within [-32768, 32767].
    src = ("VAR\n a:INT; b:INT; x:INT;\nEND_VAR\n"
           "IF a >= 0 THEN IF a <= 100 THEN IF b >= 0 THEN IF b <= 100 THEN"
           " x:=a+b; END_IF; END_IF; END_IF; END_IF;\n")
    statuses = _statuses(P(src), "CWE-190")
    assert statuses and "violated" not in statuses and "safe" in statuses


def test_overflow_unknown_for_nonlinear():
    src = "VAR\n a:INT; x:INT;\nEND_VAR\n x:=a*a*a;\n"
    assert "unknown" in _statuses(P(src), "CWE-190")
    assert "safe" not in _statuses(P(src), "CWE-190")   # never a false safe


def test_overflow_no_finding_for_plain_copy():
    # A non-arithmetic assignment carries no overflow obligation.
    src = "VAR\n a:INT; x:INT;\nEND_VAR\n x:=a;\n"
    assert _statuses(P(src), "CWE-190") == []


# --- (c) multi-variable index ------------------------------------------------

def test_multivar_index_violated_with_witness():
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n a[i+j]:=1;\n")
    viol = _results(P(src), "CWE-787", "violated")
    assert viol and viol[0].witness is not None
    assert "i" in viol[0].witness and "j" in viol[0].witness


def test_multivar_index_safe_when_guarded():
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i >= 0 THEN IF i <= 3 THEN IF j >= 0 THEN IF j <= 3 THEN"
           " a[i+j]:=1; END_IF; END_IF; END_IF; END_IF;\n")
    statuses = set(_statuses(P(src), "CWE-787"))
    assert "violated" not in statuses and "safe" in statuses


def test_multivar_index_with_constant():
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n"
           "IF i >= 0 THEN IF i <= 2 THEN IF j >= 0 THEN IF j <= 2 THEN"
           " a[i+j+5]:=1; END_IF; END_IF; END_IF; END_IF;\n")
    # i+j+5 in [5, 9] -> within [0,9] -> safe.
    statuses = set(_statuses(P(src), "CWE-787"))
    assert "violated" not in statuses and "safe" in statuses


def test_multivar_subtraction_is_unknown_not_safe():
    # Variable subtraction is unsupported -> unknown, never a false safe.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n a[i-j]:=1;\n")
    statuses = _statuses(P(src), "CWE-787")
    assert "unknown" in statuses and "safe" not in statuses


def test_multivar_unknown_on_unsupported_subexpr():
    # A non-linear sub-term -> unknown, never safe.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n i:INT; j:INT;\nEND_VAR\n a[i+j*j]:=1;\n")
    statuses = _statuses(P(src), "CWE-787")
    assert "unknown" in statuses and "safe" not in statuses


# --- (d) soundness edge cases: no false "safe" -------------------------------

def test_no_false_safe_when_guard_is_on_different_variable():
    # Guard constrains `k`, but the index uses `idx` -> idx unconstrained -> not safe.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT; k:INT;\nEND_VAR\n"
           "IF k >= 0 THEN IF k <= 7 THEN a[idx+2]:=1; END_IF; END_IF;\n")
    statuses = _statuses(P(src), "CWE-787")
    assert "safe" not in statuses
    assert "violated" in statuses


def test_no_false_safe_partial_guard():
    # Only an upper bound on idx; lower side still escapes -> must be violated.
    src = ("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n"
           "IF idx <= 7 THEN a[idx]:=1; END_IF;\n")
    statuses = _statuses(P(src), "CWE-787")
    assert "safe" not in statuses
    assert "violated" in statuses
