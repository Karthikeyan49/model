"""Extended symbolic-checker tests: block-scoped guard soundness fix and the new
integer overflow/underflow (CWE-190 / CWE-191) interval checks.

These complement test_beyond_frontier.py (which must keep passing untouched)."""
import symbolic
from schema import Program


def P(s, pid="t.st"):
    return Program(pid, pid, s, [])


def _of(results, cwe):
    return [r for r in results if r.cwe == cwe]


# --- soundness fix: guards are block-scoped, not global -----------------------

def test_guard_does_not_leak_past_endif():
    # `IF idx <= 7` dominates only the body; the a[idx+2] write AFTER END_IF is
    # unguarded, so idx is unconstrained there -> index up to 32769 -> VIOLATED.
    # The old global-guard code wrongly returned 'safe' here.
    src = ("VAR a:ARRAY[0..9] OF INT; idx:INT; END_VAR\n"
           "IF idx <= 7 THEN\n"
           " b := 1;\n"
           "END_IF;\n"
           "a[idx+2] := 1;\n")
    viol = [r for r in _of(symbolic.check(P(src)), "CWE-787") if r.status == "violated"]
    assert viol, "unguarded index after END_IF must be violated, not safe"
    statuses = {r.status for r in _of(symbolic.check(P(src)), "CWE-787")}
    assert "safe" not in statuses


def test_guard_still_applies_inside_block():
    # When the guards DO dominate the statement (nested IFs), result stays safe.
    src = ("VAR a:ARRAY[0..9] OF INT; idx:INT; END_VAR\n"
           "IF idx >= 0 THEN\n"
           " IF idx <= 7 THEN a[idx+2]:=1; END_IF;\n"
           "END_IF;\n")
    statuses = {r.status for r in _of(symbolic.check(P(src)), "CWE-787")}
    assert "violated" not in statuses and "safe" in statuses


def test_else_branch_guard_not_trusted():
    # A guard invalidated by ELSE must not be applied — be conservative (wider
    # interval). Here the unguarded write should be reported violated.
    src = ("VAR a:ARRAY[0..9] OF INT; idx:INT; END_VAR\n"
           "IF idx <= 7 THEN\n"
           " b := 1;\n"
           "ELSE\n"
           " a[idx+2] := 1;\n"
           "END_IF;\n")
    statuses = {r.status for r in _of(symbolic.check(P(src)), "CWE-787")}
    assert "safe" not in statuses


# --- CWE-190 integer overflow -------------------------------------------------

def test_overflow_additive_violation_with_witness():
    src = "VAR x:INT; y:INT; END_VAR\ny := x + 5;\n"
    viol = [r for r in _of(symbolic.check(P(src)), "CWE-190") if r.status == "violated"]
    assert viol and viol[0].witness == {"x": 32767}
    assert "32772" in viol[0].rationale  # 32767 + 5


def test_overflow_multiplicative_violation_with_witness():
    src = "VAR x:INT; y:INT; END_VAR\ny := 2 * x;\n"
    viol = [r for r in _of(symbolic.check(P(src)), "CWE-190") if r.status == "violated"]
    assert viol and viol[0].witness is not None and "x" in viol[0].witness


# --- CWE-191 integer underflow ------------------------------------------------

def test_underflow_violation_with_witness():
    src = "VAR x:INT; y:INT; END_VAR\ny := x - 5;\n"
    viol = [r for r in _of(symbolic.check(P(src)), "CWE-191") if r.status == "violated"]
    assert viol and viol[0].witness == {"x": -32768}


# --- guarded -> safe ----------------------------------------------------------

def test_overflow_guarded_safe():
    src = ("VAR x:INT; y:INT; END_VAR\n"
           "IF x <= 100 THEN\n"
           " IF x >= 0 THEN\n"
           "  y := x + 5;\n"
           " END_IF;\n"
           "END_IF;\n")
    res = _of(symbolic.check(P(src)), "CWE-190")
    assert res and all(r.status != "violated" for r in res)
    assert any(r.status == "safe" for r in res)


# --- non-linear -> unknown (never a false safe) -------------------------------

def test_overflow_nonlinear_unknown():
    src = "VAR x:INT; y:INT; END_VAR\ny := x * x;\n"
    res = _of(symbolic.check(P(src)), "CWE-190")
    assert res and any(r.status == "unknown" for r in res)
    assert all(r.status != "safe" for r in res)


# --- the overflow check must not double-flag div/index statements -------------

def test_division_statement_not_flagged_as_overflow():
    src = "VAR x:INT; y:INT; r:INT; END_VAR\nr:=x/y;\n"
    cwes = {r.cwe for r in symbolic.check(P(src))}
    assert "CWE-190" not in cwes and "CWE-191" not in cwes


def test_bare_copy_assignment_not_flagged():
    # `y := x;` is a plain copy with no arithmetic — no overflow finding.
    src = "VAR x:INT; y:INT; END_VAR\ny := x;\n"
    res = _of(symbolic.check(P(src)), "CWE-190") + _of(symbolic.check(P(src)), "CWE-191")
    assert res == []
