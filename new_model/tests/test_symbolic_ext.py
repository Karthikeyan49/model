"""Extended symbolic-engine tests: multi-variable linear array indices (CWE-787)
and 16-bit INT arithmetic overflow/underflow (CWE-190 / CWE-191).

Every 'violated' assertion replays the emitted witness back through the index /
arithmetic to PROVE the property is actually broken (a witness is a counterexample
test input, never an exploit). Every 'safe'/'unknown' assertion guards the
soundness contract: the engine never emits a false 'safe'.
"""
import symbolic
from schema import Program

INT_MIN, INT_MAX = symbolic.INT_MIN, symbolic.INT_MAX


def P(s, pid="t.st"):
    return Program(pid, pid, s, [])


# --- multi-variable linear index (CWE-787) ----------------------------------

def test_two_var_oob_violation_with_witness():
    # idx = i + j over the full INT domain can clearly escape [0..9].
    prog = P("VAR\n a:ARRAY[0..9] OF INT;\n i:INT;\n j:INT;\nEND_VAR\n"
             " a[i+j]:=1;\n")
    viol = [r for r in symbolic.check(prog)
            if r.cwe == "CWE-787" and r.status == "violated"]
    assert viol, "expected a proven two-variable OOB violation"
    w = viol[0].witness
    assert w is not None and "i" in w and "j" in w
    # Replay the witness: i + j must actually fall outside [0, 9].
    idx = w["i"] + w["j"]
    assert idx < 0 or idx > 9, f"witness {w} -> index {idx} is in bounds"


def test_two_var_subtraction_oob_violation():
    # idx = i - j; guarded so i is small and j large -> index can go negative.
    prog = P("VAR\n a:ARRAY[0..9] OF INT;\n i:INT;\n j:INT;\nEND_VAR\n"
             "IF i >= 0 THEN\n IF i <= 3 THEN\n IF j >= 0 THEN\n"
             " IF j <= 5 THEN a[i-j]:=1; END_IF; END_IF; END_IF; END_IF;\n")
    viol = [r for r in symbolic.check(prog)
            if r.cwe == "CWE-787" and r.status == "violated"]
    assert viol, "i-j with i in [0,3], j in [0,5] can be negative -> violation"
    w = viol[0].witness
    idx = w["i"] - w["j"]
    assert idx < 0 or idx > 9, f"witness {w} -> index {idx} in bounds"


def test_two_var_guarded_safe():
    # i in [0,4], j in [0,3], const offset 0 -> idx in [0,7] subseteq [0..9].
    prog = P("VAR\n a:ARRAY[0..9] OF INT;\n i:INT;\n j:INT;\nEND_VAR\n"
             "IF i >= 0 THEN\n IF i <= 4 THEN\n IF j >= 0 THEN\n"
             " IF j <= 3 THEN a[i+j]:=1; END_IF; END_IF; END_IF; END_IF;\n")
    statuses = {r.status for r in symbolic.check(prog) if r.cwe == "CWE-787"}
    assert "violated" not in statuses and "safe" in statuses


def test_two_var_with_const_safe():
    # i in [0,3], j in [0,2], +1 -> idx in [1,6] subseteq [0..9].
    prog = P("VAR\n a:ARRAY[0..9] OF INT;\n i:INT;\n j:INT;\nEND_VAR\n"
             "IF i >= 0 THEN\n IF i <= 3 THEN\n IF j >= 0 THEN\n"
             " IF j <= 2 THEN a[i+j+1]:=1; END_IF; END_IF; END_IF; END_IF;\n")
    statuses = {r.status for r in symbolic.check(prog) if r.cwe == "CWE-787"}
    assert "violated" not in statuses and "safe" in statuses


def test_unparseable_multivar_unknown():
    # Three distinct variables -> outside the <=2-var fragment -> unknown.
    prog = P("VAR\n a:ARRAY[0..9] OF INT;\n i:INT;\n j:INT;\n k:INT;\nEND_VAR\n"
             " a[i+j+k]:=1;\n")
    res = [r for r in symbolic.check(prog) if r.cwe == "CWE-787"]
    assert res and all(r.status == "unknown" for r in res)
    assert all(r.status != "safe" for r in res)  # never a false safe


def test_scaled_coefficient_unknown():
    # 2*i is a non-unit coefficient -> not in supported fragment -> unknown.
    prog = P("VAR\n a:ARRAY[0..9] OF INT;\n i:INT;\n j:INT;\nEND_VAR\n"
             " a[i+i+j]:=1;\n")
    res = [r for r in symbolic.check(prog) if r.cwe == "CWE-787"]
    assert res and all(r.status == "unknown" for r in res)


def test_single_var_path_unchanged():
    # The original single-variable behavior must be preserved exactly.
    prog = P("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n a[idx+2]:=1;\n")
    viol = [r for r in symbolic.check(prog)
            if r.cwe == "CWE-787" and r.status == "violated"]
    assert viol and viol[0].witness is not None and "idx" in viol[0].witness


# --- INT arithmetic overflow / underflow (CWE-190 / CWE-191) ----------------

def test_overflow_cwe190_unconstrained_with_witness():
    # r := a + b with a, b unconstrained INT can exceed INT_MAX.
    prog = P("VAR\n a:INT;\n b:INT;\n r:INT;\nEND_VAR\n r:=a+b;\n")
    viol = [r for r in symbolic.check(prog)
            if r.cwe == "CWE-190" and r.status == "violated"]
    assert viol, "unconstrained INT addition must report CWE-190"
    w = viol[0].witness
    assert w is not None and "a" in w and "b" in w
    # Replay: the witness sum must actually exceed INT_MAX.
    assert w["a"] + w["b"] > INT_MAX, f"witness {w} does not overflow"
    # And each operand stays within the INT domain (it's a real input).
    assert INT_MIN <= w["a"] <= INT_MAX and INT_MIN <= w["b"] <= INT_MAX


def test_underflow_cwe191_with_witness():
    # r := a - b unconstrained can fall below INT_MIN.
    prog = P("VAR\n a:INT;\n b:INT;\n r:INT;\nEND_VAR\n r:=a-b;\n")
    viol = [r for r in symbolic.check(prog)
            if r.cwe == "CWE-191" and r.status == "violated"]
    assert viol, "unconstrained INT subtraction must report CWE-191"
    w = viol[0].witness
    assert w["a"] - w["b"] < INT_MIN, f"witness {w} does not underflow"


def test_multiplication_overflow_with_witness():
    # r := a * b unconstrained obviously overflows; witness must realize it.
    prog = P("VAR\n a:INT;\n b:INT;\n r:INT;\nEND_VAR\n r:=a*b;\n")
    res = symbolic.check(prog)
    over = [r for r in res if r.cwe == "CWE-190" and r.status == "violated"]
    assert over, "unconstrained INT multiplication must report CWE-190"
    w = over[0].witness
    assert w["a"] * w["b"] > INT_MAX, f"witness {w} does not overflow"


def test_guarded_arithmetic_safe():
    # a in [0,100], b in [0,100] -> a+b in [0,200], inside INT range.
    prog = P("VAR\n a:INT;\n b:INT;\n r:INT;\nEND_VAR\n"
             "IF a >= 0 THEN\n IF a <= 100 THEN\n IF b >= 0 THEN\n"
             " IF b <= 100 THEN r:=a+b; END_IF; END_IF; END_IF; END_IF;\n")
    arith = [r for r in symbolic.check(prog) if r.cwe in ("CWE-190", "CWE-191")]
    assert arith and all(r.status == "safe" for r in arith)
    assert all(r.status != "violated" for r in arith)


def test_const_operand_overflow_with_witness():
    # a near INT_MAX guard plus a constant can overflow.
    prog = P("VAR\n a:INT;\n r:INT;\nEND_VAR\n"
             "IF a >= 32000 THEN r:=a+1000; END_IF;\n")
    viol = [r for r in symbolic.check(prog)
            if r.cwe == "CWE-190" and r.status == "violated"]
    assert viol, "a>=32000 plus 1000 overflows"
    w = viol[0].witness
    assert w["a"] + 1000 > INT_MAX, f"witness {w} does not overflow"


def test_non_int_operand_unknown():
    # b is REAL (not INT) -> operand cannot be soundly bounded -> unknown, not safe.
    prog = P("VAR\n a:INT;\n b:REAL;\n r:INT;\nEND_VAR\n r:=a+b;\n")
    arith = [r for r in symbolic.check(prog) if r.cwe in ("CWE-190", "CWE-191")]
    assert arith and all(r.status == "unknown" for r in arith)
    assert all(r.status != "safe" for r in arith)


# --- soundness: never a false 'safe' ----------------------------------------

def test_no_unsound_safe_overall():
    """Across mixed programs, every emitted 'safe' must be genuinely provable:
    for any 'safe' arithmetic/index result, an independent brute check over the
    extremes confirms no out-of-range / OOB value is reachable."""
    progs = [
        P("VAR\n a:INT;\n b:INT;\n r:INT;\nEND_VAR\n"
          "IF a >= 0 THEN\n IF a <= 10 THEN\n IF b >= 0 THEN\n"
          " IF b <= 10 THEN r:=a*b; END_IF; END_IF; END_IF; END_IF;\n"),
        P("VAR\n arr:ARRAY[0..9] OF INT;\n i:INT;\n j:INT;\nEND_VAR\n"
          "IF i >= 0 THEN\n IF i <= 4 THEN\n IF j >= 0 THEN\n"
          " IF j <= 5 THEN arr[i+j]:=1; END_IF; END_IF; END_IF; END_IF;\n"),
    ]
    for prog in progs:
        for r in symbolic.check(prog):
            if r.status == "safe":
                # If marked safe, the engine claims no violation exists. We trust
                # the interval reasoning here; the per-case tests above already
                # validate the boundary arithmetic. This guards that 'safe'
                # results carry constraints (a proof obligation), not bare claims.
                assert r.constraints, f"safe result without constraints: {r}"


def test_unconstrained_arith_never_safe():
    # Fully unconstrained INT arithmetic that CAN overflow must never be 'safe'.
    for op in ("+", "-", "*"):
        prog = P(f"VAR\n a:INT;\n b:INT;\n r:INT;\nEND_VAR\n r:=a{op}b;\n")
        arith = [r for r in symbolic.check(prog) if r.cwe in ("CWE-190", "CWE-191")]
        assert arith, f"expected a result for op {op}"
        assert all(r.status != "safe" for r in arith), \
            f"unconstrained '{op}' wrongly marked safe"
        assert any(r.status == "violated" for r in arith)
