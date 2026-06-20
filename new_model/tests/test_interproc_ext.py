"""Extended interprocedural taint tests: per-sink CWE classification, full
multi-level source->sink path reporting, and callee-side sanitization.

These complement the two interproc tests in test_beyond_frontier.py (which must
keep passing) and exercise the refinements added to advanced/interproc.py.
"""
import interproc
from schema import Program


def P(s, pid="t.st"):
    return Program(pid, pid, s, [])


# --- Task 1: refine CWE per sink kind ---------------------------------------

def test_array_sink_is_cwe_787():
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[pos]:=7;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Writer(pos := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings
    assert findings[0].cwe == "CWE-787"


def test_division_sink_is_cwe_369():
    src = ("FUNCTION_BLOCK Divider\nVAR_INPUT\n d:INT;\nEND_VAR\n"
           "VAR\n r:INT;\nEND_VAR\n r := 100 / d;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Divider(d := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings
    assert findings[0].cwe == "CWE-369"


def test_param_reaching_two_sink_kinds_recorded_in_summary():
    # one param feeds both an array index AND a divisor -> both CWEs in summary.
    src = ("FUNCTION_BLOCK Both\nVAR_INPUT\n p:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT; r:INT;\nEND_VAR\n"
           " buf[p]:=1;\n r := 100 / p;\nEND_FUNCTION_BLOCK\n")
    summaries = interproc.build_summaries(src)
    s = summaries["Both"]
    assert "p" in s.sink_params                 # backward-compatible set still works
    assert s.sink_kinds["p"] == {"CWE-787", "CWE-369"}


# --- Task 2: full source->sink path across multi-level chains ----------------

def test_two_level_chain_path_includes_both_calls():
    # PROGRAM -> FB_A -> FB_B(sink). Path must mention both hops and the sink.
    src = ("FUNCTION_BLOCK FB_B\nVAR_INPUT\n b:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[b]:=7;\nEND_FUNCTION_BLOCK\n"
           "FUNCTION_BLOCK FB_A\nVAR_INPUT\n a:INT;\nEND_VAR\n"
           "FB_B(b := a);\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "FB_A(a := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings
    joined = " ".join(findings[0].path)
    assert "FB_A(a:=field)" in joined
    assert "FB_B(b:=a)" in joined
    assert "FB_B" in joined and "CWE-787" in joined
    assert findings[0].cwe == "CWE-787"
    # source is recorded
    assert any(p.startswith("source:field") for p in findings[0].path)


def test_three_level_chain_propagates_division_cwe():
    src = ("FUNCTION_BLOCK C\nVAR_INPUT\n c:INT;\nEND_VAR\n"
           "VAR\n r:INT;\nEND_VAR\n r := 9 / c;\nEND_FUNCTION_BLOCK\n"
           "FUNCTION_BLOCK B\nVAR_INPUT\n b:INT;\nEND_VAR\n"
           "C(c := b);\nEND_FUNCTION_BLOCK\n"
           "FUNCTION_BLOCK A\nVAR_INPUT\n a:INT;\nEND_VAR\n"
           "B(b := a);\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "A(a := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings
    joined = " ".join(findings[0].path)
    assert findings[0].cwe == "CWE-369"
    assert "A(a:=field)" in joined and "B(b:=a)" in joined and "C(c:=b)" in joined


# --- Task 3: callee-side sanitization ----------------------------------------

def test_unguarded_callee_sink_is_reported():
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[pos]:=7;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Writer(pos := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings and findings[0].cwe == "CWE-787"


def test_guarded_array_sink_is_not_reported():
    # same sink, now enclosed by a guard constraining the param -> sanitized.
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n"
           " IF pos >= 0 AND pos <= 9 THEN buf[pos]:=7; END_IF;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Writer(pos := field);\nEND_PROGRAM\n")
    assert interproc.analyze(P(src)) == []


def test_guarded_division_sink_is_not_reported():
    src = ("FUNCTION_BLOCK Divider\nVAR_INPUT\n d:INT;\nEND_VAR\n"
           "VAR\n r:INT;\nEND_VAR\n"
           " IF d <> 0 THEN r := 100 / d; END_IF;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Divider(d := field);\nEND_PROGRAM\n")
    assert interproc.analyze(P(src)) == []


def test_guard_on_other_var_does_not_sanitize():
    # guard constrains a different variable, NOT the sink param -> still reported
    # (soundness: do not suppress when guard does not reference the sink param).
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT; flag:INT;\nEND_VAR\n"
           " IF flag <> 0 THEN buf[pos]:=7; END_IF;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Writer(pos := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings and findings[0].cwe == "CWE-787"


def test_div_guard_does_not_sanitize_array_sink_of_same_param():
    # param guarded for division only; an UNGUARDED array sink on it stays reported.
    src = ("FUNCTION_BLOCK Mixed\nVAR_INPUT\n p:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT; r:INT;\nEND_VAR\n"
           " IF p <> 0 THEN r := 100 / p; END_IF;\n buf[p]:=1;\nEND_FUNCTION_BLOCK\n")
    summaries = interproc.build_summaries(src)
    kinds = summaries["Mixed"].sink_kinds.get("p", set())
    assert kinds == {"CWE-787"}        # division sanitized, array sink remains
