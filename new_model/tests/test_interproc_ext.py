"""Extended interprocedural-taint tests: per-sink CWE precision,
interprocedural sanitization (guarded sinks), and output->sink taint chains.

These complement the two baseline interproc tests in test_beyond_frontier.py.
"""
import interproc
from schema import Program


def P(s, pid="t.st"):
    return Program(pid, pid, s, [])


def _cwes(findings):
    return {f.cwe for f in findings}


# --- 1. per-sink CWE precision: division sink reports CWE-369 -----------------

def test_division_sink_chain_reports_cwe369():
    src = ("FUNCTION_BLOCK Divider\nVAR_INPUT\n d:INT;\nEND_VAR\n"
           "VAR\n r:INT;\nEND_VAR\n r:=100/d;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Divider(d := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings, "division sink reachable from tainted input should be reported"
    assert _cwes(findings) == {"CWE-369"}, "division sink must be CWE-369, not 787"
    assert "Divider" in " ".join(findings[0].path)


# --- 1b. per-sink CWE precision: array-index sink reports CWE-787 -------------

def test_index_sink_chain_reports_cwe787():
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[pos]:=7;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Writer(pos := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings
    assert _cwes(findings) == {"CWE-787"}
    assert "Writer" in " ".join(findings[0].path)


# --- 2. interprocedural sanitization: guarded sink excluded, unguarded found --

def test_guarded_sink_excluded_unguarded_found():
    # Safe FB: the index sink is dominated by a guard constraining `pos`.
    guarded_src = (
        "FUNCTION_BLOCK SafeWriter\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
        "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n"
        "IF pos >= 0 AND pos <= 9 THEN\n buf[pos]:=1;\n END_IF;\n"
        "END_FUNCTION_BLOCK\n"
        "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
        "SafeWriter(pos := field);\nEND_PROGRAM\n")
    assert interproc.analyze(P(guarded_src)) == [], \
        "a sink dominated by a guard on its param must be treated as sanitized"

    # Analogous unguarded FB: same sink without the guard -> must be reported.
    unguarded_src = (
        "FUNCTION_BLOCK UnsafeWriter\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
        "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n"
        " buf[pos]:=1;\n"
        "END_FUNCTION_BLOCK\n"
        "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
        "UnsafeWriter(pos := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(unguarded_src))
    assert findings and _cwes(findings) == {"CWE-787"}


def test_guarded_division_sink_excluded():
    guarded_src = (
        "FUNCTION_BLOCK SafeDiv\nVAR_INPUT\n d:INT;\nEND_VAR\n"
        "VAR\n r:INT;\nEND_VAR\n"
        "IF d <> 0 THEN\n r:=100/d;\n END_IF;\n"
        "END_FUNCTION_BLOCK\n"
        "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
        "SafeDiv(d := field);\nEND_PROGRAM\n")
    assert interproc.analyze(P(guarded_src)) == []


# --- 3. output-param / two-hop taint chain -----------------------------------

def test_two_hop_output_to_sink_chain():
    # FB1 copies its tainted input to an output; main binds that output to `mid`
    # via `out =>`, then passes `mid` into FB2's index sink. Two-hop chain.
    src = (
        "FUNCTION_BLOCK Passthrough\nVAR_INPUT\n inp:INT;\nEND_VAR\n"
        "VAR_OUTPUT\n outp:INT;\nEND_VAR\n outp := inp;\nEND_FUNCTION_BLOCK\n"
        "FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
        "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[pos]:=7;\nEND_FUNCTION_BLOCK\n"
        "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
        "VAR\n mid:INT;\nEND_VAR\n"
        "Passthrough(inp := field, outp => mid);\n"
        "Writer(pos := mid);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings, "taint should flow through FB output into second FB's sink"
    assert _cwes(findings) == {"CWE-787"}
    joined = " ".join(p for f in findings for p in f.path)
    assert "Writer" in joined


def test_two_hop_output_untainted_input_no_finding():
    # Same shape but `field` is a local (untainted) -> no flow, no finding.
    src = (
        "FUNCTION_BLOCK Passthrough\nVAR_INPUT\n inp:INT;\nEND_VAR\n"
        "VAR_OUTPUT\n outp:INT;\nEND_VAR\n outp := inp;\nEND_FUNCTION_BLOCK\n"
        "FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
        "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[pos]:=7;\nEND_FUNCTION_BLOCK\n"
        "PROGRAM main\n"
        "VAR\n field:INT; mid:INT;\nEND_VAR\n"
        "Passthrough(inp := field, outp => mid);\n"
        "Writer(pos := mid);\nEND_PROGRAM\n")
    assert interproc.analyze(P(src)) == []
