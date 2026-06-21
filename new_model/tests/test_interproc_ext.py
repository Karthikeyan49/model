"""Extended tests for interprocedural taint: CWE refinement by sink kind,
interprocedural sanitization via dominating bounds-guards, full call-chain paths
and de-duplication. Defensive-only (detection) reasoning."""
import interproc
from schema import Program


def P(s, pid="t.st"):
    return Program(pid, pid, s, [])


# --- (1) CWE refinement by sink kind -----------------------------------------

def test_interproc_division_sink_reports_cwe369_not_787():
    src = ("FUNCTION_BLOCK Divider\nVAR_INPUT\n d:INT;\nEND_VAR\n"
           "VAR\n x:INT; r:INT;\nEND_VAR\n r := x / d;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Divider(d := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings, "expected a finding for tainted division denominator"
    cwes = {f.cwe for f in findings}
    assert cwes == {"CWE-369"}, cwes


def test_interproc_index_sink_reports_cwe787():
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[pos]:=7;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Writer(pos := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings and {f.cwe for f in findings} == {"CWE-787"}


def test_interproc_param_reaching_both_sinks_reports_both():
    src = ("FUNCTION_BLOCK Both\nVAR_INPUT\n p:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT; x:INT; r:INT;\nEND_VAR\n"
           " buf[p]:=7;\n r := x / p;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Both(p := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert {f.cwe for f in findings} == {"CWE-787", "CWE-369"}


# --- (2) interprocedural sanitization ----------------------------------------

def test_interproc_index_sanitized_by_bounds_guard_no_finding():
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n"
           " IF pos >= 0 AND pos <= 9 THEN buf[pos]:=7; END_IF;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Writer(pos := field);\nEND_PROGRAM\n")
    assert interproc.analyze(P(src)) == []


def test_interproc_division_sanitized_by_nonzero_guard_no_finding():
    src = ("FUNCTION_BLOCK Divider\nVAR_INPUT\n d:INT;\nEND_VAR\n"
           "VAR\n x:INT; r:INT;\nEND_VAR\n"
           " IF d <> 0 THEN r := x / d; END_IF;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Divider(d := field);\nEND_PROGRAM\n")
    assert interproc.analyze(P(src)) == []


def test_interproc_unguarded_sink_still_reports():
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[pos]:=7;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Writer(pos := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings and findings[0].cwe == "CWE-787"


def test_interproc_guard_on_other_var_does_not_sanitize():
    # guard constrains a DIFFERENT variable -> param still a sink (sound).
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT; other:INT;\nEND_VAR\n"
           " IF other >= 0 THEN buf[pos]:=7; END_IF;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Writer(pos := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings and findings[0].cwe == "CWE-787"


# --- (3) full call-chain path + dedup ----------------------------------------

def test_interproc_multihop_chain_names_both_fbs():
    src = ("FUNCTION_BLOCK FB2\nVAR_INPUT\n q:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[q]:=7;\nEND_FUNCTION_BLOCK\n"
           "FUNCTION_BLOCK FB1\nVAR_INPUT\n p:INT;\nEND_VAR\n"
           "FB2(q := p);\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "FB1(p := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings
    joined = " ".join(findings[0].path)
    assert "FB1" in joined and "FB2" in joined
    assert findings[0].cwe == "CWE-787"
    assert "sink in FB2" in findings[0].path


def test_interproc_findings_are_deduped():
    # Same call repeated -> a single deduped finding per (program, cwe, path).
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[pos]:=7;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Writer(pos := field);\nWriter(pos := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert len(findings) == 1, findings


def test_interproc_no_taint_when_untainted_arg():
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[pos]:=7;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR\n localc:INT;\nEND_VAR\n"
           "Writer(pos := localc);\nEND_PROGRAM\n")
    assert interproc.analyze(P(src)) == []
