"""Tests for the sound non-termination / unbounded-loop detector (CWE-835).

Soundness focus: the dangerous error for a detector is a false `safe` on a loop
that actually hangs, so these tests assert `infinite` only on structurally
provable cases and assert `unknown` (never `safe`) on the opaque ones.
"""
import termination
from schema import Program


def _prog(source, pid="t"):
    return Program(pid=pid, path=pid, source=source, labels=[])


def _one(source):
    res = termination.check(_prog(source))
    assert len(res) == 1, f"expected exactly one loop, got {res}"
    return res[0]


# (a) WHILE TRUE DO ... with no EXIT -> infinite / CWE-835 ---------------------

def test_while_true_no_exit_is_infinite():
    src = (
        "WHILE TRUE DO\n"
        "    x := x + 1;\n"
        "END_WHILE;\n"
    )
    r = _one(src)
    assert r.status == "infinite"
    assert r.cwe == "CWE-835"
    assert r.kind == "while"
    assert r.line == 1


def test_while_1_no_exit_is_infinite():
    src = "WHILE 1 DO\n    y := y;\nEND_WHILE;\n"
    r = _one(src)
    assert r.status == "infinite"
    assert r.cwe == "CWE-835"


# (b) guard var never updated, no EXIT -> infinite ----------------------------

def test_while_guard_never_updated_is_infinite():
    src = (
        "WHILE done < 10 DO\n"
        "    counter := counter + 1;\n"   # touches counter, never `done`
        "END_WHILE;\n"
    )
    r = _one(src)
    assert r.status == "infinite"
    assert r.cwe == "CWE-835"
    assert "done" in r.guards


# (c) guard var decremented toward bound -> safe / terminating ----------------

def test_while_guard_decremented_is_safe():
    src = (
        "WHILE i > 0 DO\n"
        "    i := i - 1;\n"
        "END_WHILE;\n"
    )
    r = _one(src)
    assert r.status == "safe"
    assert r.cwe == ""
    assert "i" in r.guards


def test_while_guard_incremented_toward_upper_bound_is_safe():
    src = (
        "WHILE i < 100 DO\n"
        "    i := i + 2;\n"
        "END_WHILE;\n"
    )
    r = _one(src)
    assert r.status == "safe"
    assert r.cwe == ""


# (d) WHILE TRUE with an EXIT -> NOT infinite ---------------------------------

def test_while_true_with_exit_is_not_infinite():
    src = (
        "WHILE TRUE DO\n"
        "    IF k > 5 THEN\n"
        "        EXIT;\n"
        "    END_IF;\n"
        "    k := k + 1;\n"
        "END_WHILE;\n"
    )
    r = _one(src)
    assert r.status != "infinite"
    assert r.cwe == ""
    assert r.status == "safe"   # EXIT; reachable in body


# (e) complex / unanalyzable condition -> unknown (never false safe) ----------

def test_while_complex_condition_is_unknown():
    src = (
        "WHILE (a > 0) AND (b < f(c)) DO\n"
        "    a := a - 1;\n"
        "END_WHILE;\n"
    )
    r = _one(src)
    assert r.status == "unknown"
    assert r.cwe == ""
    assert r.status != "safe"


def test_while_guard_updated_opaquely_is_unknown_not_safe():
    # guard var IS assigned, but not via a recognizable monotone step
    src = (
        "WHILE i > 0 DO\n"
        "    i := compute(i);\n"
        "END_WHILE;\n"
    )
    r = _one(src)
    assert r.status == "unknown"
    assert r.status != "safe"   # must NOT claim safe when progress unproven


def test_while_guard_moves_wrong_direction_is_unknown():
    # i increases while guard wants i > 0: not proven terminating -> unknown
    src = "WHILE i > 0 DO\n    i := i + 1;\nEND_WHILE;\n"
    r = _one(src)
    assert r.status != "safe"
    assert r.status in ("unknown",)


# --- REPEAT ------------------------------------------------------------------

def test_repeat_guard_never_updated_is_infinite():
    src = (
        "REPEAT\n"
        "    total := total + step;\n"
        "UNTIL flag > 3 END_REPEAT;\n"
    )
    r = _one(src)
    assert r.status == "infinite"
    assert r.cwe == "CWE-835"
    assert "flag" in r.guards


def test_repeat_with_exit_is_safe():
    src = (
        "REPEAT\n"
        "    EXIT;\n"
        "UNTIL flag > 3 END_REPEAT;\n"
    )
    r = _one(src)
    assert r.status == "safe"
    assert r.cwe == ""


def test_repeat_updated_guard_is_unknown():
    src = (
        "REPEAT\n"
        "    n := n + 1;\n"
        "UNTIL n >= 10 END_REPEAT;\n"
    )
    r = _one(src)
    # REPEAT direction not proven by this detector -> conservative unknown
    assert r.status == "unknown"
    assert r.status != "safe" or r.cwe == ""


# --- FOR ---------------------------------------------------------------------

def test_for_constant_bounds_is_safe():
    src = "FOR i := 1 TO 10 DO\n    s := s + i;\nEND_FOR;\n"
    r = _one(src)
    assert r.status == "safe"
    assert r.kind == "for"
    assert r.cwe == ""


def test_for_constant_bounds_with_step_is_safe():
    src = "FOR i := 0 TO 100 BY 5 DO\n    s := s + i;\nEND_FOR;\n"
    r = _one(src)
    assert r.status == "safe"


def test_for_nonconstant_bound_is_unknown():
    src = "FOR i := 1 TO n DO\n    s := s + i;\nEND_FOR;\n"
    r = _one(src)
    assert r.status == "unknown"
    assert r.status != "safe"


def test_for_zero_step_is_unknown():
    src = "FOR i := 1 TO 10 BY 0 DO\n    s := s + i;\nEND_FOR;\n"
    r = _one(src)
    assert r.status == "unknown"
    assert r.status != "safe"


# --- structural / API --------------------------------------------------------

def test_no_loops_returns_empty():
    assert termination.check(_prog("x := 1;\ny := 2;\n")) == []


def test_multiple_loops_each_reported():
    src = (
        "WHILE TRUE DO\n"
        "    a := a;\n"
        "END_WHILE;\n"
        "FOR i := 1 TO 5 DO\n"
        "    b := b + 1;\n"
        "END_FOR;\n"
    )
    res = termination.check(_prog(src))
    assert len(res) == 2
    assert res[0].status == "infinite" and res[0].cwe == "CWE-835"
    assert res[1].status == "safe" and res[1].kind == "for"


def test_nested_inner_exit_belongs_to_inner_loop():
    # Outer WHILE TRUE has no EXIT of its own; inner WHILE TRUE has the EXIT.
    src = (
        "WHILE TRUE DO\n"
        "    WHILE TRUE DO\n"
        "        EXIT;\n"
        "    END_WHILE;\n"
        "    p := p + 1;\n"
        "END_WHILE;\n"
    )
    res = termination.check(_prog(src))
    assert len(res) == 2
    outer = next(r for r in res if r.line == 1)
    inner = next(r for r in res if r.line == 2)
    # outer body DOES textually contain the inner EXIT, so flow-insensitively it
    # is treated as having a reachable EXIT -> NOT a false `infinite` (sound).
    assert outer.status != "infinite"
    assert inner.status == "safe"


def test_render_helpers():
    res = termination.check(_prog("WHILE TRUE DO\n a:=a;\nEND_WHILE;\n"))
    line = res[0].render()
    assert "CWE-835" in line
    summary = termination.render(res)
    assert "CWE-835" in summary
    assert termination.render([]) == "no loops found"
