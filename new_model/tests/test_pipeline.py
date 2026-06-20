"""Unit tests for the core pipeline logic — no network, no real backends."""
import json

import analyzer
import eval as evalmod
import reachability
import sarif
import verify
from schema import Finding, Label, Program


def _prog(pid, source, labels=None):
    return Program(pid=pid, path=pid, source=source, labels=labels or [])


# --- verify: ungrounded findings are dropped --------------------------------

def test_verify_drops_ungrounded():
    cfg = {"eval": {"severity_floor": "low"}}
    findings = [
        Finding("a.st", 3, "CWE-787", "high", "llm", grounded=False),
        Finding("a.st", 3, "CWE-787", "high", "hybrid", grounded=True),
    ]
    kept = verify.verify(findings, cfg)
    assert len(kept) == 1 and kept[0].grounded


def test_verify_dedups_and_respects_floor():
    cfg = {"eval": {"severity_floor": "medium"}}
    findings = [
        Finding("a.st", 1, "CWE-1", "low", grounded=True),     # below floor
        Finding("a.st", 2, "CWE-2", "high", grounded=True),
        Finding("a.st", 2, "CWE-2", "high", grounded=True),    # dup
    ]
    kept = verify.verify(findings, cfg)
    assert len(kept) == 1 and kept[0].cwe == "CWE-2"


# --- eval: scoring math ------------------------------------------------------

def test_eval_precision_recall():
    prog = _prog("a.st", "x\ny\nz\n",
                 labels=[Label(2, "CWE-787", "high")])
    cfg = {"eval": {"severity_floor": "low"}}
    findings = [
        Finding("a.st", 2, "CWE-787", "high"),   # TP
        Finding("a.st", 5, "CWE-369", "high"),   # FP
    ]
    r = evalmod.score("C", findings, [prog], cfg)
    assert r.tp == 1 and r.fp == 1 and r.fn == 0
    assert abs(r.precision - 0.5) < 1e-9
    assert abs(r.recall - 1.0) < 1e-9


def test_eval_line_tolerance():
    prog = _prog("a.st", "\n".join(str(i) for i in range(10)),
                 labels=[Label(5, "CWE-787", "high")])
    cfg = {"eval": {"severity_floor": "low"}}
    # off-by-one line still matches within LINE_TOLERANCE
    r = evalmod.score("C", [Finding("a.st", 6, "CWE-787", "high")], [prog], cfg)
    assert r.tp == 1


# --- analyzer: mock grounds findings ----------------------------------------

def test_mock_analyzer_flags_oob():
    cfg = {"analyzer": {"binary": "definitely-not-installed-xyz", "mock_if_missing": True}}
    prog = _prog("a.st", "VAR\nbuf[i + 1] := 5;\nEND_VAR\n")
    out = analyzer.analyze([prog], cfg)
    assert any(f.cwe == "CWE-787" and f.grounded for f in out)


# --- reachability: drops dead code, annotates ------------------------------

def test_reachability_drops_dead_code():
    src = "PROGRAM p\nRETURN;\nbuf[i + 1] := 5;\nEND_PROGRAM\n"
    prog = _prog("a.st", src)
    f = Finding("a.st", 3, "CWE-787", "high", grounded=True)
    kept = reachability.annotate([f], [prog])
    assert kept == []  # sink after unconditional RETURN is unreachable


def test_reachability_annotates_reachable():
    src = "PROGRAM p\nVAR_INPUT\n i : INT;\nEND_VAR\nbuf[i + 1] := 5;\nEND_PROGRAM\n"
    prog = _prog("a.st", src)
    f = Finding("a.st", 5, "CWE-787", "high", grounded=True)
    kept = reachability.annotate([f], [prog])
    assert len(kept) == 1 and "reachability" in kept[0].explanation


# --- sarif: valid shape ------------------------------------------------------

def test_sarif_shape():
    f = Finding("a.st", 6, "CWE-787", "high", explanation="oob", fix="clamp")
    doc = sarif.to_sarif([f])
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 6
    # round-trips as JSON
    json.loads(json.dumps(doc))
