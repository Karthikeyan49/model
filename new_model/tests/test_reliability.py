"""Tests for the reliability layer: calibration, metamorphic, drift, active
learning, provenance, RAG, regression gate."""
import active_learning as al
import calibration_metrics as cm
import drift
import metamorphic
import provenance
import rag_triage
import regression_gate as rg
from schema import ArmResult, Finding, Label, Program
from scoring import ScoredFinding


def _prog(pid, source, labels=None):
    return Program(pid=pid, path=pid, source=source, labels=labels or [])


# --- calibration metrics -----------------------------------------------------

def test_perfect_calibration_low_ece():
    # confidence == accuracy in each bin -> ECE ~ 0
    pairs = [(0.95, True)] * 9 + [(0.95, False)]      # 0.9 conf bin, 0.9 acc
    rep = cm.evaluate(pairs, n_bins=10)
    assert rep.ece < 0.06
    assert 0.0 <= rep.brier <= 1.0


def test_miscalibration_detected():
    # high confidence but always wrong -> large ECE
    pairs = [(0.95, False)] * 10
    rep = cm.evaluate(pairs, n_bins=10)
    assert rep.ece > 0.8


# --- metamorphic robustness --------------------------------------------------

def test_metamorphic_stable_detector():
    # detector that keys off the array-index pattern is invariant to renaming/comments
    def detector(p):
        out = []
        for i, ln in enumerate(p.source.splitlines(), 1):
            if "[" in ln and "+" in ln and "]" in ln:
                out.append(Finding(p.pid, i, "CWE-787", "high"))
        return out
    prog = _prog("a.st", "VAR\nbuf[i + 1] := 5;\nEND_VAR\n")
    res = metamorphic.assess(prog, detector, n_variants=3)
    assert res.stable and res.stability == 1.0


def test_metamorphic_flags_brittle_detector():
    # detector that gives up when it sees a comment -> breaks under comment insertion
    def brittle(p):
        if "(*" in p.source:
            return []
        return [Finding(p.pid, 1, "CWE-787", "high")]
    prog = _prog("a.st", "buf[i + 1] := 5;\n")
    res = metamorphic.assess(prog, brittle, n_variants=3)
    assert not res.stable      # comment-insertion variant drops the finding


# --- drift -------------------------------------------------------------------

def test_drift_stable_when_same_distribution():
    ref = [0.1, 0.2, 0.8, 0.9, 0.5, 0.85, 0.15]
    rep = drift.assess(ref, list(ref))
    assert rep.drift == "stable" and not rep.recalibrate


def test_drift_significant_when_shifted():
    ref = [0.05, 0.1, 0.15, 0.2, 0.1, 0.08]
    cur = [0.9, 0.95, 0.85, 0.92, 0.88, 0.99]
    rep = drift.assess(ref, cur)
    assert rep.drift == "significant" and rep.recalibrate


# --- active learning ---------------------------------------------------------

def test_active_learning_margin_priority():
    thr = 0.6
    scored = [ScoredFinding(Finding("a", 1, "CWE-1"), 0.59),   # closest to thr
              ScoredFinding(Finding("a", 2, "CWE-2"), 0.10)]
    q = al.select(scored, thr, k=2, strategy="margin", diversify=False)
    assert q[0].scored.finding.line == 1   # nearest-threshold first


def test_active_learning_diversifies():
    thr = 0.5
    scored = [ScoredFinding(Finding("a", i, "CWE-1"), 0.49) for i in range(3)]
    scored.append(ScoredFinding(Finding("a", 9, "CWE-2"), 0.45))
    q = al.select(scored, thr, k=2, strategy="margin", diversify=True)
    assert {q[0].scored.finding.cwe, q[1].scored.finding.cwe} == {"CWE-1", "CWE-2"}


# --- provenance --------------------------------------------------------------

def test_provenance_hash_roundtrip_and_tamper():
    f = Finding("a.st", 6, "CWE-787", "high")
    ev = provenance.Evidence(analyzer_rule="out-of-bounds", grounded=True,
                             self_consistency_votes="6/7", decision="emit",
                             confidence=0.78)
    rec = provenance.build(f, ev)
    assert provenance.verify(rec)
    rec.evidence.confidence = 0.99     # tamper
    assert not provenance.verify(rec)


# --- RAG triage --------------------------------------------------------------

def test_rag_retrieves_matching_cwe_context():
    exemplars = [
        rag_triage.Exemplar("CWE-787", "a[i + 1] := x;", "IF i < n THEN a[i] := x;"),
        rag_triage.Exemplar("CWE-369", "y := x / 0;", "IF d <> 0 THEN y := x / d;"),
    ]
    ctx = rag_triage.retrieve("buf[idx + 2] := 9;", "CWE-787", exemplars, k=1)
    assert "Out-of-bounds" in ctx["cwe_description"]
    assert ctx["exemplars"][0].cwe == "CWE-787"
    prompt = rag_triage.build_grounded_prompt("buf[idx+2]:=9;", "CWE-787", 6, ctx)
    assert "CWE-787" in prompt and "do not invent" in prompt


# --- regression gate ---------------------------------------------------------

def test_regression_gate_fails_on_lost_finding():
    result = ArmResult("C", [], precision=1.0, recall=1.0, f1=1.0, fp_rate=0.0,
                       tp=1, fp=0, fn=0)
    golden = {"min_recall": 0.8, "min_precision": 0.7,
              "must_find": [{"pid": "x.st", "cwe": "CWE-787"}]}
    gate = rg.evaluate(result, [], golden)      # nothing found
    assert not gate.passed
    assert any("lost finding" in f for f in gate.failures)


def test_regression_gate_passes_when_met():
    findings = [Finding("x.st", 6, "CWE-787", "high")]
    result = ArmResult("C", findings, precision=1.0, recall=1.0, f1=1.0, fp_rate=0.0,
                       tp=1, fp=0, fn=0)
    golden = {"min_recall": 0.8, "min_precision": 0.7,
              "must_find": [{"pid": "x.st", "cwe": "CWE-787"}]}
    assert rg.evaluate(result, findings, golden).passed
