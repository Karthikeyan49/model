"""Tests for the advanced (research-grounded) layer."""
import conformal
import dataflow
import ensemble
import mockcourt
import router
import scoring
import selfconsistency as sc
from schema import Finding, Label, Program


def _prog(pid, source, labels=None):
    return Program(pid=pid, path=pid, source=source, labels=labels or [])


# --- conformal: FP-rate bound is actually enforced ---------------------------

def test_conformal_threshold_bounds_fp():
    # confidences with a clean separation; alpha=0.1 must keep FP fraction <=0.1
    cal = [(0.9, True), (0.85, True), (0.8, True), (0.4, False),
           (0.3, False), (0.95, True), (0.2, False)]
    thr = conformal.calibrate(cal, alpha=0.1)
    emitted = [(c, t) for c, t in cal if c >= thr.threshold]
    fp = sum(1 for _, t in emitted if not t) / len(emitted)
    assert fp <= 0.1
    assert thr.coverage > 0  # still emits true findings


def test_conformal_abstains_when_uncertain():
    scored = [scoring.ScoredFinding(Finding("a", 1, "CWE-1"), 0.9),
              scoring.ScoredFinding(Finding("a", 2, "CWE-1"), 0.2)]
    thr = conformal.CalibratedThreshold(threshold=0.5, alpha=0.1,
                                        achieved_fp=0.0, coverage=1.0, n_cal=10)
    emitted, abstained = conformal.apply(scored, thr)
    assert len(emitted) == 1 and len(abstained) == 1


# --- self-consistency: confidence == vote fraction ---------------------------

def test_selfconsistency_confidence():
    prog = _prog("a.st", "buf[i+1]:=5;", labels=[Label(1, "CWE-787", "high")])
    sampler = sc.make_mock_sampler(true_rate=1.0, false_rate=0.0)
    res = sc.vote([Finding("a.st", 1, "CWE-787", "high")], [prog], sampler, n_samples=5)
    assert res[0].confidence == 1.0  # always votes real for a true finding


# --- dataflow: taint reaches sink only when unsanitized ----------------------

def test_dataflow_tainted_index_reachable():
    src = ("PROGRAM p\nVAR_INPUT\n idx : INT;\nEND_VAR\n"
           "VAR\n a : ARRAY[0..9] OF INT;\nEND_VAR\n"
           "a[idx] := 1;\nEND_PROGRAM\n")
    assert dataflow.is_reachable(_prog("a.st", src), "CWE-787") is True


def test_dataflow_constant_index_not_reachable():
    src = ("PROGRAM p\nVAR\n a : ARRAY[0..9] OF INT;\nEND_VAR\n"
           "a[3] := 1;\nEND_PROGRAM\n")
    # constant index -> no tainted var flows in
    assert dataflow.is_reachable(_prog("a.st", src), "CWE-787") in (False, None)


def test_dataflow_guard_sanitizes():
    src = ("PROGRAM p\nVAR_INPUT\n idx : INT;\nEND_VAR\n"
           "VAR\n a : ARRAY[0..9] OF INT;\nEND_VAR\n"
           "IF idx < 10 THEN\n a[idx] := 1;\nEND_IF;\nEND_PROGRAM\n")
    # idx is guarded by the IF -> treated as sanitized
    assert dataflow.is_reachable(_prog("a.st", src), "CWE-787") in (False, None)


def test_dataflow_propagation():
    src = ("PROGRAM p\nVAR_INPUT\n raw : INT;\nEND_VAR\n"
           "VAR\n j : INT;\n a : ARRAY[0..9] OF INT;\nEND_VAR\n"
           "j := raw + 1;\n a[j] := 1;\nEND_PROGRAM\n")
    # taint flows raw -> j -> index
    assert dataflow.is_reachable(_prog("a.st", src), "CWE-787") is True


# --- ensemble: fusion weights and reachability veto --------------------------

def test_ensemble_reachability_lowers_confidence():
    prog = _prog("a.st", "x", labels=[])
    f = Finding("a.st", 1, "CWE-787", "high", grounded=True)
    conf_key = {("a.st", 1, "CWE-787"): 0.8}
    high = ensemble.fuse([f], [prog], conf_key, reachability_of=lambda f, p: True)
    low = ensemble.fuse([f], [prog], conf_key, reachability_of=lambda f, p: False)
    assert high[0].confidence > low[0].confidence


# --- router: CWE -> expert ---------------------------------------------------

def test_router_routes_by_cwe():
    cfg = router.load_config()
    assert router.route(Finding("a", 1, "CWE-787"), cfg) == ["memory_safety"]
    assert router.route(Finding("a", 1, "CWE-369"), cfg) == ["arithmetic"]
    # unknown CWE -> default
    assert router.route(Finding("a", 1, "CWE-9999"), cfg) == [cfg["router"]["default_expert"]]


# --- mockcourt: defense overrides on unreachable -----------------------------

def test_mockcourt_dismisses_unreachable():
    prog = _prog("a.st", "x", labels=[])
    f = Finding("a.st", 1, "CWE-787", "high", grounded=True)
    rulings = mockcourt.adjudicate([f], [prog], reachability_of=lambda f, p: False)
    assert rulings[0].verdict == "dismissed"
    rulings2 = mockcourt.adjudicate([f], [prog], reachability_of=lambda f, p: True)
    assert rulings2[0].verdict == "real"
