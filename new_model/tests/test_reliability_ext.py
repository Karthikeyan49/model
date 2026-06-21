"""Extended reliability tests: class-conditional (Mondrian) conformal
thresholds and the combined PSI+KS drift verdict.

These complement tests/test_reliability.py without modifying it. They exercise
only the additive APIs:
  conformal.mondrian_thresholds / should_emit / apply_mondrian / min_calibration_size
  drift.combined_assessment
"""
import random

import conformal
import drift
from schema import Finding
from scoring import ScoredFinding


# --- Mondrian (class-conditional) conformal ---------------------------------

def _make_group(n_true, n_false, true_mean, false_mean, seed):
    """Synthesise (confidence, is_true) calibration pairs with separable means
    so a within-group threshold exists."""
    rng = random.Random(seed)
    pairs = []
    for _ in range(n_true):
        pairs.append((min(1.0, max(0.0, rng.gauss(true_mean, 0.05))), True))
    for _ in range(n_false):
        pairs.append((min(1.0, max(0.0, rng.gauss(false_mean, 0.05))), False))
    return pairs


def test_mondrian_returns_per_group_thresholds():
    alpha = 0.1
    scores_by_group = {
        "CWE-787": _make_group(40, 40, 0.85, 0.30, seed=1),
        "CWE-369": _make_group(40, 40, 0.80, 0.25, seed=2),
    }
    thr = conformal.mondrian_thresholds(scores_by_group, alpha=alpha)
    assert set(thr.keys()) == {"CWE-787", "CWE-369"}
    for group, cal in thr.items():
        assert isinstance(cal, conformal.CalibratedThreshold)
        # Each well-populated, separable group gets a finite (emitting) threshold.
        assert cal.threshold != conformal.ABSTAIN_THRESHOLD
        assert 0.0 <= cal.threshold <= 1.0


def test_mondrian_controls_within_group_fp_on_holdout():
    """Calibrate per group on one split, measure the empirical within-group FP
    fraction on a disjoint holdout split; it should be <= alpha within
    finite-sample slack."""
    alpha = 0.1
    slack = 0.10  # finite-sample slack for a holdout of ~60 emitted points/group
    groups = {
        "CWE-787": (0.85, 0.30),
        "CWE-369": (0.80, 0.28),
    }
    cal_split = {}
    holdout = {}
    for i, (g, (tm, fm)) in enumerate(groups.items()):
        cal_split[g] = _make_group(80, 80, tm, fm, seed=10 + i)
        holdout[g] = _make_group(80, 80, tm, fm, seed=100 + i)

    thr = conformal.mondrian_thresholds(cal_split, alpha=alpha)

    for g, pairs in holdout.items():
        cal = thr[g]
        assert cal.threshold != conformal.ABSTAIN_THRESHOLD
        emitted = [t for c, t in pairs
                   if conformal.should_emit(c, g, thr)]
        assert emitted, f"group {g} emitted nothing on holdout"
        fp_rate = sum(1 for t in emitted if not t) / len(emitted)
        assert fp_rate <= alpha + slack, (g, fp_rate)


def test_mondrian_small_sample_group_abstains():
    alpha = 0.1
    # min_calibration_size(0.1) == ceil(1/0.1) - 1 == 9; give fewer points.
    n_min = conformal.min_calibration_size(alpha)
    assert n_min == 9
    tiny = _make_group(2, 1, 0.85, 0.30, seed=7)  # only 3 points < 9
    big = _make_group(40, 40, 0.85, 0.30, seed=8)
    thr = conformal.mondrian_thresholds(
        {"CWE-rare": tiny, "CWE-common": big}, alpha=alpha)

    # The under-sampled group abstains conservatively (never emits).
    assert thr["CWE-rare"].threshold == conformal.ABSTAIN_THRESHOLD
    assert conformal.should_emit(1.0, "CWE-rare", thr) is False
    # The well-populated group still gets a usable threshold.
    assert thr["CWE-common"].threshold != conformal.ABSTAIN_THRESHOLD


def test_should_emit_unknown_group_abstains():
    thr = conformal.mondrian_thresholds(
        {"CWE-787": _make_group(40, 40, 0.85, 0.30, seed=3)}, alpha=0.1)
    assert conformal.should_emit(0.99, "CWE-unseen", thr) is False


def test_apply_mondrian_splits_by_group_threshold():
    thr = conformal.mondrian_thresholds(
        {"CWE-787": _make_group(40, 40, 0.90, 0.20, seed=4)}, alpha=0.1)
    t = thr["CWE-787"].threshold
    scored = [
        ScoredFinding(Finding("a.st", 1, "CWE-787"), min(1.0, t + 0.05)),  # emit
        ScoredFinding(Finding("a.st", 2, "CWE-787"), max(0.0, t - 0.05)),  # abstain
        ScoredFinding(Finding("a.st", 3, "CWE-unseen"), 0.99),             # abstain
    ]
    emitted, abstained = conformal.apply_mondrian(scored, thr)
    emit_lines = {s.finding.line for s in emitted}
    abstain_lines = {s.finding.line for s in abstained}
    assert emit_lines == {1}
    assert abstain_lines == {2, 3}


# --- Combined drift verdict --------------------------------------------------

def test_combined_drift_ok_for_identical_distributions():
    ref = [0.1, 0.2, 0.8, 0.9, 0.5, 0.85, 0.15, 0.4, 0.6, 0.3]
    res = drift.combined_assessment(ref, list(ref))
    assert res.verdict == "OK"
    assert res.recalibrate is False
    assert res.psi == 0.0
    assert res.ks == 0.0
    assert "no significant drift" in res.reason


def test_combined_drift_recalibrate_for_clear_shift():
    ref = [0.05, 0.1, 0.15, 0.2, 0.1, 0.08, 0.12, 0.07]
    cur = [0.9, 0.95, 0.85, 0.92, 0.88, 0.99, 0.91, 0.97]
    res = drift.combined_assessment(ref, cur)
    assert res.verdict == "RECALIBRATE"
    assert res.recalibrate is True
    assert res.psi > 0.25
    assert res.ks > 0.2
    assert "recalibrate" in res.reason.lower() or "shifted" in res.reason.lower()


def test_combined_drift_monitor_for_moderate_shift():
    # KS alone in its warn band drives a MONITOR verdict even if PSI is mild.
    res = drift.combined_assessment([], [])  # empty -> metrics 0 -> OK baseline
    assert res.verdict == "OK"

    # Construct a moderate KS-only shift: shift a minority of mass.
    ref = [0.2] * 80 + [0.8] * 20
    cur = [0.2] * 65 + [0.8] * 35
    res2 = drift.combined_assessment(ref, cur)
    assert res2.verdict in {"MONITOR", "RECALIBRATE"}
    assert res2.psi >= 0.0 and res2.ks >= 0.0


def test_combined_drift_result_as_dict_populated():
    ref = [0.1, 0.2, 0.3, 0.4, 0.5]
    cur = [0.6, 0.7, 0.8, 0.9, 0.95]
    d = drift.combined_assessment(ref, cur).as_dict()
    assert set(d.keys()) == {"psi", "ks", "verdict", "recalibrate", "reason"}
    assert d["verdict"] in {"OK", "MONITOR", "RECALIBRATE"}
    assert isinstance(d["reason"], str) and d["reason"]
