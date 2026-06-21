"""Tests for Venn-ABERS calibration (advanced/venn_abers.py).

Covers the IVAP behaviour and its guarantees:
  * PAV isotonic fit is monotone non-decreasing;
  * the Venn-ABERS ordering 0 <= p0 <= p <= p1 <= 1 always holds;
  * separable scores -> high score high p, low score low p;
  * interval width is always in [0,1] and narrows with more calibration data;
  * calibration reduces Brier score / ECE vs raw miscalibrated scores
    (measured with the existing calibration_metrics module);
  * empty and single-class calibration sets degrade to a sensible neutral/wide
    output without crashing.

All data is deterministic (seeded random.Random) so the suite is reproducible.
"""
import random
import statistics

import pytest

import calibration_metrics as cm
from schema import Finding
from scoring import ScoredFinding
from venn_abers import (
    IsotonicRegressor,
    VennAbersCalibrator,
    VennAbersResult,
    calibrate_scored,
)


# --- deterministic synthetic data helpers ------------------------------------

def _separable(n_per_class=100, seed=0):
    """Cleanly separable calibration set: positives score high, negatives low."""
    rng = random.Random(seed)
    scores, labels = [], []
    for _ in range(n_per_class):
        scores.append(0.6 + rng.random() * 0.4)   # positive class, high score
        labels.append(1)
        scores.append(rng.random() * 0.4)         # negative class, low score
        labels.append(0)
    return scores, labels


def _well_ordered(n, seed):
    """Scores in [0,1] whose TRUE positive probability equals the score itself
    (well-ordered scorer). Used to study width and to build miscalibration."""
    rng = random.Random(seed)
    scores, labels = [], []
    for _ in range(n):
        s = rng.random()
        labels.append(1 if rng.random() < s else 0)   # P(y=1|s) == s
        scores.append(s)
    return scores, labels


# --- isotonic / PAV ----------------------------------------------------------

def test_pav_is_monotone_non_decreasing():
    # An input that violates monotonicity (0,1,0,1,1) must be pooled into a
    # non-decreasing step function.
    reg = IsotonicRegressor().fit([1, 2, 3, 4, 5], [0, 1, 0, 1, 1])
    vals = [reg.predict(x) for x in [1, 2, 3, 4, 5]]
    assert all(vals[i] <= vals[i + 1] + 1e-12 for i in range(len(vals) - 1))
    # Middle violators (1 then 0) get pooled to their mean 0.5.
    assert vals[1] == vals[2] == 0.5


def test_pav_perfectly_monotone_input_is_identity_on_levels():
    # Already-monotone targets are left unchanged (no pooling needed).
    reg = IsotonicRegressor().fit([0.1, 0.2, 0.3], [0.0, 0.5, 1.0])
    assert reg.predict(0.1) == 0.0
    assert reg.predict(0.2) == 0.5
    assert reg.predict(0.3) == 1.0


def test_pav_handles_tied_x_by_averaging():
    # Tied x with mixed labels -> single block at the mean label.
    reg = IsotonicRegressor().fit([0.5, 0.5, 0.5, 0.5], [1, 0, 1, 0])
    assert reg.predict(0.5) == 0.5


def test_isotonic_clamps_outside_support():
    reg = IsotonicRegressor().fit([0.2, 0.4, 0.8], [0.0, 0.5, 1.0])
    assert reg.predict(-5.0) == 0.0     # below first block -> first level
    assert reg.predict(99.0) == 1.0     # above last block -> last level


def test_isotonic_random_data_always_monotone():
    rng = random.Random(123)
    for _ in range(20):
        n = rng.randint(2, 40)
        xs = sorted(rng.random() for _ in range(n))
        ys = [1.0 if rng.random() < 0.5 else 0.0 for _ in range(n)]
        reg = IsotonicRegressor().fit(xs, ys)
        qs = [rng.random() for _ in range(15)]
        vals = [reg.predict(q) for q in sorted(qs)]
        assert all(vals[i] <= vals[i + 1] + 1e-12 for i in range(len(vals) - 1))


def test_isotonic_unfitted_predict_raises():
    with pytest.raises(ValueError):
        IsotonicRegressor().predict(0.5)


def test_isotonic_length_mismatch_raises():
    with pytest.raises(ValueError):
        IsotonicRegressor().fit([1, 2, 3], [0, 1])


# --- Venn-ABERS ordering invariant -------------------------------------------

def test_ordering_invariant_holds_everywhere():
    # 0 <= p0 <= p <= p1 <= 1 for any calibration set and any query, including
    # scores outside the calibration range.
    rng = random.Random(7)
    for _ in range(40):
        cal = VennAbersCalibrator().fit(*_well_ordered(rng.randint(1, 50),
                                                       rng.randint(0, 9999)))
        for _ in range(15):
            r = cal.predict(rng.uniform(-0.5, 1.5))
            assert 0.0 <= r.p0 <= r.p <= r.p1 <= 1.0


def test_width_property_matches_endpoints():
    r = VennAbersResult(p0=0.2, p1=0.7, p=0.5)
    assert r.width == pytest.approx(0.5)


def test_point_estimate_formula():
    # p = p1 / (1 - p0 + p1). With p0=0.2, p1=0.6 -> 0.6/1.4.
    cal = VennAbersCalibrator().fit(*_separable())
    r = cal.predict(0.5)
    expected = r.p1 / (1.0 - r.p0 + r.p1)
    assert r.p == pytest.approx(expected)
    # Degenerate p0==p1 collapses to that value.
    deg = VennAbersResult(0.3, 0.3, 0.3)
    assert deg.p == 0.3


# --- separability ------------------------------------------------------------

def test_separable_high_score_high_p_low_score_low_p():
    cal = VennAbersCalibrator().fit(*_separable(n_per_class=150, seed=1))
    hi = cal.predict(0.95)
    lo = cal.predict(0.05)
    assert hi.p > 0.8          # confident positive
    assert lo.p < 0.2          # confident negative
    assert hi.p > lo.p
    # both intervals stay inside [0,1] and ordered
    assert 0.0 <= lo.p0 <= lo.p1 <= 1.0
    assert 0.0 <= hi.p0 <= hi.p1 <= 1.0


def test_monotone_p_increases_with_score():
    cal = VennAbersCalibrator().fit(*_separable(n_per_class=150, seed=2))
    ps = [cal.predict(s).p for s in [0.0, 0.25, 0.5, 0.75, 1.0]]
    assert all(ps[i] <= ps[i + 1] + 1e-9 for i in range(len(ps) - 1))


# --- interval width ----------------------------------------------------------

def test_width_always_in_unit_interval():
    cal = VennAbersCalibrator().fit(*_well_ordered(300, seed=3))
    for s in [-1.0, 0.0, 0.2, 0.5, 0.8, 1.0, 2.0]:
        w = cal.predict(s).width
        assert 0.0 <= w <= 1.0


def test_width_narrows_with_more_calibration_data():
    # Averaged over several mid-range queries (width is locally noisy at a single
    # point but shrinks robustly in aggregate as data accumulates).
    queries = [0.4, 0.45, 0.5, 0.55, 0.6]
    small = VennAbersCalibrator().fit(*_well_ordered(30, seed=4))
    large = VennAbersCalibrator().fit(*_well_ordered(1500, seed=4))
    w_small = statistics.mean(small.predict(q).width for q in queries)
    w_large = statistics.mean(large.predict(q).width for q in queries)
    assert w_large < w_small


# --- calibration actually improves (Brier / ECE) -----------------------------

def _miscalibrated(n, seed):
    """Return (raw_confidences, labels) where the REPORTED confidence is
    miscalibrated (squashed = s**2) but the true positive probability is s.
    Ordering is preserved, so isotonic-based Venn-ABERS can fix the scale."""
    rng = random.Random(seed)
    raws, labels = [], []
    for _ in range(n):
        s = rng.random()
        labels.append(1 if rng.random() < s else 0)
        raws.append(s * s)            # miscalibrated reported confidence
    return raws, labels


def test_venn_abers_improves_brier_and_ece():
    train_raw, train_y = _miscalibrated(1500, seed=1)
    test_raw, test_y = _miscalibrated(1500, seed=2)
    cal = VennAbersCalibrator().fit(train_raw, train_y)

    raw_pairs = [(r, bool(y)) for r, y in zip(test_raw, test_y)]
    va_pairs = [(cal.predict(r).p, bool(y)) for r, y in zip(test_raw, test_y)]

    raw = cm.evaluate(raw_pairs)
    va = cm.evaluate(va_pairs)

    # Venn-ABERS should reduce both squared error and calibration gap.
    assert va.brier < raw.brier
    assert va.ece < raw.ece
    # And the calibrated ECE should be small in absolute terms.
    assert va.ece < 0.06


# --- edge cases --------------------------------------------------------------

def test_empty_calibration_is_neutral():
    cal = VennAbersCalibrator()
    r = cal.predict(0.7)
    assert (r.p0, r.p1, r.p) == (0.0, 1.0, 0.5)
    assert r.width == 1.0
    assert cal.n_calibration == 0


def test_single_positive_class_does_not_crash():
    cal = VennAbersCalibrator().fit([0.2, 0.5, 0.8], [1, 1, 1])
    r = cal.predict(0.5)
    assert 0.0 <= r.p0 <= r.p <= r.p1 <= 1.0
    # Only positives seen -> lower bound is pulled up, not 0; interval still wide.
    assert r.p1 == 1.0


def test_single_negative_class_does_not_crash():
    cal = VennAbersCalibrator().fit([0.1, 0.5, 0.9], [0, 0, 0])
    r = cal.predict(0.5)
    assert 0.0 <= r.p0 <= r.p <= r.p1 <= 1.0
    # Only negatives seen -> upper bound is pulled down, not 1; lower bound 0.
    assert r.p0 == 0.0


def test_single_sample_calibration_does_not_crash():
    r = VennAbersCalibrator().fit([0.5], [1]).predict(0.5)
    assert 0.0 <= r.p0 <= r.p <= r.p1 <= 1.0


def test_extreme_scores_do_not_crash():
    cal = VennAbersCalibrator().fit([0.2, 0.4, 0.6, 0.8], [0, 0, 1, 1])
    for s in [-1e9, 1e9]:
        r = cal.predict(s)
        assert 0.0 <= r.p0 <= r.p <= r.p1 <= 1.0


def test_fit_length_mismatch_raises():
    with pytest.raises(ValueError):
        VennAbersCalibrator().fit([0.1, 0.2], [1])


def test_labels_accept_bools_and_floats():
    # bool / int / float labels all map to {0,1} the same way.
    a = VennAbersCalibrator().fit([0.1, 0.9], [False, True]).predict(0.9)
    b = VennAbersCalibrator().fit([0.1, 0.9], [0, 1]).predict(0.9)
    c = VennAbersCalibrator().fit([0.1, 0.9], [0.0, 1.0]).predict(0.9)
    assert a == b == c


# --- predict_batch and pipeline bridge ---------------------------------------

def test_predict_batch_matches_predict():
    cal = VennAbersCalibrator().fit(*_separable(seed=5))
    scores = [0.1, 0.5, 0.9]
    batch = cal.predict_batch(scores)
    one_by_one = [cal.predict(s) for s in scores]
    assert batch == one_by_one


def test_calibrate_scored_preserves_findings_and_order():
    cal = VennAbersCalibrator().fit(*_separable(seed=6))
    scored = [
        ScoredFinding(Finding("p.st", 1, "CWE-787"), 0.95),
        ScoredFinding(Finding("p.st", 2, "CWE-369"), 0.05),
    ]
    out = calibrate_scored(scored, cal)
    assert len(out) == 2
    # Findings passed through unchanged (non-destructive), order preserved.
    assert out[0][0] is scored[0]
    assert out[1][0] is scored[1]
    # High-confidence finding gets a higher calibrated point than the low one.
    assert out[0][1].p > out[1][1].p
    for _, res in out:
        assert isinstance(res, VennAbersResult)
        assert 0.0 <= res.p0 <= res.p <= res.p1 <= 1.0


def test_calibrate_scored_empty_input():
    cal = VennAbersCalibrator().fit(*_separable(seed=7))
    assert calibrate_scored([], cal) == []
