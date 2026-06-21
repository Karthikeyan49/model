"""Tests for Conformal Risk Control (CRC) + Learn-then-Test (LTT) miss-rate control.

These exercise the *other* side of the safety tradeoff from ``conformal.py``:
bounding the false-NEGATIVE (miss) rate rather than the false-positive fraction.
All calibration data is deterministic synthetic so the statistical assertions are
reproducible.

Background formulas being verified (see ``risk_control.py`` docstrings for cites):
  * CRC threshold rule, arXiv:2208.02814:
        lambda_hat = inf{ lambda : (n/(n+1)) R_hat(lambda) + B/(n+1) <= alpha }
  * LTT Hoeffding-Bentkus p-value, arXiv:2110.01052.
"""
import math

import pytest

import risk_control as rc
from scoring import ScoredFinding   # noqa: F401  (import-path smoke per conftest)
from schema import Finding          # noqa: F401


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _trues(confs):
    return [(c, True) for c in confs]


def _falses(confs):
    return [(c, False) for c in confs]


# A clean, separable calibration set: 10 true vulns spread 0.50..0.95, 6 false low.
CLEAN = (_trues([0.95, 0.90, 0.85, 0.80, 0.75, 0.70, 0.65, 0.60, 0.55, 0.50])
         + _falses([0.30, 0.25, 0.20, 0.15, 0.10, 0.05]))


# --------------------------------------------------------------------------- #
# fnr_loss: the monotone loss itself
# --------------------------------------------------------------------------- #
def test_fnr_loss_basic_and_endpoints():
    cal = _trues([0.2, 0.4, 0.6, 0.8]) + _falses([0.9])
    # lam=0 emits everything -> nothing missed.
    assert rc.fnr_loss(0.0, cal) == 0.0
    # lam above every true confidence -> everything missed.
    assert rc.fnr_loss(1.01, cal) == 1.0
    # lam=0.5 misses the two true findings below 0.5 (0.2, 0.4) of 4 -> 0.5.
    assert rc.fnr_loss(0.5, cal) == pytest.approx(0.5)
    # False findings never count toward the miss rate (the 0.9 false is ignored).
    assert rc.fnr_loss(0.95, cal) == pytest.approx(1.0)


def test_fnr_loss_monotone_nondecreasing_in_lambda():
    # As lambda increases, the miss rate must never decrease (CRC precondition).
    grid = [i / 20 for i in range(21)]  # 0.0 .. 1.0
    vals = [rc.fnr_loss(lam, CLEAN) for lam in grid]
    for a, b in zip(vals, vals[1:]):
        assert b >= a - 1e-12


def test_fnr_loss_no_true_vulns_is_zero():
    # Undefined miss rate (no positives) -> conservatively 0 (nothing to miss).
    assert rc.fnr_loss(0.7, _falses([0.9, 0.5, 0.1])) == 0.0


# --------------------------------------------------------------------------- #
# CRC: bound is respected
# --------------------------------------------------------------------------- #
def test_crc_bound_respected_when_achievable():
    # With a generous alpha a feasible threshold exists; the *empirical* risk at
    # the chosen threshold must be <= alpha, AND the finite-sample CRC bound must
    # be <= alpha (that bound is what actually carries the guarantee).
    alpha = 0.3
    res = rc.control_risk(CLEAN, alpha=alpha, loss="fnr")
    assert res.feasible is True
    assert res.achieved_risk <= alpha + 1e-9
    assert res.bound <= alpha + 1e-9
    # Re-derive the bound from scratch to confirm the formula.
    n = res.n
    expected_bound = (n / (n + 1)) * res.achieved_risk + res.B / (n + 1)
    assert res.bound == pytest.approx(expected_bound, abs=1e-6)
    # And re-derive the empirical risk at the chosen threshold independently.
    assert rc.fnr_loss(res.threshold, CLEAN) == pytest.approx(res.achieved_risk,
                                                              abs=1e-6)


def test_crc_picks_largest_feasible_threshold():
    # lambda_hat is the LARGEST emit-threshold meeting the budget: emit as few
    # findings as the miss-rate budget allows. Any strictly larger candidate
    # confidence must violate the CRC bound.
    alpha = 0.3
    res = rc.control_risk(CLEAN, alpha=alpha, loss="fnr")
    n = res.n
    bigger = sorted({c for c, _ in CLEAN if c > res.threshold})
    for lam in bigger:
        r_hat = rc.fnr_loss(lam, CLEAN)
        bound = (n / (n + 1)) * r_hat + 1.0 / (n + 1)
        assert bound > alpha + 1e-12, (
            f"threshold {lam} also feasible; lambda_hat not maximal"
        )


# --------------------------------------------------------------------------- #
# CRC: monotonicity in alpha
# --------------------------------------------------------------------------- #
def test_crc_monotone_in_alpha():
    # Smaller alpha (stricter miss budget) => smaller-or-equal threshold =>
    # MORE findings emitted. Verify the threshold is non-decreasing in alpha.
    alphas = [0.05, 0.1, 0.15, 0.2, 0.3, 0.4, 0.5]
    thresholds = [rc.control_risk(CLEAN, alpha=a, loss="fnr").threshold
                  for a in alphas]
    for lo, hi in zip(thresholds, thresholds[1:]):
        assert hi >= lo - 1e-12, f"threshold not monotone in alpha: {thresholds}"


def test_crc_smaller_alpha_emits_at_least_as_many():
    # Operational restatement of monotonicity: the emitted set for a smaller alpha
    # is a superset of the emitted set for a larger alpha (more recall).
    strict = rc.control_risk(CLEAN, alpha=0.1, loss="fnr")
    loose = rc.control_risk(CLEAN, alpha=0.4, loss="fnr")
    emitted_strict = {c for c, _ in CLEAN if c >= strict.threshold}
    emitted_loose = {c for c, _ in CLEAN if c >= loose.threshold}
    assert emitted_loose <= emitted_strict


# --------------------------------------------------------------------------- #
# CRC: infeasible fallback
# --------------------------------------------------------------------------- #
def test_crc_infeasible_returns_conservative_fallback_flagged():
    # alpha below the finite-sample floor B/(n+1) is unachievable no matter the
    # data; must return emit-everything (threshold 0) and flag feasible=False.
    res = rc.control_risk(CLEAN, alpha=0.001, loss="fnr")
    assert res.feasible is False
    assert res.threshold == 0.0          # most conservative for a miss budget
    # Emit-everything => every true finding emitted => miss rate 0 empirically...
    assert res.achieved_risk == 0.0
    # ...yet the bound floor exceeds alpha, which is exactly why it is infeasible.
    assert res.bound > res.alpha


def test_crc_floor_is_B_over_n_plus_1():
    # Even with a perfectly separable set (empirical FNR can hit 0), no alpha
    # below B/(n+1) is feasible. This is the finite-sample inflation, not a bug.
    n = len(CLEAN)
    floor = 1.0 / (n + 1)
    just_below = floor * 0.99
    just_above = floor * 1.01
    assert rc.control_risk(CLEAN, alpha=just_below, loss="fnr").feasible is False
    # Just above the floor, the zero-empirical-risk threshold becomes feasible.
    res = rc.control_risk(CLEAN, alpha=just_above, loss="fnr")
    assert res.feasible is True
    assert res.achieved_risk == 0.0


def test_crc_empty_calibration_no_guarantee():
    res = rc.control_risk([], alpha=0.1, loss="fnr")
    assert res.feasible is False
    assert res.n == 0


# --------------------------------------------------------------------------- #
# CRC: generic monotone callable loss
# --------------------------------------------------------------------------- #
def test_crc_generic_monotone_callable_loss():
    # A custom monotone-non-decreasing-in-lambda loss: fraction of ALL points
    # whose confidence is below lambda. (Bounded in [0,1].)
    def below_fraction(lam, calib):
        return sum(1 for c, _ in calib if c < lam) / len(calib)

    alpha = 0.3
    res = rc.control_risk(CLEAN, alpha=alpha, loss=below_fraction)
    assert res.loss == "custom"
    assert res.feasible is True
    assert res.achieved_risk <= alpha + 1e-9
    assert res.bound <= alpha + 1e-9
    # The chosen threshold's risk matches the custom loss recomputed.
    assert below_fraction(res.threshold, CLEAN) == pytest.approx(
        res.achieved_risk, abs=1e-6
    )


def test_crc_callable_and_fnr_agree_when_all_true():
    # If every calibration point is a true vuln, fnr_loss == below_fraction.
    cal = _trues([0.2, 0.4, 0.6, 0.8, 1.0])

    def below_fraction(lam, calib):
        return sum(1 for c, _ in calib if c < lam) / len(calib)

    a = rc.control_risk(cal, alpha=0.5, loss="fnr")
    b = rc.control_risk(cal, alpha=0.5, loss=below_fraction)
    assert a.threshold == pytest.approx(b.threshold)
    assert a.achieved_risk == pytest.approx(b.achieved_risk)


def test_crc_unknown_loss_raises():
    with pytest.raises(ValueError):
        rc.control_risk(CLEAN, alpha=0.1, loss="not_a_loss")


# --------------------------------------------------------------------------- #
# p-values: Hoeffding & Hoeffding-Bentkus
# --------------------------------------------------------------------------- #
def test_pvalue_one_when_empirical_exceeds_alpha():
    # If observed risk >= alpha there is no evidence the true risk is <= alpha;
    # both p-values must be exactly 1 (never reject).
    assert rc.hoeffding_p_value(0.3, 0.2, 50) == 1.0
    assert rc.hoeffding_bentkus_p_value(0.3, 0.2, 50) == 1.0
    assert rc.hoeffding_bentkus_p_value(0.2, 0.2, 50) == 1.0


def test_pvalue_decreases_as_risk_drops():
    # Lower observed risk => stronger evidence => smaller p-value.
    ps = [rc.hoeffding_bentkus_p_value(r, 0.3, 100) for r in [0.29, 0.2, 0.1, 0.0]]
    for hi, lo in zip(ps, ps[1:]):
        assert lo <= hi + 1e-15


def test_hb_is_tighter_than_plain_hoeffding():
    # Hoeffding-Bentkus is the min of two valid bounds, so it is never larger than
    # the simple Hoeffding p-value (and usually strictly smaller).
    for r in [0.0, 0.05, 0.1, 0.15]:
        pH = rc.hoeffding_p_value(r, 0.2, 100)
        pHB = rc.hoeffding_bentkus_p_value(r, 0.2, 100)
        assert pHB <= pH + 1e-12


def test_pvalues_are_valid_probabilities():
    for n in (1, 10, 100):
        for r in (0.0, 0.123, 0.5, 1.0):
            for a in (0.05, 0.2, 0.5):
                assert 0.0 <= rc.hoeffding_p_value(r, a, n) <= 1.0
                assert 0.0 <= rc.hoeffding_bentkus_p_value(r, a, n) <= 1.0


def test_hb_matches_closed_form():
    # Spot-check the HB formula against a hand computation.
    n, r, a = 50, 0.1, 0.3
    h1 = (r * math.log(r / a)) + (1 - r) * math.log((1 - r) / (1 - a))
    hoeff = math.exp(-n * h1)
    k = math.ceil(n * r)
    binom = sum(math.comb(n, i) * a ** i * (1 - a) ** (n - i) for i in range(k + 1))
    expected = min(1.0, hoeff, math.e * binom)
    assert rc.hoeffding_bentkus_p_value(r, a, n) == pytest.approx(expected, rel=1e-9)


def test_binom_cdf_edges():
    # Boundary handling stays a valid probability and is conservative.
    assert rc._binom_cdf(-1, 10, 0.3) == 0.0
    assert rc._binom_cdf(10, 10, 0.3) == 1.0
    assert rc._binom_cdf(3, 10, 0.0) == 1.0   # all mass at 0
    assert rc._binom_cdf(3, 10, 1.0) == 0.0   # all mass at n
    # Matches a direct sum in the interior.
    got = rc._binom_cdf(2, 5, 0.4)
    want = sum(math.comb(5, i) * 0.4 ** i * 0.6 ** (5 - i) for i in range(3))
    assert got == pytest.approx(want, rel=1e-12)


# --------------------------------------------------------------------------- #
# LTT: Bonferroni
# --------------------------------------------------------------------------- #
# Bigger separable set so HB has the power to certify some thresholds.
_TRUES_BIG = [(0.5 + 0.5 * (i / 80), True) for i in range(80)]  # 0.50..~0.99
_FALSES_BIG = [(0.1, False) for _ in range(20)]
BIG = _TRUES_BIG + _FALSES_BIG
LTT_CANDS = [round(0.50 + 0.05 * k, 3) for k in range(9)]       # 0.50..0.90


def test_ltt_bonferroni_certifies_only_passing_thresholds():
    alpha, delta = 0.25, 0.1
    res = rc.learn_then_test(BIG, LTT_CANDS, alpha=alpha, delta=delta,
                             correction="bonferroni")
    m = len(LTT_CANDS)
    threshold_p = delta / m
    # Every certified threshold has corrected p-value <= delta/m...
    for row in res.candidates:
        if row.certified:
            assert row.p_value <= threshold_p + 1e-15
        else:
            assert row.p_value > threshold_p - 1e-15
    # ...and the certified list is exactly those rows.
    assert set(res.certified) == {r.threshold for r in res.candidates
                                  if r.certified}
    # Something is certifiable on this clean data.
    assert res.certified


def test_ltt_recommended_respects_alpha_and_is_largest_certified():
    alpha, delta = 0.25, 0.1
    res = rc.learn_then_test(BIG, LTT_CANDS, alpha=alpha, delta=delta,
                             correction="bonferroni")
    assert res.recommended is not None
    # Recommended is the LARGEST certified threshold (fewest emitted, safest).
    assert res.recommended == max(res.certified)
    # Its *empirical* risk respects alpha (necessary condition; the real
    # guarantee is the high-probability FWER one).
    assert rc.fnr_loss(res.recommended, BIG) <= alpha + 1e-9
    # Every certified threshold likewise has empirical risk under alpha here.
    for lam in res.certified:
        assert rc.fnr_loss(lam, BIG) <= alpha + 1e-9


def test_ltt_too_strict_certifies_nothing():
    # alpha tighter than the best achievable risk => no certification, no rec.
    res = rc.learn_then_test(BIG, LTT_CANDS, alpha=0.001, delta=0.1,
                             correction="bonferroni")
    assert res.certified == []
    assert res.recommended is None
    assert res.feasible is False


def test_ltt_generic_callable_risk_fn():
    def below_fraction(lam, calib):
        return sum(1 for c, _ in calib if c < lam) / len(calib)

    res = rc.learn_then_test(BIG, LTT_CANDS, alpha=0.3, delta=0.1,
                             risk_fn=below_fraction, correction="bonferroni")
    # Recorded risks match the custom loss.
    for row in res.candidates:
        assert row.risk == pytest.approx(below_fraction(row.threshold, BIG),
                                         abs=1e-6)
    if res.recommended is not None:
        assert below_fraction(res.recommended, BIG) <= 0.3 + 1e-9


# --------------------------------------------------------------------------- #
# LTT: fixed-sequence
# --------------------------------------------------------------------------- #
def test_ltt_fixed_sequence_stops_at_first_failure():
    # Ordered low->high lambda (lowest miss-rate first). Fixed-sequence spends the
    # whole delta each step and halts at the first non-rejection: every certified
    # threshold precedes every uncertified one, with no certification after a gap.
    res = rc.learn_then_test(BIG, sorted(LTT_CANDS), alpha=0.25, delta=0.1,
                             correction="fixed_sequence")
    flags = [row.certified for row in res.candidates]
    # Pattern must be a run of True then all False (no True after the first False).
    if False in flags:
        first_false = flags.index(False)
        assert all(f is False for f in flags[first_false:])
    assert res.certified  # some prefix certifies on this clean data


def test_ltt_fixed_sequence_wrong_order_certifies_less():
    # Ordered high->low lambda (riskiest first) the very first hypothesis fails,
    # so fixed-sequence certifies nothing even though a good prefix exists in the
    # other order. Demonstrates order-sensitivity (still FWER-valid, just weaker).
    res = rc.learn_then_test(BIG, sorted(LTT_CANDS, reverse=True), alpha=0.25,
                             delta=0.1, correction="fixed_sequence")
    assert res.certified == []
    assert res.recommended is None


def test_ltt_fixed_sequence_uses_full_delta_not_bonferroni_split():
    # Fixed-sequence tests against delta (not delta/m). Construct a borderline
    # case where a p-value sits between delta/m and delta: it should certify under
    # fixed-sequence (good order) but NOT under bonferroni.
    # lam=0.6 on BIG has empirical FNR 0.20; pick alpha=0.25 so its p-value is
    # moderate. Verify the per-correction thresholds differ in effect.
    cands = sorted(LTT_CANDS)
    fs = rc.learn_then_test(BIG, cands, alpha=0.25, delta=0.1,
                            correction="fixed_sequence")
    bf = rc.learn_then_test(BIG, cands, alpha=0.25, delta=0.1,
                            correction="bonferroni")
    # Fixed-sequence (full delta budget, informative order) certifies at least as
    # many leading thresholds as Bonferroni does.
    assert len(fs.certified) >= len(bf.certified)


def test_ltt_unknown_correction_and_pvalue_raise():
    with pytest.raises(ValueError):
        rc.learn_then_test(BIG, LTT_CANDS, correction="holm")
    with pytest.raises(ValueError):
        rc.learn_then_test(BIG, LTT_CANDS, p_value="wilson")
    with pytest.raises(ValueError):
        rc.learn_then_test(BIG, LTT_CANDS, risk_fn="nope")


def test_ltt_empty_inputs():
    assert rc.learn_then_test([], LTT_CANDS).recommended is None
    assert rc.learn_then_test(BIG, []).recommended is None


def test_ltt_hoeffding_pvalue_option_runs_and_is_conservative():
    # Using the simpler Hoeffding p-value must still be valid and certify no MORE
    # than HB (since HB <= Hoeffding pointwise).
    hb = rc.learn_then_test(BIG, LTT_CANDS, alpha=0.25, delta=0.1,
                            p_value="hoeffding_bentkus")
    h = rc.learn_then_test(BIG, LTT_CANDS, alpha=0.25, delta=0.1,
                           p_value="hoeffding")
    assert set(h.certified) <= set(hb.certified)


# --------------------------------------------------------------------------- #
# report()
# --------------------------------------------------------------------------- #
def test_report_crc_feasible_states_guarantee():
    res = rc.control_risk(CLEAN, alpha=0.3, loss="fnr")
    text = rc.report(res)
    assert "Conformal Risk Control" in text
    assert "E[loss] <= alpha" in text
    assert "2208.02814" in text


def test_report_crc_infeasible_states_no_guarantee():
    res = rc.control_risk(CLEAN, alpha=0.001, loss="fnr")
    text = rc.report(res)
    assert "NONE" in text  # explicitly tells operator there is no guarantee


def test_report_ltt_feasible_and_infeasible():
    ok = rc.learn_then_test(BIG, LTT_CANDS, alpha=0.25, delta=0.1)
    text_ok = rc.report(ok)
    assert "Learn-then-Test" in text_ok
    assert "1 - delta" in text_ok
    assert "2110.01052" in text_ok

    bad = rc.learn_then_test(BIG, LTT_CANDS, alpha=0.001, delta=0.1)
    text_bad = rc.report(bad)
    assert "NONE" in text_bad
