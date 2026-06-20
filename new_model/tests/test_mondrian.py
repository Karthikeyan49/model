"""Tests for class-conditional (Mondrian) conformal calibration."""
import mondrian_conformal as mc
import conformal
from scoring import ScoredFinding
from schema import Finding


def _pairs(confs, label):
    """Build [(conf, is_true)] all sharing one label."""
    return [(c, label) for c in confs]


def test_two_groups_get_different_thresholds():
    # Group A: true findings cluster high, false low -> low threshold suffices.
    group_a = (_pairs([0.90, 0.88, 0.86, 0.84, 0.82, 0.80], True)
               + _pairs([0.30, 0.25, 0.20, 0.15], False))
    # Group B: noisier — false findings push high, forcing a higher threshold.
    group_b = (_pairs([0.95, 0.93, 0.91, 0.89, 0.60, 0.58], True)
               + _pairs([0.70, 0.68, 0.66, 0.64], False))

    mt = mc.calibrate_mondrian(
        {"CWE-A": group_a, "CWE-B": group_b}, alpha=0.1, min_group=5
    )
    thr_a = mt.per_group["CWE-A"].threshold
    thr_b = mt.per_group["CWE-B"].threshold
    assert thr_a != thr_b
    # B's intruding false positives require a stricter threshold than A.
    assert thr_b > thr_a


def test_tiny_group_uses_fallback():
    big = (_pairs([0.9, 0.88, 0.86, 0.84, 0.82, 0.80, 0.78, 0.76, 0.74, 0.72,
                   0.70], True)
           + _pairs([0.2, 0.18, 0.16], False))
    tiny = _pairs([0.99, 0.5], True)  # only 2 samples (< min_group)

    mt = mc.calibrate_mondrian(
        {"CWE-BIG": big, "CWE-TINY": tiny}, alpha=0.1, min_group=10
    )

    assert mt.used_fallback("CWE-TINY") is True
    assert "CWE-TINY" in mt.fallback_groups
    # Tiny group reuses the pooled fallback threshold exactly.
    assert mt.per_group["CWE-TINY"].threshold == mt.fallback.threshold
    # Big group is class-conditional, not fallback.
    assert mt.used_fallback("CWE-BIG") is False


def test_apply_routes_by_cwe_threshold():
    # Force a known-ish split: build groups so thresholds differ, then route.
    group_a = (_pairs([0.85, 0.83, 0.81, 0.80, 0.79], True)
               + _pairs([0.10, 0.12, 0.14], False))
    group_b = (_pairs([0.95, 0.93, 0.92, 0.91, 0.90], True)
               + _pairs([0.80, 0.81, 0.82], False))
    mt = mc.calibrate_mondrian(
        {"CWE-A": group_a, "CWE-B": group_b}, alpha=0.1, min_group=5
    )
    thr_a = mt.per_group["CWE-A"].threshold
    thr_b = mt.per_group["CWE-B"].threshold

    scored = [
        ScoredFinding(Finding("p", 1, "CWE-A"), thr_a),          # >= -> emit
        ScoredFinding(Finding("p", 2, "CWE-A"), thr_a - 0.01),   # < -> abstain
        ScoredFinding(Finding("p", 3, "CWE-B"), thr_b),          # >= -> emit
        ScoredFinding(Finding("p", 4, "CWE-B"), thr_b - 0.01),   # < -> abstain
    ]
    emitted, abstained = mc.apply_mondrian(scored, mt)
    emitted_lines = {s.finding.line for s in emitted}
    abstained_lines = {s.finding.line for s in abstained}
    assert emitted_lines == {1, 3}
    assert abstained_lines == {2, 4}


def test_unseen_cwe_uses_fallback_no_crash():
    group = (_pairs([0.9, 0.88, 0.86, 0.84, 0.82], True)
             + _pairs([0.2, 0.18, 0.16], False))
    mt = mc.calibrate_mondrian({"CWE-KNOWN": group}, alpha=0.1, min_group=5)

    # finding.cwe never seen at calibration time -> must resolve to fallback.
    assert mt.used_fallback("CWE-NEVER-SEEN") is True
    cal = mt.threshold_for("CWE-NEVER-SEEN")
    assert cal is mt.fallback

    fb_thr = mt.fallback.threshold
    scored = [
        ScoredFinding(Finding("p", 1, "CWE-NEVER-SEEN"), fb_thr),       # emit
        ScoredFinding(Finding("p", 2, "CWE-NEVER-SEEN"), fb_thr - 0.05),  # abstain
    ]
    emitted, abstained = mc.apply_mondrian(scored, mt)  # must not raise
    assert {s.finding.line for s in emitted} == {1}
    assert {s.finding.line for s in abstained} == {2}


def test_each_group_respects_alpha_budget():
    alpha = 0.1
    # A satisfying threshold exists for each group (clean separation).
    group_a = (_pairs([0.90, 0.88, 0.86, 0.84, 0.82, 0.80], True)
               + _pairs([0.30, 0.25, 0.20], False))
    group_b = (_pairs([0.95, 0.93, 0.91, 0.89, 0.87], True)
               + _pairs([0.40, 0.35, 0.30], False))
    by_group = {"CWE-A": group_a, "CWE-B": group_b}
    mt = mc.calibrate_mondrian(by_group, alpha=alpha, min_group=5)

    for group, pairs in by_group.items():
        cal = mt.per_group[group]
        # Re-derive achieved FP on this group's own calibration data.
        emitted = [(c, t) for c, t in pairs if c >= cal.threshold]
        assert emitted, f"group {group} emitted nothing"
        fp = sum(1 for _, t in emitted if not t) / len(emitted)
        assert fp <= alpha + 1e-9
        # Consistent with the stored achieved_fp from conformal.calibrate.
        assert cal.achieved_fp <= alpha + 1e-9


def test_group_calibration_helper_and_report():
    triples = [
        ("CWE-A", 0.9, True), ("CWE-A", 0.2, False),
        ("CWE-B", 0.8, True), ("CWE-B", 0.1, False),
    ]
    by_group = mc.group_calibration(triples)
    assert set(by_group) == {"CWE-A", "CWE-B"}
    assert by_group["CWE-A"] == [(0.9, True), (0.2, False)]

    mt = mc.calibrate_mondrian(by_group, alpha=0.1, min_group=1)
    rows = mc.report(mt)
    assert {r.group for r in rows} == {"CWE-A", "CWE-B"}
    for r in rows:
        assert isinstance(r.used_fallback, bool)
        assert r.n_cal == 2
    # format_report includes the pooled fallback row and does not crash.
    text = mc.format_report(mt)
    assert "pooled/fallback" in text
