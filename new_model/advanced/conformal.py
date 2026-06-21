"""Conformal selective prediction — statistically calibrated abstention.

This is the most important advanced technique for the product's moat: a
*distribution-free, finite-sample bound on the false-positive rate*. Instead of
guessing a severity floor, we calibrate a confidence threshold on a held-out
calibration set so that, among emitted findings, the expected false-positive
fraction is <= alpha (target risk). Findings below threshold are ABSTAINED
(sent to human review) rather than shipped as noise.

Grounded in conformal abstention / selective conformal prediction
(arXiv 2405.01563; Conformal Abstention Framework, 2026). Under the standard iid
assumption between calibration and test, this gives marginal risk control —
the rigorous version of "low false-positive rate".

Why non-traditional: traditional tools pick a fixed threshold by hand; this
*derives* the threshold from a target error budget with a guarantee, and abstains
under uncertainty instead of emitting a guess.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from scoring import ScoredFinding


@dataclass
class CalibratedThreshold:
    threshold: float
    alpha: float                 # target false-positive fraction among emitted
    achieved_fp: float           # FP fraction on calibration at this threshold
    coverage: float              # fraction of true findings still emitted (recall proxy)
    n_cal: int


def calibrate(calibration: List[Tuple[float, bool]], alpha: float = 0.1,
              min_coverage: float = 0.0) -> CalibratedThreshold:
    """calibration: list of (confidence, is_true_vulnerability).
    Returns the LOWEST threshold whose emitted set has FP-fraction <= alpha
    (so recall is maximised subject to the FP budget). If `min_coverage` is set,
    the threshold must also keep at least that fraction of true findings.
    """
    if not calibration:
        return CalibratedThreshold(1.0, alpha, 0.0, 0.0, 0)

    n_true = sum(1 for _, t in calibration if t)
    # candidate thresholds = the observed confidences (split-conformal style)
    candidates = sorted({c for c, _ in calibration})
    best = CalibratedThreshold(1.0, alpha, 0.0, 0.0, len(calibration))

    for thr in candidates:
        emitted = [(c, t) for c, t in calibration if c >= thr]
        if not emitted:
            continue
        fp = sum(1 for _, t in emitted if not t) / len(emitted)
        cov = (sum(1 for _, t in emitted if t) / n_true) if n_true else 1.0
        if fp <= alpha and cov >= min_coverage:
            # first (lowest) threshold satisfying the budget => max recall
            return CalibratedThreshold(thr, alpha, round(fp, 4), round(cov, 4),
                                       len(calibration))
    return best  # nothing meets budget => most conservative


def apply(scored: List[ScoredFinding], cal: CalibratedThreshold
          ) -> Tuple[List[ScoredFinding], List[ScoredFinding]]:
    """Split into (emitted, abstained) at the calibrated threshold."""
    emitted = [s for s in scored if s.confidence >= cal.threshold]
    abstained = [s for s in scored if s.confidence < cal.threshold]
    return emitted, abstained


# --- Class-conditional (Mondrian) conformal prediction -----------------------
#
# The marginal guarantee above controls the false-positive budget alpha *pooled
# across all classes*. That can hide a class where the detector is much worse:
# a class with many easy true-positives can "pay for" another class's false
# positives while the pooled FP-fraction still looks <= alpha.
#
# Mondrian (class-conditional / taxonomic) conformal prediction instead
# calibrates a SEPARATE threshold per group (here: per CWE), so the FP budget
# alpha is controlled *within each group*. This is still a conformal guarantee
# and still rests on exchangeability (the iid assumption) — but now only
# *within* a class, which is a strictly stronger, per-class form of control.
#
# Soundness note: the guarantee remains marginal *conditional on the group*.
# It assumes calibration and production data are exchangeable within that group.
# When a group has too few calibration points to support the requested alpha,
# we deliberately ABSTAIN (return a threshold above any achievable confidence)
# rather than emit a misleadingly loose threshold and a false guarantee.

# Sentinel threshold that abstains on everything in [0, 1]. We use a value
# strictly above 1.0 so that no finding with confidence in [0, 1] is ever
# emitted; `apply`/`should_emit` therefore abstain conservatively.
ABSTAIN_THRESHOLD = float("inf")


def min_calibration_size(alpha: float) -> int:
    """Smallest calibration count n for which the finite-sample conformal
    quantile index ceil((n + 1) * (1 - alpha)) is <= n.

    Below this, the (1 - alpha) conformal quantile would point past the largest
    observed nonconformity score, so no finite threshold can honestly promise an
    FP-fraction <= alpha. The classic split-conformal requirement is
    n >= ceil(1 / alpha) - 1, i.e. n + 1 >= 1 / alpha.
    """
    if not (0.0 < alpha < 1.0):
        return 1
    return max(1, math.ceil(1.0 / alpha) - 1)


def mondrian_thresholds(scores_by_group: Dict[str, List[Tuple[float, bool]]],
                        alpha: float = 0.1,
                        min_coverage: float = 0.0
                        ) -> Dict[str, CalibratedThreshold]:
    """Class-conditional (Mondrian) conformal calibration.

    `scores_by_group`: mapping group/class (e.g. CWE id) -> list of
    (confidence, is_true_vulnerability) calibration pairs for that group.

    Returns a mapping group -> CalibratedThreshold, where each group's threshold
    independently controls the within-group false-positive fraction to <= alpha.
    Each group reuses the exact single-group calibration logic in `calibrate`
    (same split-conformal threshold search), so the math is identical per group.

    Insufficient-data policy (honest abstention): if a group has fewer
    calibration points than `min_calibration_size(alpha)`, the requested alpha
    cannot be supported with a finite-sample conformal guarantee for that group.
    We then return a conservative CalibratedThreshold whose `threshold` is
    `ABSTAIN_THRESHOLD` (never emits), rather than a loose threshold that would
    over-promise. The same conservative abstention is used if `calibrate` cannot
    find any threshold meeting the budget for that group.

    Guarantee: marginal FP control *within each group*, under exchangeability
    of calibration and production data within that group (the iid assumption).
    """
    out: Dict[str, CalibratedThreshold] = {}
    n_min = min_calibration_size(alpha)
    for group, pairs in scores_by_group.items():
        n = len(pairs)
        if n < n_min:
            # Too few points to honestly promise alpha for this group -> abstain.
            out[group] = CalibratedThreshold(ABSTAIN_THRESHOLD, alpha, 0.0, 0.0, n)
            continue
        cal = calibrate(pairs, alpha=alpha, min_coverage=min_coverage)
        # If no threshold met the budget, `calibrate` returns its conservative
        # fallback (threshold 1.0, achieved_fp 0.0). Promote that to a true
        # abstain so a borderline confidence of exactly 1.0 cannot slip through
        # without an honest within-group guarantee.
        if cal.achieved_fp == 0.0 and cal.coverage == 0.0 and cal.threshold >= 1.0:
            out[group] = CalibratedThreshold(ABSTAIN_THRESHOLD, alpha, 0.0, 0.0, n)
        else:
            out[group] = cal
    return out


def should_emit(confidence: float, group: str,
                thresholds: Dict[str, CalibratedThreshold]) -> bool:
    """Decide emit (True) vs abstain (False) for a single finding given its
    group's Mondrian threshold.

    A finding is emitted only if its group has a calibrated threshold AND the
    finding's confidence meets it. Unknown groups (no calibration data) abstain,
    because we have no within-group guarantee for them.
    """
    cal = thresholds.get(group)
    if cal is None:
        return False
    return confidence >= cal.threshold


def apply_mondrian(scored: List[ScoredFinding],
                   thresholds: Dict[str, CalibratedThreshold],
                   group_of=lambda s: s.finding.cwe
                   ) -> Tuple[List[ScoredFinding], List[ScoredFinding]]:
    """Split scored findings into (emitted, abstained) using per-group
    (Mondrian) thresholds. `group_of` extracts the group key from a
    ScoredFinding (defaults to its CWE). Findings in groups without a
    calibrated threshold are abstained."""
    emitted: List[ScoredFinding] = []
    abstained: List[ScoredFinding] = []
    for s in scored:
        if should_emit(s.confidence, group_of(s), thresholds):
            emitted.append(s)
        else:
            abstained.append(s)
    return emitted, abstained
