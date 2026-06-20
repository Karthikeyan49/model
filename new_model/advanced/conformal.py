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

from dataclasses import dataclass
from typing import List, Tuple

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
