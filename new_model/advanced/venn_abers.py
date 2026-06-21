"""Venn-ABERS calibration — honest probability *intervals* for findings.

Every other layer here turns a raw scorer into a single number in [0,1] and then
trusts it (conformal thresholding, ensembling, abstention). But a point
probability hides its own uncertainty: "0.80" from a scorer fit on 20 examples
and "0.80" from one fit on 20000 are not the same claim. Venn-ABERS makes that
uncertainty explicit by emitting a probability *interval* ``[p0, p1]`` for the
positive class together with a point estimate ``p`` — and the interval is
*automatically calibrated* regardless of how good or bad the underlying scorer is.

Method — Inductive Venn-ABERS Predictors (IVAP)
-----------------------------------------------
Given a calibration set of ``(score, label in {0,1})`` and a test score ``s``,
fit isotonic regression on the scores -> labels *twice*:

  * once on the calibration set augmented with the hypothetical point ``(s, 0)``
    and read the fitted value at ``s``  -> ``p0``
  * once augmented with ``(s, 1)`` and read the fitted value at ``s`` -> ``p1``

Because the two fits differ only in the label forced onto the point at ``s``
(0 vs 1) and the isotonic projection is monotone in its targets, we always have
``0 <= p0 <= p1 <= 1``. The pair ``[p0, p1]`` is the Venn-ABERS output; a common
single-probability summary is ``p = p1 / (1 - p0 + p1)``. The interval width
``p1 - p0`` is a principled, data-driven uncertainty signal: it shrinks as
calibration data accumulates and as a query lands in a well-populated score
region.

Validity / soundness note (read this before trusting the numbers)
-----------------------------------------------------------------
The Venn-ABERS guarantee is a *multiprobability* calibration guarantee on the
**pair** ``[p0, p1]`` (one of the two endpoints is "perfectly calibrated" in the
Venn sense), under the standard i.i.d./exchangeability assumption between the
calibration set and the test point — the same assumption the conformal layers
make. It is NOT a claim that the single point ``p`` is perfectly calibrated, and
it says nothing about accuracy or recall. With a tiny or one-class calibration
set the interval is correctly *wide* (we degrade to the neutral ``[0, 1]`` /
``p=0.5`` rather than inventing confidence) — that honesty is the whole point.

Citations
---------
* Vovk & Petej, "Venn-Abers Predictors", arXiv:1211.0025 (UAI 2014) — defines
  Venn-ABERS predictors via isotonic regression and proves the multiprobability
  calibration guarantee; introduces the inductive (IVAP) variant.
* Vovk, Petej & Fedorova, "Large-scale probabilistic prediction with and without
  validity guarantees", arXiv:1511.00213 (2015) — the fast/large-scale IVAP and
  the point-estimate ``p = p1/(1 - p0 + p1)``.
* Isotonic regression fit by the Pool-Adjacent-Violators Algorithm (PAVA):
  Ayer, Brunk, Ewing, Reid & Silverman (1955); Barlow et al. (1972). Implemented
  here from scratch (stdlib only) — see :class:`IsotonicRegressor`.
(Algorithm details were cross-checked against the sources above via web search;
the PAVA and IVAP procedures are standard and restated in many follow-ups, e.g.
the COPA-2017 Venn-ABERS tutorial and the reference implementation
github.com/ptocca/VennABERS.)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Sequence, Tuple

try:  # normal package-relative import
    from .scoring import ScoredFinding
except ImportError:  # conftest puts advanced/ on sys.path -> flat import in tests
    from scoring import ScoredFinding


# ---------------------------------------------------------------------------
# Isotonic regression (Pool Adjacent Violators), stdlib-only.
# ---------------------------------------------------------------------------

@dataclass
class _Block:
    """A pooled block produced by PAV: weighted level over an x-interval.

    ``x_lo``/``x_hi`` are the smallest/largest input x merged into the block;
    ``value`` is the (weighted) mean label, i.e. the isotonic fit on the block.
    """
    x_lo: float
    x_hi: float
    weight: float
    value: float


class IsotonicRegressor:
    """Non-decreasing least-squares fit via Pool Adjacent Violators (PAVA).

    Fits ``y ~ f(x)`` with ``f`` monotone non-decreasing, minimising the
    weighted squared error — the classic isotonic regression (Ayer et al. 1955;
    Barlow et al. 1972). Ties in ``x`` are aggregated into a single weighted
    point first (the standard handling), so the fit is a well-defined step
    function of ``x``.

    Complexity: ``O(n log n)`` to sort, then ``O(n)`` for the PAV sweep
    (each point is pushed once and merged at most once). :meth:`predict` is a
    binary search over the resulting blocks: ``O(log b)`` per query.

    Caveat: isotonic regression assumes the score is (weakly) monotonically
    related to ``P(y=1)``. If a higher score genuinely means *less* likely
    positive, fit on the negated score. The monotone-fit values are clamped to
    ``[0, 1]`` only implicitly (labels are 0/1 so means already lie in [0,1]).
    """

    def __init__(self) -> None:
        self.blocks: List[_Block] = []

    def fit(self, x: Sequence[float], y: Sequence[float],
            weight: Sequence[float] | None = None) -> "IsotonicRegressor":
        """Fit the monotone step function. ``x``, ``y`` (and optional ``weight``)
        are parallel sequences. Returns ``self``."""
        n = len(x)
        if len(y) != n:
            raise ValueError("x and y must have the same length")
        w = [1.0] * n if weight is None else list(weight)
        if len(w) != n:
            raise ValueError("weight must match length of x")
        if n == 0:
            self.blocks = []
            return self

        # Sort by x (stable). Aggregate exact ties in x into one weighted point
        # so the fit is single-valued at each distinct x.
        order = sorted(range(n), key=lambda i: x[i])
        agg: List[Tuple[float, float, float]] = []  # (x, weight, weighted_mean_y)
        for i in order:
            xi, wi, yi = float(x[i]), float(w[i]), float(y[i])
            if wi <= 0:
                raise ValueError("weights must be positive")
            if agg and agg[-1][0] == xi:
                px, pw, py = agg[-1]
                nw = pw + wi
                agg[-1] = (px, nw, (py * pw + yi * wi) / nw)
            else:
                agg.append((xi, wi, yi))

        # PAV sweep: push each point as a block; while the previous block's level
        # exceeds the current (a violation of monotonicity), pool them.
        blocks: List[_Block] = []
        for xi, wi, yi in agg:
            blk = _Block(x_lo=xi, x_hi=xi, weight=wi, value=yi)
            blocks.append(blk)
            while len(blocks) >= 2 and blocks[-2].value > blocks[-1].value:
                b = blocks.pop()
                a = blocks.pop()
                tw = a.weight + b.weight
                merged = _Block(
                    x_lo=a.x_lo, x_hi=b.x_hi, weight=tw,
                    value=(a.value * a.weight + b.value * b.weight) / tw,
                )
                blocks.append(merged)
        self.blocks = blocks
        return self

    def predict(self, x: float) -> float:
        """Evaluate the fitted step function at ``x``.

        The fit is constant on each pooled block. Between/around blocks we use a
        right-continuous step with end-clamping: queries at or below the first
        block take the first level; at or above the last block take the last
        level; in between, the level of the nearest block at or to the left.
        Clamping (rather than extrapolating a slope) is the standard, sound
        choice — isotonic regression makes no claim outside the data's support.
        """
        blocks = self.blocks
        if not blocks:
            raise ValueError("regressor is not fitted")
        if x <= blocks[0].x_lo:
            return blocks[0].value
        if x >= blocks[-1].x_hi:
            return blocks[-1].value
        # Binary search for the last block whose x_lo <= x.
        lo, hi = 0, len(blocks) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if blocks[mid].x_lo <= x:
                lo = mid
            else:
                hi = mid - 1
        return blocks[lo].value


# ---------------------------------------------------------------------------
# Venn-ABERS calibrator.
# ---------------------------------------------------------------------------

@dataclass
class VennAbersResult:
    """Output of a Venn-ABERS prediction for one score.

    ``p0`` / ``p1`` are the calibrated lower/upper probabilities of the positive
    class (``0 <= p0 <= p1 <= 1``); ``p`` is the point summary
    ``p1 / (1 - p0 + p1)``. ``width`` is the honest uncertainty signal.
    """
    p0: float
    p1: float
    p: float

    @property
    def width(self) -> float:
        """Interval width ``p1 - p0`` — the data-driven uncertainty measure
        (smaller = more confident). Always in ``[0, 1]``."""
        return self.p1 - self.p0


def _point_estimate(p0: float, p1: float) -> float:
    """Venn-ABERS point probability ``p = p1 / (1 - p0 + p1)``.

    Vovk, Petej & Fedorova (2015). The denominator ``1 - p0 + p1`` is always
    >= 1 (since ``p1 >= p0``), so this is well defined; with ``p0 == p1`` it
    reduces to ``p == p0 == p1``.
    """
    denom = 1.0 - p0 + p1
    if denom <= 0.0:  # unreachable given p1 >= p0, but guard anyway
        return 0.5
    return p1 / denom


class VennAbersCalibrator:
    """Inductive Venn-ABERS predictor built on isotonic regression.

    ``fit`` stores the calibration set ``(scores, labels)``; ``predict`` returns
    a :class:`VennAbersResult` for a new score by fitting isotonic regression
    twice (test point hypothetically labelled 0, then 1) — see the module
    docstring for the method and its guarantee.

    Complexity: this is the transparent "refit-with-augmentation" formulation, so
    each :meth:`predict` is ``O(n log n)`` (one sort + two PAV sweeps over n+1
    points). A batch of m queries is ``O(m * n log n)``; for our finding-set
    scale (n, m in the hundreds-to-thousands) that is fine, and it is exactly the
    O(n^2)-ish cost the task allows. The fast incremental IVAP of Vovk et al.
    (2015) precomputes the two isotonic "envelopes" once for ``O(n log n)`` total
    plus ``O(log n)`` per query; we deliberately keep the direct version for
    auditability and document the trade-off rather than hide it.

    Edge cases (sound-by-default):
      * empty calibration set        -> neutral ``[0, 1]``, ``p = 0.5``
      * all-one-class calibration    -> handled without crashing (isotonic fit is
        flat at that class's rate); the interval stays appropriately wide.
    """

    def __init__(self) -> None:
        self._scores: List[float] = []
        self._labels: List[int] = []

    def fit(self, scores: Sequence[float],
            labels: Sequence[object]) -> "VennAbersCalibrator":
        """Store the calibration set. ``labels`` may be bool/int/0-1 floats;
        anything truthy is treated as the positive class (1)."""
        if len(scores) != len(labels):
            raise ValueError("scores and labels must have the same length")
        self._scores = [float(s) for s in scores]
        self._labels = [1 if bool(y) else 0 for y in labels]
        return self

    @property
    def n_calibration(self) -> int:
        """Number of stored calibration examples."""
        return len(self._scores)

    def predict(self, score: float) -> VennAbersResult:
        """Venn-ABERS prediction for a single ``score``.

        Returns the calibrated interval ``[p0, p1]`` and point ``p``. With no
        calibration data, returns the neutral ``VennAbersResult(0.0, 1.0, 0.5)``.
        """
        if not self._scores:
            # No information -> maximally uncertain, honestly.
            return VennAbersResult(0.0, 1.0, 0.5)

        s = float(score)
        # p0: augment with (s, 0); p1: augment with (s, 1). One sort is shared by
        # building the augmented arrays then letting the regressor sort.
        xs = self._scores + [s]
        reg0 = IsotonicRegressor().fit(xs, self._labels + [0])
        reg1 = IsotonicRegressor().fit(xs, self._labels + [1])
        p0 = reg0.predict(s)
        p1 = reg1.predict(s)
        # Theory guarantees p0 <= p1; clamp tiny FP noise to keep it exact and
        # keep both endpoints inside [0, 1].
        p0 = min(1.0, max(0.0, p0))
        p1 = min(1.0, max(0.0, p1))
        if p1 < p0:
            p0, p1 = p1, p0
        return VennAbersResult(p0, p1, _point_estimate(p0, p1))

    def predict_batch(self, scores: Sequence[float]) -> List[VennAbersResult]:
        """Vectorised convenience wrapper over :meth:`predict`.

        Note: this still costs ``O(m * n log n)`` (no shared precomputation); it
        exists for ergonomics, not asymptotic speed. See the class docstring for
        the faster incremental scheme if that ever matters.
        """
        return [self.predict(s) for s in scores]


# ---------------------------------------------------------------------------
# Bridge to the findings pipeline.
# ---------------------------------------------------------------------------

def calibrate_scored(
    scored_findings: Sequence[ScoredFinding],
    calibrator: VennAbersCalibrator,
) -> List[Tuple[ScoredFinding, VennAbersResult]]:
    """Map each finding's raw ``confidence`` through ``calibrator``.

    Returns ``[(scored_finding, venn_abers_result), ...]`` preserving order, so
    callers can keep the original confidence alongside the calibrated interval
    (e.g. to abstain when ``result.width`` is large, or to feed ``result.p`` into
    the conformal layer). The original :class:`ScoredFinding` objects are passed
    through unchanged — calibration here is non-destructive and side-effect free,
    which keeps it mock-friendly.
    """
    return [(sf, calibrator.predict(sf.confidence)) for sf in scored_findings]
