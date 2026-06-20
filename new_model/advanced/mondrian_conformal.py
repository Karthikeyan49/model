"""Mondrian (class-conditional) conformal selective prediction.

The sibling module ``conformal.py`` calibrates ONE global confidence threshold so
the emitted set's false-positive fraction is <= alpha. That bound is *marginal*:
it holds on average over the whole population but not necessarily within any
sub-population. When false-positive cost is heterogeneous across weakness classes
(CWEs), a single global threshold can silently over-emit one CWE while
over-abstaining another — the global FP budget is "paid for" unevenly.

Mondrian conformal prediction (Vovk, Lindsay, Nouretdinov & Gammerman, 2003;
"Mondrian Confidence Machine") fixes this by partitioning the calibration data
into groups (a "Mondrian taxonomy") and calibrating a SEPARATE threshold per
group. Each per-group threshold controls the FP budget alpha *within that class*,
giving class-conditional (group-conditional) validity instead of mere marginal
validity. This is the standard remedy for heterogeneous populations and is the
group-conditional analogue of the conformal abstention framing in ``conformal.py``
(arXiv 2405.01563; conformal selective prediction).

Soundness / honesty note
-------------------------
Class-conditional validity needs enough calibration samples *per group*. For a
group with fewer than ``min_group`` samples we cannot honestly claim a
class-conditional bound, so we FALL BACK to a pooled (global) threshold computed
over all data. That fallback is sound but only *marginal* — not class-conditional
— for those small classes. We record this explicitly via ``used_fallback`` so an
operator can see exactly which classes have the weaker (marginal-only) guarantee.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Mapping, Tuple

import conformal
from conformal import CalibratedThreshold
from scoring import ScoredFinding


# A calibration pair is (confidence, is_true_vulnerability), matching conformal.py.
CalPair = Tuple[float, bool]
# When carrying the group key alongside, a pair is (cwe, confidence, is_true).
CalPairWithCwe = Tuple[str, float, bool]


@dataclass
class MondrianThresholds:
    """Per-group calibrated thresholds plus a pooled fallback.

    ``per_group`` maps a group key (CWE string) -> CalibratedThreshold derived
    *within that group* (class-conditional, valid when n >= min_group).
    ``fallback`` is the pooled/global CalibratedThreshold computed over ALL
    calibration data; it is used for small groups and for groups unseen at
    calibration time. ``fallback_groups`` lists the calibration groups that fell
    back (too few samples) — their guarantee is only marginal, not
    class-conditional.
    """
    per_group: Dict[str, CalibratedThreshold]
    fallback: CalibratedThreshold
    fallback_groups: List[str] = field(default_factory=list)
    alpha: float = 0.1
    min_group: int = 10

    def threshold_for(self, group: str) -> CalibratedThreshold:
        """Resolve the threshold for a group, defaulting to the pooled fallback
        for groups never seen during calibration."""
        return self.per_group.get(group, self.fallback)

    def used_fallback(self, group: str) -> bool:
        """True if ``group``'s guarantee is the pooled (marginal-only) fallback:
        either it had too few samples, or it was unseen at calibration time."""
        return group not in self.per_group or group in self.fallback_groups


def group_calibration(
    pairs_with_cwe: Iterable[CalPairWithCwe],
) -> Dict[str, List[CalPair]]:
    """Build the by-group dict expected by :func:`calibrate_mondrian`.

    Input: an iterable of (cwe, confidence, is_true) triples.
    Output: {cwe -> [(confidence, is_true), ...]}.
    """
    by_group: Dict[str, List[CalPair]] = {}
    for cwe, conf, is_true in pairs_with_cwe:
        by_group.setdefault(cwe, []).append((conf, is_true))
    return by_group


def calibrate_mondrian(
    calibration_by_group: Mapping[str, List[CalPair]],
    alpha: float = 0.1,
    min_coverage: float = 0.0,
    min_group: int = 10,
) -> MondrianThresholds:
    """Calibrate one conformal threshold per group (CWE).

    ``calibration_by_group``: {group_key -> [(confidence, is_true), ...]}.

    For each group with >= ``min_group`` samples, the threshold is derived with
    the SAME split-conformal logic as :func:`conformal.calibrate`, applied to
    that group's data only — yielding a class-conditional FP bound of ``alpha``.

    Groups with fewer than ``min_group`` samples cannot support a class-conditional
    bound, so they reuse a pooled/global threshold calibrated over ALL data
    (sound but only marginal — flagged in ``fallback_groups``). Groups unseen at
    calibration time also resolve to the pooled fallback at apply time.
    """
    # Pooled fallback: all pairs across every group, calibrated globally.
    pooled: List[CalPair] = [pair for pairs in calibration_by_group.values()
                             for pair in pairs]
    fallback = conformal.calibrate(pooled, alpha=alpha, min_coverage=min_coverage)

    per_group: Dict[str, CalibratedThreshold] = {}
    fallback_groups: List[str] = []

    for group, pairs in calibration_by_group.items():
        if len(pairs) >= min_group:
            # Enough data => honest class-conditional calibration.
            per_group[group] = conformal.calibrate(
                pairs, alpha=alpha, min_coverage=min_coverage
            )
        else:
            # Too few samples => fall back to pooled (marginal-only) threshold.
            per_group[group] = fallback
            fallback_groups.append(group)

    return MondrianThresholds(
        per_group=per_group,
        fallback=fallback,
        fallback_groups=fallback_groups,
        alpha=alpha,
        min_group=min_group,
    )


def apply_mondrian(
    scored: List[ScoredFinding],
    mt: MondrianThresholds,
) -> Tuple[List[ScoredFinding], List[ScoredFinding]]:
    """Split ``scored`` into (emitted, abstained) using each finding's group
    threshold.

    Each finding is thresholded against the calibrated threshold for its CWE
    (``finding.cwe``); findings whose CWE was unseen at calibration time use the
    pooled fallback threshold. Mirrors :func:`conformal.apply` but routes
    per-group.
    """
    emitted: List[ScoredFinding] = []
    abstained: List[ScoredFinding] = []
    for s in scored:
        cal = mt.threshold_for(s.finding.cwe)
        if s.confidence >= cal.threshold:
            emitted.append(s)
        else:
            abstained.append(s)
    return emitted, abstained


@dataclass
class GroupReport:
    group: str
    threshold: float
    achieved_fp: float
    coverage: float
    n_cal: int
    used_fallback: bool


def report(mt: MondrianThresholds) -> List[GroupReport]:
    """Per-group operator summary: threshold, achieved FP, coverage, n, and
    whether the (weaker, marginal-only) pooled fallback was used.

    Returned rows are sorted by group key for stable output.
    """
    rows: List[GroupReport] = []
    for group in sorted(mt.per_group):
        cal = mt.per_group[group]
        rows.append(
            GroupReport(
                group=group,
                threshold=cal.threshold,
                achieved_fp=cal.achieved_fp,
                coverage=cal.coverage,
                n_cal=cal.n_cal,
                used_fallback=mt.used_fallback(group),
            )
        )
    return rows


def format_report(mt: MondrianThresholds) -> str:
    """Human-readable table of :func:`report`, including the pooled fallback row."""
    lines = [
        f"Mondrian conformal thresholds (alpha={mt.alpha}, min_group={mt.min_group})",
        f"{'group':<16}{'thr':>8}{'fp':>8}{'cov':>8}{'n':>6}  fallback",
    ]
    for r in report(mt):
        lines.append(
            f"{r.group:<16}{r.threshold:>8.3f}{r.achieved_fp:>8.3f}"
            f"{r.coverage:>8.3f}{r.n_cal:>6}  {r.used_fallback}"
        )
    fb = mt.fallback
    lines.append(
        f"{'<pooled/fallback>':<16}{fb.threshold:>8.3f}{fb.achieved_fp:>8.3f}"
        f"{fb.coverage:>8.3f}{fb.n_cal:>6}  (used for unseen/small groups)"
    )
    return "\n".join(lines)
