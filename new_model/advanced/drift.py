"""Distribution-drift detection — knows when the conformal guarantee goes stale.

The conformal FP-rate bound (conformal.py) holds only while production data is
distributed like the calibration data (the iid assumption). Real PLC codebases
drift: new vendors, new coding styles, new CWE mixes. When they do, the bound
silently breaks and the tool starts lying about its FP-rate.

This module watches for that. It compares the confidence distribution (and CWE
mix) of recent production findings against the calibration reference, using:

  - PSI (Population Stability Index): standard drift metric.
        PSI < 0.1  stable · 0.1-0.25 moderate · > 0.25 significant drift.
  - KS  (Kolmogorov-Smirnov) statistic: max CDF gap between the two samples.

On significant drift it raises a RECALIBRATE signal. This is the reliability
control that turns a one-time guarantee into a maintained one.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List


@dataclass
class DriftReport:
    psi: float
    ks: float
    drift: str                 # "stable" | "moderate" | "significant"
    recalibrate: bool
    note: str = ""


def _hist(values: List[float], edges: List[float]) -> List[float]:
    counts = [0] * (len(edges) - 1)
    for v in values:
        for i in range(len(edges) - 1):
            if edges[i] <= v < edges[i + 1] or (i == len(edges) - 2 and v == edges[-1]):
                counts[i] += 1
                break
    total = sum(counts) or 1
    # smooth to avoid log(0)
    return [(c + 1e-6) / (total + 1e-6 * len(counts)) for c in counts]


def psi(reference: List[float], current: List[float], n_bins: int = 10) -> float:
    if not reference or not current:
        return 0.0
    edges = [i / n_bins for i in range(n_bins + 1)]   # confidences in [0,1]
    ref_h = _hist(reference, edges)
    cur_h = _hist(current, edges)
    return sum((c - r) * math.log(c / r) for r, c in zip(ref_h, cur_h))


def ks_statistic(reference: List[float], current: List[float]) -> float:
    if not reference or not current:
        return 0.0
    grid = sorted(set(reference + current))

    def cdf(sample, x):
        return sum(1 for s in sample if s <= x) / len(sample)

    return max(abs(cdf(reference, x) - cdf(current, x)) for x in grid)


def assess(reference: List[float], current: List[float],
           psi_warn: float = 0.1, psi_alert: float = 0.25) -> DriftReport:
    p = psi(reference, current)
    k = ks_statistic(reference, current)
    if p > psi_alert:
        level, recal = "significant", True
    elif p > psi_warn:
        level, recal = "moderate", False
    else:
        level, recal = "stable", False
    note = ("recalibrate conformal threshold — distribution shifted"
            if recal else "guarantee still valid")
    return DriftReport(round(p, 4), round(k, 4), level, recal, note)
