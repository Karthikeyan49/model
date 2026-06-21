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


# --- Combined drift verdict + recommendation ---------------------------------
#
# `assess` keys the verdict off PSI alone. The combined assessment below fuses
# both available drift signals (PSI and KS) into a single, actionable
# recommendation in {"OK", "MONITOR", "RECALIBRATE"}, so the standing caveat
# "the conformal guarantee assumes iid — recalibrate on drift" becomes an
# explicit operational instruction.
#
# Documented thresholds:
#   PSI (population stability index, common rule-of-thumb):
#       < 0.10            -> no significant change
#       0.10 .. 0.25      -> moderate shift (monitor)
#       > 0.25            -> major shift (recalibrate)
#   KS (Kolmogorov-Smirnov statistic, max CDF gap in [0, 1]):
#       a large gap is independent evidence of a distribution shift. We treat
#       ks > ks_alert as recalibrate-worthy and ks > ks_warn as monitor-worthy.
#       Defaults (0.1 / 0.2) are conservative operating points; tune per fleet.
#
# Decision: take the MORE severe of the two signals (fail-safe toward
# recalibration), because either metric crossing its alert band is enough to
# invalidate the iid assumption the conformal bound rests on.

_VERDICT_RANK = {"OK": 0, "MONITOR": 1, "RECALIBRATE": 2}


@dataclass
class CombinedDriftResult:
    psi: float
    ks: float
    verdict: str               # "OK" | "MONITOR" | "RECALIBRATE"
    recalibrate: bool          # True iff verdict == "RECALIBRATE"
    reason: str                # human-readable explanation
    psi_warn: float = 0.1
    psi_alert: float = 0.25
    ks_warn: float = 0.1
    ks_alert: float = 0.2

    def as_dict(self) -> dict:
        return {
            "psi": self.psi,
            "ks": self.ks,
            "verdict": self.verdict,
            "recalibrate": self.recalibrate,
            "reason": self.reason,
        }


def combined_assessment(reference: List[float], current: List[float],
                        psi_warn: float = 0.1, psi_alert: float = 0.25,
                        ks_warn: float = 0.1, ks_alert: float = 0.2
                        ) -> CombinedDriftResult:
    """Fuse PSI and KS into a single verdict + recommendation.

    Returns a CombinedDriftResult holding both individual metrics, the combined
    verdict in {"OK", "MONITOR", "RECALIBRATE"}, a `recalibrate` flag, and a
    human-readable reason citing which signal drove the decision.

    The verdict is the most severe of the per-metric verdicts (fail-safe): if
    *either* PSI or KS lands in its alert band the result is RECALIBRATE; if
    either lands in its warn band (and neither alerts) the result is MONITOR;
    otherwise OK.

    Reminder: conformal FP-rate control is marginal and assumes calibration and
    production data are exchangeable (iid). A RECALIBRATE verdict means that
    assumption is likely violated and the guarantee should be re-derived on
    fresh calibration data.
    """
    p = psi(reference, current)
    k = ks_statistic(reference, current)

    if p > psi_alert:
        psi_verdict, psi_reason = "RECALIBRATE", (
            f"PSI={p:.4f} > {psi_alert} (major shift)")
    elif p > psi_warn:
        psi_verdict, psi_reason = "MONITOR", (
            f"PSI={p:.4f} in [{psi_warn}, {psi_alert}] (moderate shift)")
    else:
        psi_verdict, psi_reason = "OK", f"PSI={p:.4f} < {psi_warn} (stable)"

    if k > ks_alert:
        ks_verdict, ks_reason = "RECALIBRATE", (
            f"KS={k:.4f} > {ks_alert} (large CDF gap)")
    elif k > ks_warn:
        ks_verdict, ks_reason = "MONITOR", (
            f"KS={k:.4f} in [{ks_warn}, {ks_alert}] (moderate CDF gap)")
    else:
        ks_verdict, ks_reason = "OK", f"KS={k:.4f} < {ks_warn} (stable)"

    # Most severe of the two drives the verdict (fail-safe toward recalibration).
    if _VERDICT_RANK[psi_verdict] >= _VERDICT_RANK[ks_verdict]:
        verdict, driver = psi_verdict, psi_reason
    else:
        verdict, driver = ks_verdict, ks_reason

    if verdict == "RECALIBRATE":
        reason = (f"{driver} — distribution shifted; re-derive the conformal "
                  f"threshold on fresh calibration data (iid assumption broken)")
    elif verdict == "MONITOR":
        reason = (f"{driver} — watch closely; guarantee still plausibly valid "
                  f"but trending")
    else:
        reason = f"{driver} — no significant drift; conformal guarantee valid"

    return CombinedDriftResult(round(p, 4), round(k, 4), verdict,
                               verdict == "RECALIBRATE", reason,
                               psi_warn, psi_alert, ks_warn, ks_alert)
