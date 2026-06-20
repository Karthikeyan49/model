"""Calibration measurement — is the model's confidence trustworthy?

A confidence of 0.8 should be right ~80% of the time. If it isn't, every
downstream decision (conformal threshold, abstention, prioritisation) is built on
sand. This module measures that with standard, rigorous metrics:

  - ECE  (Expected Calibration Error): gap between confidence and accuracy, binned.
  - MCE  (Maximum Calibration Error): worst-case bin gap.
  - Brier score: mean squared error of probabilistic predictions.
  - reliability diagram data: per-bin (confidence, accuracy) for plotting.

"Whoever measures best, improves fastest" — this is the measurement that tells you
whether the confidence pipeline can be trusted, and is the prerequisite for the
conformal guarantee to mean anything.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple


@dataclass
class CalibrationReport:
    ece: float
    mce: float
    brier: float
    n: int
    bins: List[dict] = field(default_factory=list)   # {lo, hi, conf, acc, count}


def evaluate(pairs: List[Tuple[float, bool]], n_bins: int = 10) -> CalibrationReport:
    """pairs: (confidence, is_correct/is_true). Returns calibration metrics."""
    if not pairs:
        return CalibrationReport(0.0, 0.0, 0.0, 0, [])

    brier = sum((c - (1.0 if t else 0.0)) ** 2 for c, t in pairs) / len(pairs)

    bins = []
    ece = 0.0
    mce = 0.0
    n = len(pairs)
    for b in range(n_bins):
        lo, hi = b / n_bins, (b + 1) / n_bins
        # last bin is inclusive of 1.0
        in_bin = [(c, t) for c, t in pairs
                  if (c >= lo and c < hi) or (b == n_bins - 1 and c == 1.0)]
        if not in_bin:
            bins.append({"lo": lo, "hi": hi, "conf": 0.0, "acc": 0.0, "count": 0})
            continue
        conf = sum(c for c, _ in in_bin) / len(in_bin)
        acc = sum(1 for _, t in in_bin if t) / len(in_bin)
        gap = abs(conf - acc)
        ece += (len(in_bin) / n) * gap
        mce = max(mce, gap)
        bins.append({"lo": round(lo, 2), "hi": round(hi, 2),
                     "conf": round(conf, 4), "acc": round(acc, 4),
                     "count": len(in_bin)})
    return CalibrationReport(round(ece, 4), round(mce, 4), round(brier, 4), n, bins)


def render(report: CalibrationReport) -> str:
    lines = [f"Calibration: ECE={report.ece} MCE={report.mce} "
             f"Brier={report.brier} (n={report.n})",
             "bin            conf   acc   count"]
    for b in report.bins:
        if b["count"]:
            bar = "#" * int(b["acc"] * 20)
            lines.append(f"[{b['lo']:.1f},{b['hi']:.1f})   {b['conf']:.2f}  "
                         f"{b['acc']:.2f}  {b['count']:4d}  {bar}")
    return "\n".join(lines)
