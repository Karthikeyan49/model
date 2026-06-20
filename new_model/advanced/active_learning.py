"""Active learning — turn the abstain bucket into the most valuable labels.

The conformal layer abstains on uncertain findings. Instead of those being dead
weight, they are the single most informative thing a human can label: examples the
model is least sure about. Labeling near the decision boundary improves the model
far faster than labeling random data — this is what makes the data flywheel turn
with minimal human effort.

Selection strategies (classic active learning):
  - margin    : closest to the decision threshold (|conf - threshold| small).
  - entropy   : highest binary entropy (conf near 0.5).
  - diversity : de-duplicate by CWE so a batch isn't all one weakness class.

Output: a ranked, deduplicated labeling queue with a reason per item.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import List

from scoring import ScoredFinding


@dataclass
class QueueItem:
    scored: ScoredFinding
    priority: float
    reason: str


def _entropy(p: float) -> float:
    p = min(max(p, 1e-9), 1 - 1e-9)
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def select(abstained: List[ScoredFinding], threshold: float, k: int = 10,
           strategy: str = "margin", diversify: bool = True) -> List[QueueItem]:
    items: List[QueueItem] = []
    for s in abstained:
        if strategy == "entropy":
            pr = _entropy(s.confidence)
            reason = f"entropy={pr:.3f} (near 0.5)"
        else:  # margin
            pr = 1.0 - abs(s.confidence - threshold)
            reason = f"margin={abs(s.confidence - threshold):.3f} from threshold"
        items.append(QueueItem(s, round(pr, 4), reason))

    items.sort(key=lambda x: x.priority, reverse=True)

    if diversify:
        seen_cwe, balanced, overflow = set(), [], []
        for it in items:
            cwe = it.scored.finding.cwe
            (balanced if cwe not in seen_cwe else overflow).append(it)
            seen_cwe.add(cwe)
        items = balanced + overflow  # one-per-CWE first, then the rest

    return items[:k]


def render(queue: List[QueueItem]) -> str:
    lines = ["Labeling queue (most informative first):"]
    for i, it in enumerate(queue, 1):
        f = it.scored.finding
        lines.append(f"{i:2d}. {f.pid}:{f.line} {f.cwe} "
                     f"conf={it.scored.confidence:.3f} — {it.reason}")
    return "\n".join(lines)
