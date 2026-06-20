"""Scoring. A finding is a true positive iff it matches a ground-truth label on
the same (line, cwe) within a small line tolerance. Reports precision, recall,
F1, and false-positives-per-program (the headline usability metric).
"""
from __future__ import annotations

from typing import List

from schema import ArmResult, Finding, Label, Program, severity_at_least

LINE_TOLERANCE = 1  # analyzers/LLMs can be off by a line


def _matches(f: Finding, label: Label) -> bool:
    return f.cwe == label.cwe and abs(f.line - label.line) <= LINE_TOLERANCE


def score(arm: str, findings: List[Finding], programs: List[Program],
          cfg: dict) -> ArmResult:
    floor = cfg["eval"]["severity_floor"]
    by_pid = {p.pid: p for p in programs}

    # Only score programs/labels at or above the severity floor.
    gold = []
    for p in programs:
        for l in p.labels:
            if severity_at_least(l.severity, floor):
                gold.append((p.pid, l))
    total_labels = len(gold)

    matched_labels = set()
    tp = 0
    fp = 0
    for f in findings:
        if not severity_at_least(f.severity, floor):
            continue
        program = by_pid.get(f.pid)
        if program is None:
            fp += 1
            continue
        hit = None
        for i, l in enumerate(program.labels):
            key = (f.pid, i)
            if key in matched_labels:
                continue
            if _matches(f, l) and severity_at_least(l.severity, floor):
                hit = key
                break
        if hit is not None:
            matched_labels.add(hit)
            tp += 1
        else:
            fp += 1

    fn = total_labels - tp
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fp_rate = fp / len(programs) if programs else 0.0

    return ArmResult(arm=arm, findings=findings, precision=precision, recall=recall,
                     f1=f1, fp_rate=fp_rate, tp=tp, fp=fp, fn=fn)


def table(results: List[ArmResult], cfg: dict) -> str:
    tr = cfg["eval"]["target_recall"]
    lines = [
        f"Operating point: target recall {tr}, severity floor "
        f"'{cfg['eval']['severity_floor']}'",
        "",
        "| Arm | Precision | Recall | F1 | FP/prog | TP | FP | FN |",
        "|-----|-----------|--------|----|---------|----|----|----|",
    ]
    label = {"A": "A frontier free-scan", "B": "B analyzer only", "C": "C hybrid"}
    for r in results:
        lines.append(
            f"| {label.get(r.arm, r.arm)} | {r.precision:.2f} | {r.recall:.2f} | "
            f"{r.f1:.2f} | {r.fp_rate:.2f} | {r.tp} | {r.fp} | {r.fn} |"
        )
    # Go/no-go verdict
    arms = {r.arm: r for r in results}
    if "A" in arms and "C" in arms:
        a, c = arms["A"], arms["C"]
        beats = (c.precision >= a.precision and c.fp_rate <= a.fp_rate
                 and c.recall >= tr)
        lines += [
            "",
            f"**Go/no-go:** hybrid (C) {'BEATS' if beats else 'does NOT beat'} "
            f"frontier (A) on precision-at-recall + FP-rate.",
            f"  -> {'Proceed to Phase 2 (data assembly).' if beats else 'Iterate grounding before any training spend.'}",
        ]
    return "\n".join(lines)
