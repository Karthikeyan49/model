"""Render per-finding reports: location / severity / explanation / fix.
This is the product's output style — the "way the model replies."
"""
from __future__ import annotations

import os
from typing import List

from schema import ArmResult, Finding


def render_findings(findings: List[Finding]) -> str:
    if not findings:
        return "_No findings._\n"
    out = []
    for f in sorted(findings, key=lambda x: (x.pid, -x.sev_rank(), x.line)):
        out.append(
            f"### {f.pid}:{f.line} — {f.cwe} ({f.severity})\n"
            f"- **Source:** {f.source} (grounded={f.grounded})\n"
            f"- **Why:** {f.explanation or 'n/a'}\n"
            f"- **Fix:** {f.fix or 'n/a'}\n"
        )
    return "\n".join(out)


def write_report(results: List[ArmResult], metrics_table: str, cfg: dict) -> str:
    out_dir = cfg["report"]["out_dir"]
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "phase1_report.md")
    arms = {r.arm: r for r in results}
    hybrid = arms.get("C")
    body = [
        "# Phase 1 — OT/PLC Hybrid Baseline Results\n",
        "## Metrics\n",
        metrics_table,
        "\n## Hybrid (Arm C) findings\n",
        render_findings(hybrid.findings if hybrid else []),
    ]
    with open(path, "w") as fh:
        fh.write("\n".join(body))
    return path
