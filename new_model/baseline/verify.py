"""Verification step for Arm C.

Rule: a finding survives only if it is grounded (backed by a deterministic
analyzer location). Ungrounded LLM claims are dropped. This is the core of the
94-98% false-positive reduction the hybrid relies on.

Also de-duplicates findings that collapse to the same (pid, line, cwe).
"""
from __future__ import annotations

from typing import List

from schema import Finding, severity_at_least


def verify(findings: List[Finding], cfg: dict) -> List[Finding]:
    floor = cfg["eval"]["severity_floor"]
    seen = set()
    out: List[Finding] = []
    for f in findings:
        if not f.grounded:
            continue
        if not severity_at_least(f.severity, floor):
            continue
        key = (f.pid, f.line, f.cwe)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
