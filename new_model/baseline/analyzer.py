"""Deterministic analyzer arm: run iec-checker over ST programs and normalise
its output to Finding objects. This is the grounding half of the hybrid.

If the iec-checker binary is unavailable and analyzer.mock_if_missing is true, a
small heuristic mock runs instead so the harness is runnable without setup.
The mock is NOT a real analyzer — it exists only for the smoke test.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from typing import Dict, List, Tuple

from schema import Finding, Program

_RULE_MAP_PATH = os.path.join(os.path.dirname(__file__), "rule_map.json")


def _load_rule_map() -> Dict[str, Tuple[str, str]]:
    """Load iec-checker rule id -> (CWE, severity) from rule_map.json."""
    with open(_RULE_MAP_PATH) as fh:
        raw = json.load(fh)
    return {k: (v[0], v[1]) for k, v in raw.items() if not k.startswith("_")}


RULE_TO_CWE = _load_rule_map()


def _have_binary(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run_iec_checker(program: Program, binary: str, args: List[str]) -> List[Finding]:
    """Invoke iec-checker and parse its JSON diagnostics.
    iec-checker emits one diagnostic per issue; we map rule -> CWE/severity."""
    cmd = [binary, *args, "--output-format", "json", program.path]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    findings: List[Finding] = []
    try:
        diagnostics = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return findings
    for d in diagnostics:
        rule = str(d.get("rule", d.get("id", "")))
        cwe, sev = RULE_TO_CWE.get(rule, ("CWE-Other", "low"))
        findings.append(
            Finding(
                pid=program.pid,
                line=int(d.get("line", 0)),
                cwe=cwe,
                severity=sev,
                source="analyzer",
                grounded=True,
                explanation=str(d.get("message", rule)),
            )
        )
    return findings


# --- mock analyzer (smoke test only) -----------------------------------------

_MOCK_PATTERNS = [
    (re.compile(r"\[\s*\w+\s*\+\s*\d+\s*\]"), "CWE-787", "high", "possible OOB index"),
    (re.compile(r"/\s*0\b"), "CWE-369", "medium", "division by zero"),
    (re.compile(r"\bVAR\b(?![\s\S]*:=)"), "CWE-457", "low", "uninitialized var"),
]


def _run_mock(program: Program) -> List[Finding]:
    findings: List[Finding] = []
    for i, line in enumerate(program.source.splitlines(), start=1):
        for pat, cwe, sev, msg in _MOCK_PATTERNS:
            if pat.search(line):
                findings.append(
                    Finding(program.pid, i, cwe, sev, "analyzer", True, msg)
                )
    return findings


def analyze(programs: List[Program], cfg: dict) -> List[Finding]:
    binary = cfg["analyzer"]["binary"]
    args = cfg["analyzer"].get("args", [])
    use_real = _have_binary(binary)
    if not use_real and not cfg["analyzer"].get("mock_if_missing", True):
        raise RuntimeError(f"iec-checker '{binary}' not found and mock disabled")

    out: List[Finding] = []
    for p in programs:
        if use_real:
            out.extend(_run_iec_checker(p, binary, args))
        else:
            out.extend(_run_mock(p))
    return out
