"""Phase 6 — SARIF 2.1.0 output.

SARIF is the industry-standard static-analysis result format; emitting it lets the
scanner drop straight into CI/CD (GitHub code scanning, Azure DevOps, etc.) — the
"scan on commit" distribution model from the plan. Converts our Finding objects
into a SARIF run.
"""
from __future__ import annotations

import json
from typing import List

from schema import Finding

# SARIF "level" only has error/warning/note — map our severities onto it.
SEV_TO_LEVEL = {
    "critical": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
}


def to_sarif(findings: List[Finding], tool_name: str = "plc-vuln-scanner",
             version: str = "0.1.0") -> dict:
    rules = {}
    results = []
    for f in findings:
        rule_id = f.cwe or "CWE-Other"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": f"{rule_id} weakness"},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{_cwe_num(rule_id)}.html",
        })
        results.append({
            "ruleId": rule_id,
            "level": SEV_TO_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.explanation or rule_id},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.pid},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
            "properties": {
                "severity": f.severity,
                "source": f.source,
                "grounded": f.grounded,
                "fix": f.fix,
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": version,
                "informationUri": "https://example.invalid/plc-vuln-scanner",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def _cwe_num(cwe: str) -> str:
    return cwe.split("-")[-1] if cwe and cwe.upper().startswith("CWE-") else "0"


def write_sarif(findings: List[Finding], path: str) -> str:
    with open(path, "w") as fh:
        json.dump(to_sarif(findings), fh, indent=2)
    return path
