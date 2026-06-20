"""Output spec for the fine-tuned model — the canonical "way the model replies".

Every training pair teaches this exact shape so the model is consistent at
inference: finding -> location -> severity -> explanation -> fix.
Keep this in lock-step with baseline/report.py's rendering.
"""
from __future__ import annotations

import json
from typing import List

INSTRUCTION = (
    "You are a defensive PLC (IEC 61131-3 Structured Text) security reviewer. "
    "Review the program and report every real vulnerability. For each finding "
    "give: location (line), CWE, severity (info|low|medium|high|critical), a "
    "plain-language explanation, and a concrete remediation. If the program has "
    "no vulnerabilities, say so. Do not invent issues; only report what is real "
    "and reachable."
)


def build_prompt(source: str) -> str:
    return f"Analyze this IEC 61131-3 Structured Text program:\n\n```st\n{source}\n```"


def build_response(findings: List[dict]) -> str:
    """Render the gold response. `findings` items:
        {line, cwe, severity, explanation, fix}
    A clean program yields the explicit no-vuln response."""
    if not findings:
        return "No vulnerabilities found. The program appears safe on review."
    blocks = []
    for f in sorted(findings, key=lambda x: x.get("line", 0)):
        blocks.append(
            f"- Line {f['line']} — {f['cwe']} ({f['severity']})\n"
            f"  Explanation: {f['explanation']}\n"
            f"  Fix: {f['fix']}"
        )
    return "Findings:\n" + "\n".join(blocks)


def to_chat_record(source: str, findings: List[dict]) -> dict:
    """One training example in messages format (works for SFT / Axolotl chat)."""
    return {
        "messages": [
            {"role": "system", "content": INSTRUCTION},
            {"role": "user", "content": build_prompt(source)},
            {"role": "assistant", "content": build_response(findings)},
        ]
    }


def dumps_jsonl(records: List[dict]) -> str:
    return "\n".join(json.dumps(r, ensure_ascii=False) for r in records)
