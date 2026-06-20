"""LLM triage. Two uses:

  - triage_candidates(): Arm C. The LLM judges ONLY analyzer-surfaced candidates
    (real? severity? why? fix?). This is the FP-reduction recipe.
  - free_scan(): Arm A. The LLM scans raw source with no grounding (the frontier
    baseline the hybrid must beat).

Providers: mock (default, deterministic), anthropic, vllm (OpenAI-compatible).
"""
from __future__ import annotations

import json
import os
import re
from typing import List

from schema import Finding, Program, Verdict

TRIAGE_SYS = (
    "You are a defensive PLC (IEC 61131-3 Structured Text) security reviewer. "
    "For the given candidate finding, decide if it is a REAL vulnerability. "
    "Reply STRICT JSON: {\"is_real\": bool, \"severity\": "
    "\"info|low|medium|high|critical\", \"why\": str, \"fix\": str}. "
    "Be conservative: if it is not exploitable or not reachable, is_real=false."
)

FREESCAN_SYS = (
    "You are a PLC (IEC 61131-3 Structured Text) security reviewer. List every "
    "vulnerability you find. Reply STRICT JSON list of "
    "{\"line\": int, \"cwe\": str, \"severity\": str, \"why\": str, \"fix\": str}."
)


# --- provider plumbing --------------------------------------------------------

def _call_anthropic(model: str, system: str, user: str, cfg: dict) -> str:
    import anthropic

    client = anthropic.Anthropic()
    msg = client.messages.create(
        model=model,
        max_tokens=cfg["triage"]["max_tokens"],
        temperature=cfg["triage"]["temperature"],
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    return "".join(b.text for b in msg.content if b.type == "text")


def _call_vllm(model: str, system: str, user: str, cfg: dict) -> str:
    from openai import OpenAI

    client = OpenAI(base_url=cfg["triage"]["vllm_base_url"], api_key="EMPTY")
    resp = client.chat.completions.create(
        model=model,
        temperature=cfg["triage"]["temperature"],
        max_tokens=cfg["triage"]["max_tokens"],
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    )
    return resp.choices[0].message.content


def _extract_json(text: str):
    m = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


# --- mock backend (deterministic, no network) --------------------------------

def _mock_triage(finding: Finding, program: Program) -> Verdict:
    # Real iff a ground-truth label sits on the same line + cwe. This makes the
    # mock a useful oracle for smoke-testing the plumbing, not a real model.
    real = any(l.line == finding.line and l.cwe == finding.cwe for l in program.labels)
    return Verdict(
        is_real=real,
        severity=finding.severity,
        why=("matches known sink" if real else "benign pattern, not reachable"),
        fix=("validate/clamp the indexed access before use" if real else ""),
    )


def _mock_freescan(program: Program) -> List[Finding]:
    # Over-reports: flags every label line PLUS one spurious line -> mimics a
    # frontier free-scan's high-recall/low-precision behaviour.
    out: List[Finding] = []
    for l in program.labels:
        out.append(Finding(program.pid, l.line, l.cwe, l.severity, "frontier",
                           False, "flagged by free-scan", "apply input validation"))
    n_lines = len(program.source.splitlines())
    if n_lines:
        out.append(Finding(program.pid, max(1, n_lines // 2), "CWE-Other", "low",
                           "frontier", False, "speculative issue", ""))
    return out


# --- public API ---------------------------------------------------------------

def triage_candidates(candidates: List[Finding], programs: List[Program],
                      cfg: dict) -> List[Finding]:
    """Arm C step: keep only candidates the LLM confirms as real."""
    by_pid = {p.pid: p for p in programs}
    provider = cfg["triage"]["provider"]
    model = cfg["triage"]["model"] if provider == "anthropic" else cfg["triage"]["vllm_model"]
    kept: List[Finding] = []
    for f in candidates:
        program = by_pid[f.pid]
        if provider == "mock":
            v = _mock_triage(f, program)
        else:
            user = (
                f"Candidate: line {f.line}, {f.cwe} ({f.explanation}).\n"
                f"Program:\n{program.source}"
            )
            raw = (_call_anthropic if provider == "anthropic" else _call_vllm)(
                model, TRIAGE_SYS, user, cfg
            )
            data = _extract_json(raw) or {}
            v = Verdict(
                is_real=bool(data.get("is_real", False)),
                severity=str(data.get("severity", f.severity)),
                why=str(data.get("why", "")),
                fix=str(data.get("fix", "")),
            )
        if v.is_real:
            kept.append(Finding(f.pid, f.line, f.cwe, v.severity, "hybrid",
                               True, v.why, v.fix))
    return kept


def free_scan(programs: List[Program], cfg: dict) -> List[Finding]:
    """Arm A: ungrounded LLM free-scan (the frontier baseline)."""
    provider = cfg["baseline"]["frontier_provider"]
    model = cfg["baseline"]["frontier_model"]
    out: List[Finding] = []
    for p in programs:
        if provider == "mock":
            out.extend(_mock_freescan(p))
            continue
        raw = _call_anthropic(model, FREESCAN_SYS, p.source, cfg)
        for d in _extract_json(raw) or []:
            out.append(Finding(p.pid, int(d.get("line", 0)), str(d.get("cwe", "CWE-Other")),
                              str(d.get("severity", "medium")), "frontier", False,
                              str(d.get("why", "")), str(d.get("fix", ""))))
    return out
