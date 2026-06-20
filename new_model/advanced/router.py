"""Expert router for the per-CWE LoRA MoE (advanced/moe_routing.yaml).

Rule-based by default (deterministic, debuggable). Returns the expert name(s) a
candidate finding should be triaged by. A learned router can later replace
`route()` without changing callers.
"""
from __future__ import annotations

import os
from typing import List

import yaml

from schema import Finding

_CFG_PATH = os.path.join(os.path.dirname(__file__), "moe_routing.yaml")


def load_config(path: str = _CFG_PATH) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def route(finding: Finding, cfg: dict) -> List[str]:
    router = cfg["router"]
    if router["type"] != "rule_based":
        raise NotImplementedError("learned router not yet trained; use rule_based")
    for rule in router.get("rules", []):
        if finding.cwe in rule.get("match_cwe", []):
            return [rule["expert"]]
    return [router["default_expert"]]


def route_all(findings: List[Finding], cfg: dict) -> dict:
    """Group findings by expert -> list of findings (a routing plan)."""
    plan: dict = {}
    for f in findings:
        for expert in route(f, cfg):
            plan.setdefault(expert, []).append(f)
    return plan
