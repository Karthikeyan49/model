"""Interprocedural taint via compositional function summaries.

Whole-program reasoning is where a stateless LLM hits a wall: it can't reliably
track taint across many function blocks that don't fit in one context window, and
it re-derives nothing between calls. A specialist computes a *summary* per function
block once ("input param P reaches a dangerous sink"), builds a call graph, and
propagates taint across calls to a fixpoint — compositional analysis that scales to
arbitrarily large programs (IFDS/summary-based, the classic scalable technique).

Model (minimal IEC 61131-3):
  - FUNCTION_BLOCK FB ... VAR_INPUT p : T; END_VAR ... body ...
  - a body sink `arr[p ...]` or `_ / p` makes param `p` a "sink param" of FB.
  - a body call `FB2(x := expr)` connects expr's taint to FB2's param.
  - a top-level PROGRAM taints VAR_INPUT vars and calls FBs.
Taint reaches a sink iff a tainted actual argument maps to a sink param,
transitively across the call graph (computed to a fixpoint).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set

from schema import Program

_FB = re.compile(r"\bFUNCTION_BLOCK\s+([A-Za-z_]\w*)(.*?)\bEND_FUNCTION_BLOCK\b",
                 re.IGNORECASE | re.DOTALL)
_PROGRAM = re.compile(r"\bPROGRAM\s+([A-Za-z_]\w*)(.*?)\bEND_PROGRAM\b",
                      re.IGNORECASE | re.DOTALL)
_VAR_INPUT = re.compile(r"\bVAR_INPUT\b(.*?)\bEND_VAR\b", re.IGNORECASE | re.DOTALL)
_PARAM = re.compile(r"([A-Za-z_]\w*)\s*:")
_SINK_INDEX = re.compile(r"\[\s*([A-Za-z_]\w*)")
_SINK_DIV = re.compile(r"/\s*([A-Za-z_]\w*)")
# call:  FBName( formal := actual , ... )
_CALL = re.compile(r"([A-Za-z_]\w*)\s*\(([^)]*)\)")
_ARG = re.compile(r"([A-Za-z_]\w*)\s*:=\s*([A-Za-z_]\w*)")


@dataclass
class Summary:
    name: str
    params: List[str] = field(default_factory=list)
    sink_params: Set[str] = field(default_factory=set)      # params reaching a sink
    calls: List[tuple] = field(default_factory=list)        # (callee, {formal: actual})


@dataclass
class InterprocFinding:
    program: str
    cwe: str
    path: List[str]                  # source → call chain → sink


def _params(block: str) -> List[str]:
    out = []
    for vi in _VAR_INPUT.findall(block):
        out += _PARAM.findall(vi)
    return out


def _summarize_block(name: str, block: str) -> Summary:
    params = _params(block)
    s = Summary(name=name, params=params)
    body = _VAR_INPUT.sub("", block)  # strip decls so sinks aren't matched in them
    for line in body.splitlines():
        for var in _SINK_INDEX.findall(line):
            if var in params:
                s.sink_params.add(var)
        for var in _SINK_DIV.findall(line):
            if var in params:
                s.sink_params.add(var)
    for m in _CALL.finditer(body):
        callee, argstr = m.group(1), m.group(2)
        if callee.upper() in ("IF", "WHILE", "FOR"):
            continue
        mapping = {f: a for f, a in _ARG.findall(argstr)}
        if mapping:
            s.calls.append((callee, mapping))
    return s


def build_summaries(source: str) -> Dict[str, Summary]:
    summaries: Dict[str, Summary] = {}
    for m in _FB.finditer(source):
        summaries[m.group(1)] = _summarize_block(m.group(1), m.group(2))
    return summaries


def _reaches_sink(callee: str, actual_tainted: str, summaries: Dict[str, Summary],
                  mapping: Dict[str, str], seen: Set[str]) -> bool:
    """Does a tainted actual argument reach a sink in callee (transitively)?"""
    if callee not in summaries or callee in seen:
        return False
    seen = seen | {callee}
    s = summaries[callee]
    # which formal params receive the tainted actual?
    tainted_formals = {f for f, a in mapping.items() if a == actual_tainted}
    if tainted_formals & s.sink_params:
        return True
    # propagate into nested calls
    for nested_callee, nested_map in s.calls:
        for f, a in nested_map.items():
            if a in tainted_formals and _reaches_sink(nested_callee, a, summaries,
                                                      nested_map, seen):
                return True
    return False


def analyze(program: Program) -> List[InterprocFinding]:
    src = program.source
    summaries = build_summaries(src)
    findings: List[InterprocFinding] = []
    for m in _PROGRAM.finditer(src):
        pname, body = m.group(1), m.group(2)
        tainted = set(_params(body))   # VAR_INPUT of the program = tainted sources
        body_wo_decl = _VAR_INPUT.sub("", body)
        for cm in _CALL.finditer(body_wo_decl):
            callee, argstr = cm.group(1), cm.group(2)
            if callee.upper() in ("IF", "WHILE", "FOR"):
                continue
            mapping = {f: a for f, a in _ARG.findall(argstr)}
            for formal, actual in mapping.items():
                if actual in tainted and _reaches_sink(callee, actual, summaries,
                                                       mapping, set()):
                    cwe = "CWE-787"  # refined by callee sink kind in a fuller impl
                    findings.append(InterprocFinding(
                        pname, cwe,
                        [f"source:{actual}", f"call {callee}({formal}:={actual})",
                         f"sink in {callee}"]))
    return findings
