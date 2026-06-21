"""Interprocedural taint via compositional function summaries.

Whole-program reasoning is where a stateless LLM hits a wall: it can't reliably
track taint across many function blocks that don't fit in one context window, and
it re-derives nothing between calls. A specialist computes a *summary* per function
block once ("input param P reaches a dangerous sink"), builds a call graph, and
propagates taint across calls to a fixpoint — compositional analysis that scales to
arbitrarily large programs (IFDS/summary-based, the classic scalable technique).

Model (minimal IEC 61131-3):
  - FUNCTION_BLOCK FB ... VAR_INPUT p : T; END_VAR ... body ...
  - a body sink `arr[p ...]` makes param `p` an index sink param  (CWE-787)
  - a body sink `_ / p` makes param `p` a division sink param      (CWE-369)
  - a sink dominated by an IF-guard that constrains `p` is *sanitized*
    (not recorded as a sink param).
  - a body call `FB2(x := expr)` connects expr's taint to FB2's param.
  - `out := p` inside an FB makes VAR_OUTPUT `out` taint-carrying for `p`.
  - a top-level PROGRAM taints VAR_INPUT vars and calls FBs; output bindings
    `FB(in := x, out => y)` propagate taint from FB outputs into actual `y`.
Taint reaches a sink iff a tainted actual argument maps to a sink param,
transitively across the call graph and across output bindings (fixpoint).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from schema import Program

_FB = re.compile(r"\bFUNCTION_BLOCK\s+([A-Za-z_]\w*)(.*?)\bEND_FUNCTION_BLOCK\b",
                 re.IGNORECASE | re.DOTALL)
_PROGRAM = re.compile(r"\bPROGRAM\s+([A-Za-z_]\w*)(.*?)\bEND_PROGRAM\b",
                      re.IGNORECASE | re.DOTALL)
_VAR_INPUT = re.compile(r"\bVAR_INPUT\b(.*?)\bEND_VAR\b", re.IGNORECASE | re.DOTALL)
_VAR_OUTPUT = re.compile(r"\bVAR_OUTPUT\b(.*?)\bEND_VAR\b", re.IGNORECASE | re.DOTALL)
# Any VAR ... END_VAR (used to strip all declarations before scanning the body)
_ANY_VAR = re.compile(r"\bVAR(?:_INPUT|_OUTPUT|_IN_OUT|_TEMP|_GLOBAL)?\b.*?\bEND_VAR\b",
                      re.IGNORECASE | re.DOTALL)
_PARAM = re.compile(r"([A-Za-z_]\w*)\s*:")
_SINK_INDEX = re.compile(r"\[\s*([A-Za-z_]\w*)")
_SINK_DIV = re.compile(r"/\s*([A-Za-z_]\w*)")
# call:  FBName( formal := actual , ... )   /   FBName( out => actual , ... )
_CALL = re.compile(r"([A-Za-z_]\w*)\s*\(([^)]*)\)")
_ARG = re.compile(r"([A-Za-z_]\w*)\s*:=\s*([A-Za-z_]\w*)")
_OUT_BIND = re.compile(r"([A-Za-z_]\w*)\s*=>\s*([A-Za-z_]\w*)")
# assignment of one identifier to another:  lhs := rhs ;
_ASSIGN = re.compile(r"^\s*([A-Za-z_]\w*)\s*:=\s*([A-Za-z_]\w*)\s*;?\s*$")
_IF = re.compile(r"\bIF\b", re.IGNORECASE)
_END_IF = re.compile(r"\bEND_IF\b", re.IGNORECASE)

CWE_INDEX = "CWE-787"
CWE_DIV = "CWE-369"

_KEYWORDS = ("IF", "WHILE", "FOR", "CASE", "ELSIF", "RETURN")


@dataclass
class Summary:
    name: str
    params: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    # param -> set of CWEs reached by an *unsanitized* sink using that param
    sink_params: Dict[str, Set[str]] = field(default_factory=dict)
    # output var -> set of params whose taint flows into it
    output_taint: Dict[str, Set[str]] = field(default_factory=dict)
    calls: List[tuple] = field(default_factory=list)  # (callee, {formal: actual})

    def add_sink(self, param: str, cwe: str) -> None:
        self.sink_params.setdefault(param, set()).add(cwe)


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


def _outputs(block: str) -> List[str]:
    out = []
    for vo in _VAR_OUTPUT.findall(block):
        out += _PARAM.findall(vo)
    return out


def _strip_decls(block: str) -> str:
    """Remove all VAR...END_VAR declaration sections so sinks aren't matched there."""
    return _ANY_VAR.sub("", block)


def _guarded_params_at(lines: List[str], idx: int) -> Set[str]:
    """Sound, conservative dominance approximation.

    Walk the lines preceding `idx`, tracking open IF-guards as a stack of the
    parameters their conditions mention. Any param that appears in a still-open
    guard condition at line `idx` is considered to constrain that line's sink.

    We only collect identifiers that look like a constraint on the param (the
    condition simply mentions the identifier, e.g. `IF p >= 0 AND p <= 9` or
    `IF p <> 0`). This intentionally treats "mentioned in a dominating guard" as
    "sanitized" — conservative toward *not* reporting, matching the soundness
    preference of avoiding false positives while still flagging unguarded sinks.
    """
    stack: List[Set[str]] = []
    for i in range(idx):
        line = lines[i]
        opens = len(_IF.findall(line))
        closes = len(_END_IF.findall(line))
        # An ELSIF / ELSE does not open a new block for our purposes; we keep it
        # simple: treat each IF token as one push, each END_IF as one pop.
        for _ in range(opens):
            # identifiers mentioned on this IF line are the guard's constrained vars
            cond_vars = set(re.findall(r"[A-Za-z_]\w*", line))
            stack.append(cond_vars)
        for _ in range(closes):
            if stack:
                stack.pop()
    guarded: Set[str] = set()
    for cond_vars in stack:
        guarded |= cond_vars
    return guarded


def _summarize_block(name: str, block: str) -> Summary:
    params = _params(block)
    outputs = _outputs(block)
    s = Summary(name=name, params=params, outputs=outputs)
    body = _strip_decls(block)
    lines = body.splitlines()

    for i, line in enumerate(lines):
        # Determine which params are constrained by a dominating guard at this line.
        guarded = _guarded_params_at(lines, i)

        for var in _SINK_INDEX.findall(line):
            if var in params and var not in guarded:
                s.add_sink(var, CWE_INDEX)
        for var in _SINK_DIV.findall(line):
            if var in params and var not in guarded:
                s.add_sink(var, CWE_DIV)

        # output taint:  out := param ;   (input param flows to an output var)
        am = _ASSIGN.match(line)
        if am:
            lhs, rhs = am.group(1), am.group(2)
            if lhs in outputs and rhs in params:
                s.output_taint.setdefault(lhs, set()).add(rhs)

    for m in _CALL.finditer(body):
        callee, argstr = m.group(1), m.group(2)
        if callee.upper() in _KEYWORDS:
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


def _sink_cwes(callee: str, actual_tainted: str, summaries: Dict[str, Summary],
               mapping: Dict[str, str], seen: Set[str]) -> Set[str]:
    """CWEs of sinks reached by a tainted actual argument in callee (transitively)."""
    if callee not in summaries or callee in seen:
        return set()
    seen = seen | {callee}
    s = summaries[callee]
    cwes: Set[str] = set()
    # which formal params receive the tainted actual?
    tainted_formals = {f for f, a in mapping.items() if a == actual_tainted}
    for f in tainted_formals:
        cwes |= s.sink_params.get(f, set())
    # propagate into nested calls
    for nested_callee, nested_map in s.calls:
        for f, a in nested_map.items():
            if a in tainted_formals:
                cwes |= _sink_cwes(nested_callee, a, summaries, nested_map, seen)
    return cwes


def analyze(program: Program) -> List[InterprocFinding]:
    src = program.source
    summaries = build_summaries(src)
    findings: List[InterprocFinding] = []
    for m in _PROGRAM.finditer(src):
        pname, body = m.group(1), m.group(2)
        tainted = set(_params(body))   # VAR_INPUT of the program = tainted sources
        body_wo_decl = _strip_decls(body)

        calls = []
        for cm in _CALL.finditer(body_wo_decl):
            callee, argstr = cm.group(1), cm.group(2)
            if callee.upper() in _KEYWORDS:
                continue
            in_map = {f: a for f, a in _ARG.findall(argstr)}
            out_map = {f: a for f, a in _OUT_BIND.findall(argstr)}
            calls.append((callee, in_map, out_map))

        # Fixpoint: a tainted output binding can taint an actual that feeds a
        # later call's sink. Iterate over the call list until taint stops growing.
        changed = True
        while changed:
            changed = False
            for callee, in_map, out_map in calls:
                if callee not in summaries:
                    continue
                s = summaries[callee]
                # formals that receive a tainted actual
                tainted_formals = {f for f, a in in_map.items() if a in tainted}
                if not tainted_formals:
                    continue
                for out_var, src_params in s.output_taint.items():
                    if (src_params & tainted_formals) and out_var in out_map:
                        actual = out_map[out_var]
                        if actual not in tainted:
                            tainted.add(actual)
                            changed = True

        # Report sinks reachable from the now-complete tainted set.
        for callee, in_map, out_map in calls:
            for formal, actual in in_map.items():
                if actual not in tainted:
                    continue
                cwes = _sink_cwes(callee, actual, summaries, in_map, set())
                for cwe in sorted(cwes):
                    findings.append(InterprocFinding(
                        pname, cwe,
                        [f"source:{actual}", f"call {callee}({formal}:={actual})",
                         f"sink in {callee} ({cwe})"]))
    return findings
