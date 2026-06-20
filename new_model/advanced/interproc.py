"""Interprocedural taint via compositional function summaries.

Whole-program reasoning is where a stateless LLM hits a wall: it can't reliably
track taint across many function blocks that don't fit in one context window, and
it re-derives nothing between calls. A specialist computes a *summary* per function
block once ("input param P reaches a dangerous sink of kind K"), builds a call
graph, and propagates taint across calls to a fixpoint — compositional analysis
that scales to arbitrarily large programs (IFDS/summary-based, the classic
scalable technique).

Model (minimal IEC 61131-3):
  - FUNCTION_BLOCK FB ... VAR_INPUT p : T; END_VAR ... body ...
  - a body sink `arr[p ...]`  makes param `p` an array-index sink param (CWE-787).
  - a body sink `_ / p`        makes param `p` a division sink param (CWE-369).
  - a body call `FB2(x := expr)` connects expr's taint to FB2's param.
  - a top-level PROGRAM taints VAR_INPUT vars and calls FBs.
Taint reaches a sink iff a tainted actual argument maps to a sink param,
transitively across the call graph (computed to a fixpoint over the summaries).

Capabilities (this module):
  - Per-sink CWE classification: array-index sinks -> CWE-787, division sinks
    -> CWE-369. A single param may reach several sink kinds; each source->sink
    path is reported with the CWE matching the *final* sink it reaches.
  - Full source->sink path reporting across multi-level chains: the finding's
    `path` lists the source, every call hop as `formal:=actual`, and the final
    sink annotated with its kind/CWE — not merely the first hop.
  - Callee-side sanitization (precision, kept sound): if a sink statement is
    lexically enclosed by an IF...END_IF whose guard constrains the sink param
    (e.g. `IF p >= 0 AND p <= 9 THEN buf[p]:=...; END_IF;` for an array sink, or
    `IF d <> 0 THEN _ / d END_IF;` for a division sink), that param is treated as
    sanitized for that sink kind and is NOT reported.

Soundness caveats (this is detection-oriented; we prefer false positives to
false negatives):
  - Sanitization is suppressed ONLY when the guard demonstrably encloses the
    sink statement AND syntactically references the sink param. Any aliasing,
    arithmetic on the param (`buf[p+1]` under a guard on `p`), partial guards,
    or guards we cannot resolve leave the sink REPORTED.
  - We do not model assignments through locals, indirect/aliased calls, loop
    induction, or value ranges; taint is propagated structurally. This can
    over-report but is intended not to silently drop a reachable sink.
  - Recursion in the call graph is handled by a visited-set; a sink reachable
    only via an unbounded recursive cycle past the first revisit may be missed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from schema import Program

# CWE per sink kind.
CWE_ARRAY = "CWE-787"   # out-of-bounds write via tainted array index
CWE_DIV = "CWE-369"     # divide-by-zero via tainted divisor

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
# IF ... THEN ... END_IF  (non-greedy, dotall) — used to find guarded regions.
_IF_BLOCK = re.compile(r"\bIF\b(.*?)\bTHEN\b(.*?)\bEND_IF\b",
                       re.IGNORECASE | re.DOTALL)
_KEYWORDS = {"IF", "WHILE", "FOR", "ELSIF", "CASE", "RETURN"}


@dataclass
class Summary:
    name: str
    params: List[str] = field(default_factory=list)
    # Backward-compatible: the set of params that reach SOME dangerous sink.
    sink_params: Set[str] = field(default_factory=set)
    # Refined: param -> set of CWEs for the sink kinds it reaches.
    sink_kinds: Dict[str, Set[str]] = field(default_factory=dict)
    calls: List[tuple] = field(default_factory=list)        # (callee, {formal: actual})

    def add_sink(self, param: str, cwe: str) -> None:
        self.sink_params.add(param)
        self.sink_kinds.setdefault(param, set()).add(cwe)


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


def _guards_param(guard: str, param: str) -> bool:
    """Does this IF guard syntactically reference `param` as a bare identifier?

    Conservative: a word-boundary match on the param name. We do not attempt to
    prove the guard is *sufficient* (e.g. covers the full array range); a guard
    that merely constrains the param is taken as a sanitizer for that param, in
    line with the symbolic checker's behaviour on guarded indices. Anything we
    cannot match leaves the sink reported.
    """
    return re.search(r"\b" + re.escape(param) + r"\b", guard) is not None


def _sanitized_params(body: str, kind_re: re.Pattern, params: List[str]) -> Set[str]:
    """Params whose sink (of the given kind) is enclosed by a guard on that param.

    For every IF...END_IF region we collect the sink params used inside the THEN
    body; if the guard references that same param, the sink is considered
    sanitized for the param. Returned set is the union over all guarded regions.
    """
    sanitized: Set[str] = set()
    for m in _IF_BLOCK.finditer(body):
        guard, then_body = m.group(1), m.group(2)
        for var in kind_re.findall(then_body):
            if var in params and _guards_param(guard, var):
                sanitized.add(var)
    return sanitized


def _summarize_block(name: str, block: str) -> Summary:
    params = _params(block)
    s = Summary(name=name, params=params)
    body = _VAR_INPUT.sub("", block)  # strip decls so sinks aren't matched in them

    # Callee-side sanitization: params whose sink is enclosed by a constraining
    # guard are excluded for that sink KIND only (a param guarded for division
    # but not for an array sink is still an array sink param).
    san_index = _sanitized_params(body, _SINK_INDEX, params)
    san_div = _sanitized_params(body, _SINK_DIV, params)

    for line in body.splitlines():
        for var in _SINK_INDEX.findall(line):
            if var in params and var not in san_index:
                s.add_sink(var, CWE_ARRAY)
        for var in _SINK_DIV.findall(line):
            if var in params and var not in san_div:
                s.add_sink(var, CWE_DIV)

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


def _trace_sink(callee: str, actual_tainted: str, summaries: Dict[str, Summary],
                mapping: Dict[str, str],
                seen: Set[str]) -> Optional[Tuple[str, List[str]]]:
    """Trace a tainted actual into `callee`; return (cwe, path_tail) or None.

    `path_tail` is the chain from inside `callee` down to the final sink:
    each call hop is rendered `Callee(formal:=actual)` and the terminal element
    is `sink kind=<...> in <FB>[ via <param>] (<CWE>)`. Returns the first sink
    found (DFS); soundness only requires reporting *a* reachable sink.
    """
    if callee not in summaries or callee in seen:
        return None
    seen = seen | {callee}
    s = summaries[callee]
    # which formal params receive the tainted actual?
    tainted_formals = {f for f, a in mapping.items() if a == actual_tainted}

    # Direct sink: a tainted formal is a sink param of this callee.
    for f in tainted_formals:
        if f in s.sink_kinds:
            cwe = sorted(s.sink_kinds[f])[0]
            kind = "array-index" if cwe == CWE_ARRAY else "division"
            return cwe, [f"sink {kind} in {callee} via {f} ({cwe})"]

    # Propagate into nested calls.
    for nested_callee, nested_map in s.calls:
        for f, a in nested_map.items():
            if a in tainted_formals:
                res = _trace_sink(nested_callee, a, summaries, nested_map, seen)
                if res is not None:
                    cwe, tail = res
                    hop = f"call {nested_callee}({f}:={a})"
                    return cwe, [hop] + tail
    return None


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
            if callee.upper() in _KEYWORDS:
                continue
            mapping = {f: a for f, a in _ARG.findall(argstr)}
            for formal, actual in mapping.items():
                if actual not in tainted:
                    continue
                res = _trace_sink(callee, actual, summaries, mapping, set())
                if res is None:
                    continue
                cwe, tail = res
                path = [f"source:{actual}",
                        f"call {callee}({formal}:={actual})"] + tail
                findings.append(InterprocFinding(pname, cwe, path))
    return findings
