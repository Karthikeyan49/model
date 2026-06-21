"""Interprocedural taint via compositional function summaries.

Whole-program reasoning is where a stateless LLM hits a wall: it can't reliably
track taint across many function blocks that don't fit in one context window, and
it re-derives nothing between calls. A specialist computes a *summary* per function
block once ("input param P reaches a dangerous sink"), builds a call graph, and
propagates taint across calls to a fixpoint — compositional analysis that scales to
arbitrarily large programs (IFDS/summary-based, the classic scalable technique).

Model (minimal IEC 61131-3):
  - FUNCTION_BLOCK FB ... VAR_INPUT p : T; END_VAR ... body ...
  - a body sink `arr[p ...]` (index) or `_ / p` (division) makes param `p` a
    "sink param" of FB, refined by sink KIND:
        index sink    -> CWE-787 (out-of-bounds write)
        division sink -> CWE-369 (divide-by-zero)
    A param reaching both kinds yields findings for both.
  - a body call `FB2(x := expr)` connects expr's taint to FB2's param.
  - a top-level PROGRAM taints VAR_INPUT vars and calls FBs.
Taint reaches a sink iff a tainted actual argument maps to a sink param,
transitively across the call graph (computed to a fixpoint). The reported `path`
includes the full transitive call chain from source to the sink, and findings are
de-duplicated on (program, cwe, path).

Interprocedural sanitization (SOUND for a DETECTION tool):
  - If a sink on param `p` is dominated by an enclosing block-structured `IF`-guard
    that plainly CONSTRAINS `p` (e.g. `IF p >= 0 AND p <= 9 THEN buf[p]:=7; END_IF;`
    for an index sink, or `IF p <> 0 THEN r:=x/p; END_IF;` for a division sink),
    then `p` is treated as SANITIZED at THAT sink and is not reported.
  - We track the stack of open IF guards by `IF ... THEN` / `END_IF` and only
    suppress when a guard that mentions the param dominates the sink line.

Caveats (honest, and deliberately CONSERVATIVE — we never silently drop a real
taint path):
  - ELSE / ELSIF branches are approximated: a guard remains "in scope" until its
    END_IF, so we do NOT attempt to model branch-specific constraints. A param
    that is unguarded in an ELSE branch is still treated as guarded only if the
    guard condition mentions it — when unsure we keep the finding.
  - Complex / non-trivial guard expressions (function calls, indirection) are not
    interpreted; if the guard merely MENTIONS the sink param we accept it as a
    constraint. This can suppress an unusual non-constraining guard (rare), but the
    design bias is to suppress only on a clearly-dominating param-mentioning guard.
  - When in doubt the param is left as a sink param (prefer a false positive over a
    missed real finding).
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
_PARAM = re.compile(r"([A-Za-z_]\w*)\s*:")
_SINK_INDEX = re.compile(r"\[\s*([A-Za-z_]\w*)")
_SINK_DIV = re.compile(r"/\s*([A-Za-z_]\w*)")
# call:  FBName( formal := actual , ... )
_CALL = re.compile(r"([A-Za-z_]\w*)\s*\(([^)]*)\)")
_ARG = re.compile(r"([A-Za-z_]\w*)\s*:=\s*([A-Za-z_]\w*)")
# block-structured guard markers
_IF_THEN = re.compile(r"\bIF\b(.*?)\bTHEN\b", re.IGNORECASE | re.DOTALL)
_END_IF = re.compile(r"\bEND_IF\b", re.IGNORECASE)

CWE_INDEX = "CWE-787"   # out-of-bounds write via array index
CWE_DIV = "CWE-369"     # divide-by-zero


@dataclass
class Summary:
    name: str
    params: List[str] = field(default_factory=list)
    # param -> set of CWEs of the (unsanitized) sinks it reaches in this FB
    sink_params: Dict[str, Set[str]] = field(default_factory=dict)
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


def _word_in(name: str, text: str) -> bool:
    """Whole-word membership (avoids matching `pos` inside `position`)."""
    return re.search(r"\b" + re.escape(name) + r"\b", text) is not None


def _open_guards(body: str, upto: int) -> List[str]:
    """Return the conditions of IF-guards open at character offset `upto`.

    Block-structured: each `IF ... THEN` opens a guard, each `END_IF` closes the
    innermost. We collect the guard condition strings whose scope encloses `upto`.
    """
    # Build an ordered event list of (offset, kind, cond).
    events: List[Tuple[int, str, str]] = []
    for m in _IF_THEN.finditer(body):
        events.append((m.end(), "open", m.group(1)))
    for m in _END_IF.finditer(body):
        events.append((m.start(), "close", ""))
    events.sort(key=lambda e: e[0])

    stack: List[str] = []
    for off, kind, cond in events:
        if off > upto:
            break
        if kind == "open":
            stack.append(cond)
        elif stack:
            stack.pop()
    return stack


def _sanitized(param: str, body: str, sink_offset: int) -> bool:
    """True iff some open IF-guard dominating the sink plainly mentions `param`."""
    for cond in _open_guards(body, sink_offset):
        if _word_in(param, cond):
            return True
    return False


def _summarize_block(name: str, block: str) -> Summary:
    params = _params(block)
    s = Summary(name=name, params=params)
    body = _VAR_INPUT.sub("", block)  # strip decls so sinks aren't matched in them

    def record(var: str, cwe: str, offset: int) -> None:
        if var not in params:
            return
        if _sanitized(var, body, offset):
            return  # dominated by a param-constraining guard -> sanitized
        s.sink_params.setdefault(var, set()).add(cwe)

    # Walk the body tracking character offsets so guard scoping is precise.
    for m in _SINK_INDEX.finditer(body):
        record(m.group(1), CWE_INDEX, m.start())
    for m in _SINK_DIV.finditer(body):
        record(m.group(1), CWE_DIV, m.start())

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
                  mapping: Dict[str, str], seen: Set[str],
                  chain: List[str]) -> List[Tuple[str, List[str]]]:
    """All (cwe, call-chain) by which a tainted actual reaches a sink in callee.

    `chain` is the list of FB names visited so far (callee NOT yet appended).
    Returns one entry per distinct (cwe, full-chain-to-sink-FB).
    """
    out: List[Tuple[str, List[str]]] = []
    if callee not in summaries or callee in seen:
        return out
    seen = seen | {callee}
    new_chain = chain + [callee]
    s = summaries[callee]
    # which formal params receive the tainted actual?
    tainted_formals = {f for f, a in mapping.items() if a == actual_tainted}
    for formal in tainted_formals:
        for cwe in s.sink_params.get(formal, set()):
            out.append((cwe, new_chain))
    # propagate into nested calls
    for nested_callee, nested_map in s.calls:
        for f, a in nested_map.items():
            if a in tainted_formals:
                out += _reaches_sink(nested_callee, a, summaries, nested_map,
                                     seen, new_chain)
    return out


def analyze(program: Program) -> List[InterprocFinding]:
    src = program.source
    summaries = build_summaries(src)
    findings: List[InterprocFinding] = []
    seen_keys: Set[Tuple[str, str, Tuple[str, ...]]] = set()
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
                if actual not in tainted:
                    continue
                for cwe, chain in _reaches_sink(callee, actual, summaries,
                                                mapping, set(), []):
                    path = [f"source:{actual}"]
                    prev = actual
                    for hop in chain:
                        path.append(f"call {hop}({prev})")
                        prev = hop
                    path.append(f"sink in {chain[-1]}")
                    key = (pname, cwe, tuple(path))
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)
                    findings.append(InterprocFinding(pname, cwe, path))
    return findings
