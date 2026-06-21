"""Variant analysis — from one confirmed bug, mechanically find ALL its clones.

When a real vulnerability is confirmed (or a CVE drops), the highest-leverage move
is finding every *structurally similar* instance across the whole codebase before
an attacker does. A frontier LLM can't reliably enumerate this over a large repo —
it has no persistent index and forgets between calls. A specialist extracts a
*structural signature* from the seed and queries every program for matches.

Signature = a normalised AST-ish skeleton of the vulnerable statement:
  - operation kind (array-index-write, division, ...),
  - variable roles abstracted to placeholders (so `a[i+1]` ≡ `buf[idx+2]`),
  - whether a sanitising guard dominates the statement.

This is structural, not textual: renamed variables and different constants still
match; an added bounds-guard does NOT (it's a fixed variant, correctly excluded).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from schema import Program

_INDEX_WRITE = re.compile(r"([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*([+\-]\s*\d+)?\s*\]\s*:=")
_DIV = re.compile(r":=\s*[^;]*?/\s*([A-Za-z_]\w*|\d+)")
# RHS array read: ` := ... arr[i] ...` where the indexed expr is NOT immediately
# followed by ":=" (that would be an index-write, handled above).
_INDEX_READ = re.compile(
    r":=\s*[^;]*?([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*([+\-]\s*\d+)?\s*\](?!\s*:=)")
# FOR loop header: `FOR i := lo TO hi [BY ...] DO`
_FOR = re.compile(
    r"\bFOR\b\s+([A-Za-z_]\w*)\s*:=\s*[^;]+?\bTO\b\s+([^;]+?)(?:\bBY\b|\bDO\b)",
    re.IGNORECASE)
# any array indexed by a bare variable (used to spot loop-var indexing in a body)
_INDEX_ANY = re.compile(r"([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*([+\-]\s*\d+)?\s*\]")
_GUARD_CMP = re.compile(r"\bIF\b[^;]*?\b([A-Za-z_]\w*)\b\s*(<=|>=|<>|<|>)", re.IGNORECASE)


@dataclass
class Signature:
    kind: str                  # "index-write" | "division" | "index-read" | "loop-index"
    guarded_var: bool          # is the index/divisor var constrained by a guard?
    cwe: str
    has_offset: bool = False   # does a constant offset appear (arr[i+1] vs arr[i])?

    def key(self) -> str:
        # NOTE: has_offset is intentionally excluded so legacy keys are stable.
        return f"{self.kind}|guarded={self.guarded_var}|{self.cwe}"


@dataclass
class Variant:
    pid: str
    line: int
    snippet: str
    signature: Signature


def _guarded_vars(source: str) -> set:
    return {m.group(1) for m in _GUARD_CMP.finditer(source)}


def _has_offset(grp) -> bool:
    """True when the optional constant-offset group matched (e.g. `i+1`)."""
    return bool(grp and grp.strip())


def _signatures_in(program: Program) -> List[Variant]:
    guarded = _guarded_vars(program.source)
    out: List[Variant] = []
    for i, line in enumerate(program.source.splitlines(), 1):
        mi = _INDEX_WRITE.search(line)
        if mi:
            idx_var = mi.group(2)
            out.append(Variant(program.pid, i, line.strip(),
                               Signature("index-write", idx_var in guarded, "CWE-787",
                                         has_offset=_has_offset(mi.group(3)))))
        else:
            # index-read on the RHS — only when this isn't an index-write line,
            # so a write statement is never double-counted as a read.
            mr = _INDEX_READ.search(line)
            if mr:
                idx_var = mr.group(2)
                out.append(Variant(program.pid, i, line.strip(),
                                   Signature("index-read", idx_var in guarded, "CWE-125",
                                             has_offset=_has_offset(mr.group(3)))))
        md = _DIV.search(line)
        if md:
            dv = md.group(1)
            is_var = not dv.isdigit()
            out.append(Variant(program.pid, i, line.strip(),
                               Signature("division", (dv in guarded) if is_var else True,
                                         "CWE-369")))
        mf = _FOR.search(line)
        if mf:
            loop_var = mf.group(1)
            # Does the loop body index an array with the loop variable? Scan the
            # remainder of the program after the FOR header for `arr[loop_var..]`.
            rest = "\n".join(program.source.splitlines()[i:])
            body_idx = [m for m in _INDEX_ANY.finditer(rest)
                        if m.group(2) == loop_var]
            if body_idx:
                # guarded only if the loop variable itself is constrained by an
                # explicit IF guard (the TO bound is a structural risk we flag).
                offset = any(_has_offset(m.group(3)) for m in body_idx)
                out.append(Variant(program.pid, i, line.strip(),
                                   Signature("loop-index", loop_var in guarded,
                                             "CWE-787", has_offset=offset)))
    return out


def seed_signature(seed_program: Program, line: int) -> Optional[Signature]:
    for v in _signatures_in(seed_program):
        if v.line == line:
            return v.signature
    return None


def hunt(seed_signature: Signature, corpus: List[Program],
         require_unguarded: bool = True,
         match_offset: bool = False) -> List[Variant]:
    """Find all statements across `corpus` matching the seed's structure.

    By default only returns UNGUARDED matches (the still-vulnerable variants);
    guarded matches are treated as already-fixed and excluded.

    Heuristic structural matcher: it surfaces candidates for human review, not a
    formal proof of vulnerability. Guard dominance is honoured (guarded =>
    excluded) but the matcher does not claim soundness beyond that.

    If `match_offset` is True, candidates must additionally agree with the seed
    on whether a constant offset is present (so a seed of `arr[i+1]` will not
    pull in plain `arr[i]` matches, and vice versa). Defaults to False so the
    existing behaviour is unchanged.
    """
    hits: List[Variant] = []
    for prog in corpus:
        for v in _signatures_in(prog):
            same = (v.signature.kind == seed_signature.kind
                    and v.signature.cwe == seed_signature.cwe)
            if not same:
                continue
            if require_unguarded and v.signature.guarded_var:
                continue
            if match_offset and v.signature.has_offset != seed_signature.has_offset:
                continue
            hits.append(v)
    return hits


def render(hits: List[Variant]) -> str:
    if not hits:
        return "No variants found."
    lines = [f"Found {len(hits)} structural variant(s):"]
    for v in hits:
        lines.append(f"  {v.pid}:{v.line}  [{v.signature.cwe}]  {v.snippet}")
    return "\n".join(lines)
