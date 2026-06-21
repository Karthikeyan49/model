"""Variant analysis — from one confirmed bug, mechanically find ALL its clones.

When a real vulnerability is confirmed (or a CVE drops), the highest-leverage move
is finding every *structurally similar* instance across the whole codebase before
an attacker does. A frontier LLM can't reliably enumerate this over a large repo —
it has no persistent index and forgets between calls. A specialist extracts a
*structural signature* from the seed and queries every program for matches.

Signature = a normalised AST-ish skeleton of the vulnerable statement:
  - operation kind (array-index-write, array-index-read, division, ...),
  - variable roles abstracted to placeholders (so `a[i+1]` ≡ `buf[idx+2]`),
  - whether a sanitising guard dominates the statement.

This is structural, not textual: the signature deliberately ABSTRACTS AWAY
variable NAMES and CONSTANT offsets (so `a[i+1]` ≡ `buf[idx+3]`) while PRESERVING
the operation kind and guardedness. Two statements match iff they share the same
`kind`, the same `cwe`, AND the same guarded/unguarded status — so a renamed,
re-constanted clone matches, an added bounds-guard does NOT (a fixed variant,
correctly excluded), and a *different* operation never cross-matches
(index-write, index-read, and division are kept strictly distinct).

Operation kinds handled:
  - "index-write" (CWE-787): indexed write target on the LEFT of `:=`,
    e.g. `arr[idx] := ...`  (out-of-bounds write).
  - "index-read"  (CWE-125): indexed read on the RIGHT of `:=`,
    e.g. `x := arr[idx + c];`  (out-of-bounds read).
  - "division"    (CWE-369): division by a (possibly tainted) divisor.

A single statement may emit several signatures: `a[i] := b[j];` yields an
index-write for `a[i]` AND an index-read for `b[j]`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from schema import Program

_INDEX_WRITE = re.compile(r"([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*([+\-]\s*\d+)?\s*\]\s*:=")
# An indexed read: an `arr[idx (+/- c)]` occurring AFTER a `:=` (r-value side).
_INDEX_READ = re.compile(r"([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*([+\-]\s*\d+)?\s*\]")
# ARRAY declarations also contain `name[...]`; never treat them as accesses.
_ARRAY_DECL = re.compile(r"\bARRAY\b", re.IGNORECASE)
_DIV = re.compile(r":=\s*[^;]*?/\s*([A-Za-z_]\w*|\d+)")
_GUARD_CMP = re.compile(r"\bIF\b[^;]*?\b([A-Za-z_]\w*)\b\s*(<=|>=|<>|<|>)", re.IGNORECASE)


@dataclass
class Signature:
    kind: str                  # "index-write" | "index-read" | "division"
    guarded_var: bool          # is the index/divisor var constrained by a guard?
    cwe: str

    def key(self) -> str:
        return f"{self.kind}|guarded={self.guarded_var}|{self.cwe}"


@dataclass
class Variant:
    pid: str
    line: int
    snippet: str
    signature: Signature


def _guarded_vars(source: str) -> set:
    return {m.group(1) for m in _GUARD_CMP.finditer(source)}


def _signatures_in(program: Program) -> List[Variant]:
    guarded = _guarded_vars(program.source)
    out: List[Variant] = []
    for i, line in enumerate(program.source.splitlines(), 1):
        is_decl = bool(_ARRAY_DECL.search(line))  # ARRAY[..] declarations aren't accesses
        mi = _INDEX_WRITE.search(line)
        if mi and not is_decl:
            idx_var = mi.group(2)
            out.append(Variant(program.pid, i, line.strip(),
                               Signature("index-write", idx_var in guarded, "CWE-787")))
        # Index READ (CWE-125): only on the r-value side, i.e. after the first `:=`,
        # so the write target on the left is never double-counted as a read.
        if not is_decl and ":=" in line:
            rhs = line.split(":=", 1)[1]
            mr = _INDEX_READ.search(rhs)
            if mr:
                ridx_var = mr.group(2)
                out.append(Variant(program.pid, i, line.strip(),
                                   Signature("index-read", ridx_var in guarded, "CWE-125")))
        md = _DIV.search(line)
        if md:
            dv = md.group(1)
            is_var = not dv.isdigit()
            out.append(Variant(program.pid, i, line.strip(),
                               Signature("division", (dv in guarded) if is_var else True,
                                         "CWE-369")))
    return out


def seed_signature(seed_program: Program, line: int) -> Optional[Signature]:
    for v in _signatures_in(seed_program):
        if v.line == line:
            return v.signature
    return None


def hunt(seed_signature: Signature, corpus: List[Program],
         require_unguarded: bool = True) -> List[Variant]:
    """Find all statements across `corpus` matching the seed's structure.

    Matching is exact on `kind` and `cwe`, so the three operation kinds
    (index-write / index-read / division) never cross-match — only clones of
    the *same* operation count. Variable names and constant offsets are ignored
    (they're abstracted out of the signature). By default only UNGUARDED matches
    are returned (the still-vulnerable variants); a guarded match is treated as
    an already-fixed variant and excluded."""
    hits: List[Variant] = []
    for prog in corpus:
        for v in _signatures_in(prog):
            same = (v.signature.kind == seed_signature.kind
                    and v.signature.cwe == seed_signature.cwe)
            if not same:
                continue
            if require_unguarded and v.signature.guarded_var:
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
