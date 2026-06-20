"""Variant analysis — from one confirmed bug, mechanically find ALL its clones.

When a real vulnerability is confirmed (or a CVE drops), the highest-leverage move
is finding every *structurally similar* instance across the whole codebase before
an attacker does. A frontier LLM can't reliably enumerate this over a large repo —
it has no persistent index and forgets between calls. A specialist extracts a
*structural signature* from the seed and queries every program for matches.

Signature = a normalised AST-ish skeleton of the vulnerable statement:
  - operation kind (array-index-write, array-index-read, division, ...),
  - variable roles abstracted to placeholders (so `a[i+1]` ≡ `buf[idx+2]`),
  - whether a sanitising guard dominates the statement,
  - (optionally) a constant-offset abstraction.

Statement kinds recognised:
  - index-write  (CWE-787, out-of-bounds write):  `a[i+1] := x;`
  - index-read   (CWE-125, out-of-bounds read):   `x := a[i+1];`
  - division     (CWE-369, divide-by-zero):       `r := x / y;`

This is structural, not textual: renamed variables and different constants still
match; an added bounds-guard does NOT (it's a fixed variant, correctly excluded).

Abstraction levels (Signature.level) — how loosely two statements may match:
  - "kind-guard" (default): same operation kind + guard status. Preserves the
    original behaviour; `a[i]` and `a[i+1]` are treated as the same variant.
  - "offset": stricter — additionally requires the same offset presence/sign
    (`a[i+1]` no longer matches `a[i]`), to separate exact-offset clone families
    during fine-grained variant triage.

Caveat: this is a lightweight line-local regex skeleton, not a full parser; it
does not resolve guards across procedures or model multi-line guard scopes. It
is deliberately conservative — meant to surface candidate clones for human/
symbolic follow-up, not to prove (un)safety.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from schema import Program

_INDEX_WRITE = re.compile(r"([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*([+\-]\s*\d+)?\s*\]\s*:=")
# array-index READ: an array access appearing on the RHS of an assignment
# (i.e. after ":=" anywhere in the statement). CWE-125 out-of-bounds read.
_INDEX_READ = re.compile(r":=[^;]*?([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*([+\-]\s*\d+)?\s*\]")
_DIV = re.compile(r":=\s*[^;]*?/\s*([A-Za-z_]\w*|\d+)")
_GUARD_CMP = re.compile(r"\bIF\b[^;]*?\b([A-Za-z_]\w*)\b\s*(<=|>=|<>|<|>)", re.IGNORECASE)


def _offset_token(raw: Optional[str]) -> str:
    """Normalise a captured constant offset to a sign token for the strict
    abstraction: "" (no offset), "+" (positive), or "-" (negative)."""
    if not raw:
        return ""
    return "-" if raw.strip().startswith("-") else "+"


@dataclass
class Signature:
    kind: str                  # "index-write" | "index-read" | "division"
    guarded_var: bool          # is the index/divisor var constrained by a guard?
    cwe: str
    offset: str = ""           # normalised offset token: "", "+", or "-"
    level: str = "kind-guard"  # "kind-guard" (default) | "offset" (stricter)

    def key(self) -> str:
        return f"{self.kind}|guarded={self.guarded_var}|{self.cwe}"

    def matches(self, other: "Signature") -> bool:
        """Whether `other` (a candidate statement's signature) matches this seed.

        Always requires same kind + CWE. The stricter "offset" level (taken from
        the SEED signature) additionally requires the same offset sign/presence.
        Guard status is handled separately by hunt()."""
        if self.kind != other.kind or self.cwe != other.cwe:
            return False
        if self.level == "offset" and self.offset != other.offset:
            return False
        return True


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
        mi = _INDEX_WRITE.search(line)
        if mi:
            idx_var = mi.group(2)
            out.append(Variant(program.pid, i, line.strip(),
                               Signature("index-write", idx_var in guarded, "CWE-787",
                                         offset=_offset_token(mi.group(3)))))
        else:
            # only treat as a READ if it isn't an index-write (avoids matching
            # the LHS array of `a[i] := b[j];` as a read of `a`)
            mr = _INDEX_READ.search(line)
            if mr:
                idx_var = mr.group(2)
                out.append(Variant(program.pid, i, line.strip(),
                                   Signature("index-read", idx_var in guarded, "CWE-125",
                                             offset=_offset_token(mr.group(3)))))
        md = _DIV.search(line)
        if md:
            dv = md.group(1)
            is_var = not dv.isdigit()
            out.append(Variant(program.pid, i, line.strip(),
                               Signature("division", (dv in guarded) if is_var else True,
                                         "CWE-369")))
    return out


def seed_signature(seed_program: Program, line: int,
                   level: str = "kind-guard") -> Optional[Signature]:
    """Extract the structural signature of the statement at `line`.

    `level` selects the abstraction strictness for later hunt() matching:
      - "kind-guard" (default): match on kind+CWE+guard (original behaviour).
      - "offset": also require the same constant-offset sign/presence."""
    for v in _signatures_in(seed_program):
        if v.line == line:
            v.signature.level = level
            return v.signature
    return None


def hunt(seed_signature: Signature, corpus: List[Program],
         require_unguarded: bool = True) -> List[Variant]:
    """Find all statements across `corpus` matching the seed's structure.
    By default only returns UNGUARDED matches (the still-vulnerable variants);
    guarded matches are treated as already-fixed and excluded."""
    hits: List[Variant] = []
    for prog in corpus:
        for v in _signatures_in(prog):
            if not seed_signature.matches(v.signature):
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
