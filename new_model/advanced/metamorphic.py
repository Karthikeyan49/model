"""Metamorphic robustness testing — does the verdict survive semantics-preserving
edits?

A reliable detector must give the SAME finding when code is rewritten in a way that
changes nothing about its behaviour. If renaming a variable or inserting a comment
flips the verdict, the model is brittle and its findings can't be trusted. This is
a metamorphic relation: transform(input) preserves the expected output.

Transformations (all behaviour-preserving for IEC 61131-3 ST):
  - rename a non-keyword identifier consistently,
  - insert a comment / blank line,
  - reorder independent VAR declarations,
  - add a harmless `(* note *)` block comment.

We run the detector on the original and each variant and measure a STABILITY score
= fraction of variants whose finding set matches the original. Low stability flags
brittle detections (a reliability signal, and a great hard-example source).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Set

from schema import Finding, Program

# A detector: source -> set of (line-ish key, cwe). We key on CWE only for the
# stability check, because line numbers legitimately shift under edits.
Detector = Callable[[Program], List[Finding]]

_KEYWORDS = {"PROGRAM", "END_PROGRAM", "VAR", "VAR_INPUT", "END_VAR", "IF", "THEN",
             "ELSE", "END_IF", "INT", "REAL", "BOOL", "ARRAY", "OF", "TRUE", "FALSE",
             "AND", "OR", "NOT", "MOD", "RETURN", "WHILE", "DO", "FOR", "TO"}


def _rename_identifier(src: str, seed: int) -> str:
    idents = [m.group(0) for m in re.finditer(r"[A-Za-z_]\w*", src)
              if m.group(0).upper() not in _KEYWORDS]
    if not idents:
        return src
    target = idents[seed % len(idents)]
    new = f"{target}_r"
    return re.sub(rf"\b{re.escape(target)}\b", new, src)


def _insert_comment(src: str, seed: int) -> str:
    lines = src.splitlines()
    if not lines:
        return src
    at = seed % len(lines)
    lines.insert(at, "(* metamorphic: behaviour-preserving note *)")
    return "\n".join(lines)


def _blank_lines(src: str, seed: int) -> str:
    return src.replace("\n", "\n\n", 1) if seed % 2 else "\n" + src


TRANSFORMS = [_rename_identifier, _insert_comment, _blank_lines]


@dataclass
class RobustnessResult:
    pid: str
    stable: bool
    stability: float          # fraction of variants matching the original
    original_cwes: Set[str]
    variant_cwes: List[Set[str]]


def _cwe_set(findings: List[Finding]) -> Set[str]:
    return {f.cwe for f in findings}


def assess(program: Program, detector: Detector, n_variants: int = 3) -> RobustnessResult:
    base = _cwe_set(detector(program))
    matches = 0
    variant_sets: List[Set[str]] = []
    for i in range(n_variants):
        t = TRANSFORMS[i % len(TRANSFORMS)]
        mutated = Program(pid=f"{program.pid}~v{i}", path=program.path,
                          source=t(program.source, i), labels=program.labels)
        vs = _cwe_set(detector(mutated))
        variant_sets.append(vs)
        if vs == base:
            matches += 1
    stability = matches / n_variants if n_variants else 1.0
    return RobustnessResult(program.pid, stability == 1.0, round(stability, 3),
                            base, variant_sets)


def assess_corpus(programs: List[Program], detector: Detector,
                  n_variants: int = 3) -> List[RobustnessResult]:
    return [assess(p, detector, n_variants) for p in programs]
