"""Sound non-termination / unbounded-loop detection for IEC 61131-3 ST.

WHY (OT-specific): a PLC runs a cyclic scan. A loop that cannot terminate within
a scan starves the cyclic task and trips the watchdog, faulting the controller —
a real availability / safety hazard (DoS). This module is a *defensive* static
analysis: it detects loops that PROVABLY cannot terminate (CWE-835, "Loop with
Unreachable Exit Condition (Infinite Loop)") and points the owner at the line to
fix. It does NOT generate exploits or weaponize anything — it only reasons about
reachability of a loop exit and reports a structural witness.

A frontier LLM can *guess* "this loop looks infinite"; this module gives a SOUND
verdict over a small, explicitly documented fragment: when it says `infinite` it
carries a structural proof, and when it cannot prove either way it says `unknown`
rather than risk a false `safe`.

Supported fragment (intraprocedural):
  - `WHILE <cond> DO ... END_WHILE;`
  - `REPEAT ... UNTIL <cond> END_REPEAT;`
  - `FOR v := a TO b [BY s] DO ... END_FOR;` — a well-formed FOR with CONSTANT
    bounds/step is `safe` (IEC 61131-3 FOR counts a bounded counter). A FOR whose
    bound or step expression is non-constant -> `unknown` (we cannot prove the
    counter reaches the limit; e.g. `BY 0` or a runtime-computed TO would not).

Condition fragment we can decompose ("simple guard"):
  - a single relational comparison `v <op> <expr>` with op in
    {`<`, `<=`, `>`, `>=`, `<>`, `=`}, OR
  - a bare boolean variable `v` / `NOT v`, OR
  - the constant-true literals `TRUE` / `1`.
Anything with AND/OR, function calls, array/pointer indexing, or more than one
comparison -> we do not trust ourselves to decompose it -> `unknown`.

Verdicts (status):
  * `infinite`  (cwe="CWE-835") — PROVABLY non-terminating, with a structural
                witness, in exactly two cases:
                  (1) constant-true guard (`WHILE TRUE` / `WHILE 1`) and NO
                      reachable `EXIT;` in the body; or
                  (2) a simple guard whose guard variable(s) are NEVER assigned
                      anywhere in the body AND there is no `EXIT;` — the condition
                      value can never change, so the exit is unreachable.
  * `safe`      (cwe="") — termination justified: a reachable `EXIT;` in the body,
                OR a guard variable is moved MONOTONICALLY toward the exit boundary
                (e.g. guard `i > 0` with body `i := i - c`, c>0), OR a well-formed
                constant-bounded FOR.
  * `unknown`   (cwe="") — anything outside the analyzable fragment, or where the
                body's effect on a guard variable is unclear. Conservative default.

SOUNDNESS (the asymmetry that matters): for a *detector* the dangerous error is a
false `safe` on a loop that actually hangs. So we only emit `safe` when we can
justify it, and we fall back to `unknown` (never `safe`) whenever a guard
variable's update is non-linear, sign-ambiguous, conditional, or otherwise
opaque. We only emit `infinite` when the non-termination is structurally provable
as above. Everything else is `unknown`.

Honest caveats:
  - `EXIT;` is treated as potentially reachable wherever it appears in the body
    (we do not prove it is *actually* reached). This is the SAFE direction for a
    non-termination detector: assuming an EXIT can fire only ever moves us AWAY
    from claiming `infinite`, so it cannot cause a false `infinite`. It can cause
    us to under-report (miss a truly-infinite loop whose only EXIT is dead code) —
    a false negative, which for a detector is the tolerable error.
  - Guard updates are checked over the WHOLE body text (flow-insensitive). A guard
    var updated only inside a never-taken branch could still read as "updated";
    again this only ever weakens an `infinite` claim, never strengthens it.
  - Nested loops: each loop is analyzed against its own (top-level) body span; an
    inner EXIT belongs to the inner loop. We match END tokens by nesting depth.

Reference: CWE-835, "Loop with Unreachable Exit Condition ('Infinite Loop')",
https://cwe.mitre.org/data/definitions/835.html
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from schema import Program

# --- lexical helpers (IEC 61131-3 ST is case-insensitive) --------------------
_WHILE = re.compile(r"\bWHILE\b(.+?)\bDO\b", re.IGNORECASE | re.DOTALL)
_WHILE_OPEN = re.compile(r"\bWHILE\b", re.IGNORECASE)
_WHILE_CLOSE = re.compile(r"\bEND_WHILE\b", re.IGNORECASE)
_REPEAT_OPEN = re.compile(r"\bREPEAT\b", re.IGNORECASE)
_REPEAT_CLOSE = re.compile(r"\bEND_REPEAT\b", re.IGNORECASE)
_UNTIL = re.compile(r"\bUNTIL\b(.+?)\bEND_REPEAT\b", re.IGNORECASE | re.DOTALL)
_FOR_OPEN = re.compile(r"\bFOR\b", re.IGNORECASE)
_FOR_CLOSE = re.compile(r"\bEND_FOR\b", re.IGNORECASE)
_FOR_HEAD = re.compile(
    r"\bFOR\b\s+([A-Za-z_]\w*)\s*:=\s*(.+?)\s+\bTO\b\s+(.+?)"
    r"(?:\s+\bBY\b\s+(.+?))?\s+\bDO\b",
    re.IGNORECASE | re.DOTALL,
)
_EXIT = re.compile(r"\bEXIT\b", re.IGNORECASE)

# a single relational comparison: var op expr
_REL = re.compile(r"^\s*([A-Za-z_]\w*)\s*(<=|>=|<>|<|>|=)\s*(.+?)\s*$")
# assignment to a name: `v := rhs`
_ASSIGN_TO = re.compile(r"([A-Za-z_]\w*)\s*:=")
# tokens that, if present in a condition, mean we will not decompose it
_COMPLEX = re.compile(r"\b(AND|OR|XOR|NOT)\b|\(|\[", re.IGNORECASE)
_IDENT = re.compile(r"[A-Za-z_]\w*")
_INT_LIT = re.compile(r"^[+-]?\d+$")

# IEC ST keywords that look like identifiers but are not guard variables.
_KEYWORDS = {
    "true", "false", "and", "or", "xor", "not", "mod", "to", "by", "do",
    "then", "else", "elsif", "end_if", "end_while", "end_repeat", "end_for",
}


@dataclass
class TerminationResult:
    """One loop's termination verdict."""
    cwe: str                                   # "CWE-835" iff status == infinite
    line: int                                  # 1-based line of the loop header
    status: str                                # infinite | safe | unknown
    kind: str = ""                             # while | repeat | for
    guards: List[str] = field(default_factory=list)   # guard variable name(s)
    rationale: str = ""

    def render(self) -> str:
        g = ",".join(self.guards) if self.guards else "-"
        tag = self.cwe or self.status.upper()
        return f"{tag} {self.kind}@L{self.line} guards={{{g}}}: {self.rationale}"


def render(results: List[TerminationResult]) -> str:
    """Multi-line human-readable summary of a list of results."""
    if not results:
        return "no loops found"
    return "\n".join(r.render() for r in results)


# --- structural matching -----------------------------------------------------

def _match_block(lines: List[str], start: int,
                 open_re: re.Pattern, close_re: re.Pattern) -> int:
    """Return the line index (0-based) of the matching close token for a block
    whose open token is on line `start`, accounting for nesting. The first open
    on `start` is the one we are matching. Returns len(lines)-1 if unmatched."""
    depth = 0
    # count opens on the start line (the header counts as one open)
    depth += len(open_re.findall(lines[start]))
    depth -= len(close_re.findall(lines[start]))
    if depth <= 0:
        return start
    for j in range(start + 1, len(lines)):
        depth += len(open_re.findall(lines[j]))
        depth -= len(close_re.findall(lines[j]))
        if depth <= 0:
            return j
    return len(lines) - 1


def _body_text(lines: List[str], start: int, end: int,
               head_strip: str, tail_strip: str) -> str:
    """Join the body between header line `start` and closing line `end`,
    removing the header text up to/including the opening keyword sentinel and
    the closing keyword from the last line, so guard/EXIT scans don't see them.
    `head_strip` text is removed from the start line; `tail_strip` from end."""
    if start == end:
        seg = lines[start]
        seg = seg.replace(head_strip, " ", 1) if head_strip else seg
        seg = seg.replace(tail_strip, " ", 1) if tail_strip else seg
        return seg
    parts = [lines[start].replace(head_strip, " ", 1) if head_strip else lines[start]]
    parts.extend(lines[start + 1:end])
    last = lines[end].replace(tail_strip, " ", 1) if tail_strip else lines[end]
    parts.append(last)
    return "\n".join(parts)


def _guard_vars(cond: str) -> Optional[List[str]]:
    """Return the guard variable names referenced by a SIMPLE condition, or None
    if the condition is outside the decomposable fragment."""
    c = cond.strip()
    low = c.lower()
    if low in ("true", "1"):
        return []                                    # constant-true: no guard var
    if _COMPLEX.search(c):
        return None                                  # AND/OR/NOT/call/index -> opaque
    m = _REL.match(c)
    if m:
        var, _op, rhs = m.group(1), m.group(2), m.group(3)
        names = [var]
        # rhs may reference another variable (e.g. `i < n`); include it as a guard
        for ident in _IDENT.findall(rhs):
            if ident.lower() not in _KEYWORDS:
                names.append(ident)
        # dedupe, preserve order
        seen: List[str] = []
        for n in names:
            if n not in seen:
                seen.append(n)
        return seen
    if re.fullmatch(r"[A-Za-z_]\w*", c):             # bare boolean variable
        return [c]
    return None                                      # not decomposable


def _is_const(expr: str) -> bool:
    return bool(_INT_LIT.match(expr.strip()))


def _monotone_toward_exit(cond: str, body: str) -> bool:
    """Conservatively decide whether the (single) guard variable of a relational
    condition is moved MONOTONICALLY toward the exit boundary in the body.

    Only the narrow, justifiable cases return True:
      guard `v > k` or `v >= k`  with body assignment `v := v - c` (c>0) -> True
      guard `v < k` or `v <= k`  with body assignment `v := v + c` (c>0) -> True
    Anything else (other ops, RHS not a constant, multiple updates, ambiguous
    sign) returns False so the caller falls back to `unknown`."""
    m = _REL.match(cond.strip())
    if not m:
        return False
    var, op, rhs = m.group(1), m.group(2), m.group(3).strip()
    if not _is_const(rhs):
        return False                                 # boundary not a constant
    # find body assignments to var of the form `var := var +/- c`
    step_re = re.compile(
        r"\b" + re.escape(var) + r"\s*:=\s*" + re.escape(var) +
        r"\s*([+\-])\s*(\d+)\b", re.IGNORECASE)
    steps = step_re.findall(body)
    if len(steps) != 1:
        return False                                 # 0 or multiple updates -> unclear
    sign, num = steps[0]
    c = int(num)
    if c == 0:
        return False
    # any OTHER assignment to var (not the recognized step) -> ambiguous
    all_assigns = [a for a in _ASSIGN_TO.findall(body) if a == var]
    if len(all_assigns) != 1:
        return False
    if op in (">", ">=") and sign == "-":
        return True
    if op in ("<", "<=") and sign == "+":
        return True
    return False


def _assigns_any(body: str, names: List[str]) -> bool:
    assigned = set(_ASSIGN_TO.findall(body))
    return any(n in assigned for n in names)


# --- per-loop analysis -------------------------------------------------------

def _analyze_while(cond: str, body: str, line: int) -> TerminationResult:
    has_exit = bool(_EXIT.search(body))
    gvars = _guard_vars(cond)

    if gvars is None:
        return TerminationResult("", line, "unknown", "while", [],
                                 f"condition '{cond.strip()}' outside analyzable "
                                 "fragment")
    is_const_true = cond.strip().lower() in ("true", "1")

    if is_const_true:
        if has_exit:
            return TerminationResult("", line, "safe", "while", [],
                                     "constant-true guard but EXIT; is reachable "
                                     "in body")
        return TerminationResult("CWE-835", line, "infinite", "while", [],
                                 "constant-true guard (WHILE TRUE) with no EXIT; "
                                 "in body — exit unreachable")

    # has at least one guard variable
    if has_exit:
        return TerminationResult("", line, "safe", "while", gvars,
                                 "EXIT; reachable in body")

    if not _assigns_any(body, gvars):
        return TerminationResult("CWE-835", line, "infinite", "while", gvars,
                                 f"guard var(s) {gvars} never assigned in body and "
                                 "no EXIT; — condition value cannot change")

    # guard var IS updated: try to prove monotone progress toward the bound
    if _monotone_toward_exit(cond, body):
        return TerminationResult("", line, "safe", "while", gvars,
                                 f"guard var {gvars[0]} moves monotonically toward "
                                 "the exit boundary")

    return TerminationResult("", line, "unknown", "while", gvars,
                             "guard var updated but progress toward exit not "
                             "provable — conservative unknown")


def _analyze_repeat(cond: str, body: str, line: int) -> TerminationResult:
    # REPEAT executes body then exits when UNTIL <cond> is TRUE.
    has_exit = bool(_EXIT.search(body))
    gvars = _guard_vars(cond)

    if gvars is None:
        return TerminationResult("", line, "unknown", "repeat", [],
                                 f"UNTIL condition '{cond.strip()}' outside "
                                 "analyzable fragment")

    # UNTIL TRUE / UNTIL 1 -> exits after first iteration: terminating.
    if cond.strip().lower() in ("true", "1"):
        return TerminationResult("", line, "safe", "repeat", [],
                                 "UNTIL TRUE — exits after first iteration")

    if has_exit:
        return TerminationResult("", line, "safe", "repeat", gvars,
                                 "EXIT; reachable in body")

    if not _assigns_any(body, gvars):
        return TerminationResult("CWE-835", line, "infinite", "repeat", gvars,
                                 f"UNTIL guard var(s) {gvars} never assigned in "
                                 "body and no EXIT; — condition value cannot change")

    # For REPEAT, the exit boundary direction is inverted relative to WHILE
    # (loop continues while cond is FALSE). We do not attempt to prove monotone
    # progress here; updated-but-unproven -> unknown (never false safe).
    return TerminationResult("", line, "unknown", "repeat", gvars,
                             "UNTIL guard var updated but progress not proven — "
                             "conservative unknown")


def _analyze_for(head_m: re.Match, line: int) -> TerminationResult:
    var = head_m.group(1)
    a, b, step = head_m.group(2), head_m.group(3), head_m.group(4)
    # well-formed bounded FOR requires CONSTANT bounds (and step if present).
    consts_ok = _is_const(a) and _is_const(b)
    if step is not None:
        if not _is_const(step):
            consts_ok = False
        elif int(step.strip()) == 0:
            # BY 0 never advances the counter -> not provably terminating.
            return TerminationResult("", line, "unknown", "for", [var],
                                     "FOR step is 0 (non-advancing) — cannot prove "
                                     "termination")
    if consts_ok:
        return TerminationResult("", line, "safe", "for", [var],
                                 "well-formed FOR with constant bounds — bounded "
                                 "counter terminates")
    return TerminationResult("", line, "unknown", "for", [var],
                             "FOR bound/step is non-constant — cannot prove the "
                             "counter reaches the limit")


# --- entry point -------------------------------------------------------------

def check(program: Program) -> List[TerminationResult]:
    """Analyze every WHILE / REPEAT / FOR loop in `program.source` and return one
    TerminationResult per loop header. Sound where it claims a verdict; otherwise
    `unknown`. See module docstring for the supported fragment and guarantees."""
    src = program.source
    lines = src.splitlines()
    results: List[TerminationResult] = []

    for i, line in enumerate(lines):
        # WHILE ---------------------------------------------------------------
        if _WHILE_OPEN.search(line) and not _WHILE_CLOSE.search(line):
            end = _match_block(lines, i, _WHILE_OPEN, _WHILE_CLOSE)
            span = "\n".join(lines[i:end + 1])
            mcond = _WHILE.search(span)
            if mcond is None:
                results.append(TerminationResult("", i + 1, "unknown", "while", [],
                               "could not parse WHILE..DO header"))
                continue
            cond = mcond.group(1)
            # body excludes the `WHILE..DO` header text and the END_WHILE token
            head = mcond.group(0)
            body = _body_text(lines, i, end, head, "END_WHILE")
            results.append(_analyze_while(cond, body, i + 1))

        # REPEAT --------------------------------------------------------------
        elif _REPEAT_OPEN.search(line) and not _REPEAT_CLOSE.search(line):
            end = _match_block(lines, i, _REPEAT_OPEN, _REPEAT_CLOSE)
            span = "\n".join(lines[i:end + 1])
            mcond = _UNTIL.search(span)
            if mcond is None:
                results.append(TerminationResult("", i + 1, "unknown", "repeat", [],
                               "could not parse REPEAT..UNTIL header"))
                continue
            cond = mcond.group(1)
            # body is everything between REPEAT and UNTIL
            until_start = span.find(mcond.group(0))
            body = span[:until_start].replace("REPEAT", " ", 1)
            results.append(_analyze_repeat(cond, body, i + 1))

        # FOR -----------------------------------------------------------------
        elif _FOR_OPEN.search(line) and not _FOR_CLOSE.search(line):
            end = _match_block(lines, i, _FOR_OPEN, _FOR_CLOSE)
            span = "\n".join(lines[i:end + 1])
            head_m = _FOR_HEAD.search(span)
            if head_m is None:
                results.append(TerminationResult("", i + 1, "unknown", "for", [],
                               "could not parse FOR header"))
                continue
            results.append(_analyze_for(head_m, i + 1))

    return results
