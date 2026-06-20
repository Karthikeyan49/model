"""Knowledge-grounded triage — reduce hallucination by retrieving real context.

Instead of asking the LLM to judge a candidate from memory (where it can confabulate
CWE semantics), we retrieve and inject:
  - the authoritative CWE description for the candidate's weakness class, and
  - the nearest known vulnerable↔fixed exemplars from the curated training data.

The triage prompt is then grounded in real references, which empirically cuts
hallucinated verdicts. Retrieval here is a dependency-free BM25-lite scorer over a
small corpus so it runs anywhere; swap in a vector store for scale — the interface
(`retrieve`) stays identical.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List

# Minimal authoritative CWE knowledge base (extend from MITRE CWE export).
CWE_KB: Dict[str, str] = {
    "CWE-787": "Out-of-bounds Write: the product writes past the end or before the "
               "beginning of the intended buffer; in PLC code, an array index "
               "derived from input without bounds checking.",
    "CWE-369": "Divide By Zero: a calculation divides by a value that can be zero, "
               "causing a fault; check divisors derived from process values.",
    "CWE-457": "Use of Uninitialized Variable: a variable is read before being "
               "assigned, yielding nondeterministic control behaviour.",
    "CWE-190": "Integer Overflow or Wraparound: arithmetic exceeds the type range, "
               "wrapping to an unexpected value used in control logic.",
}


@dataclass
class Exemplar:
    cwe: str
    vulnerable: str
    fixed: str


def _tokens(text: str) -> List[str]:
    return re.findall(r"[a-z_]\w+", text.lower())


class BM25Lite:
    """Tiny BM25 over a small exemplar corpus — no external deps."""

    def __init__(self, docs: List[str], k1: float = 1.5, b: float = 0.75):
        self.docs = [_tokens(d) for d in docs]
        self.k1, self.b = k1, b
        self.N = len(self.docs)
        self.avgdl = (sum(len(d) for d in self.docs) / self.N) if self.N else 0.0
        self.df: Counter = Counter()
        for d in self.docs:
            for term in set(d):
                self.df[term] += 1

    def _idf(self, term: str) -> float:
        n = self.df.get(term, 0)
        return math.log(1 + (self.N - n + 0.5) / (n + 0.5))

    def score(self, query: str, idx: int) -> float:
        doc = self.docs[idx]
        if not doc:
            return 0.0
        tf = Counter(doc)
        dl = len(doc)
        s = 0.0
        for term in _tokens(query):
            if term not in tf:
                continue
            num = tf[term] * (self.k1 + 1)
            den = tf[term] + self.k1 * (1 - self.b + self.b * dl / (self.avgdl or 1))
            s += self._idf(term) * num / den
        return s

    def top(self, query: str, k: int = 2) -> List[int]:
        return sorted(range(self.N), key=lambda i: self.score(query, i),
                      reverse=True)[:k]


def retrieve(candidate_source: str, cwe: str, exemplars: List[Exemplar],
             k: int = 2) -> dict:
    """Return grounding context for the triage prompt."""
    pool = [e for e in exemplars if e.cwe == cwe] or exemplars
    bm = BM25Lite([e.vulnerable for e in pool])
    idxs = bm.top(candidate_source, k=k) if pool else []
    return {
        "cwe_description": CWE_KB.get(cwe, "No KB entry; rely on code evidence."),
        "exemplars": [pool[i] for i in idxs],
    }


def build_grounded_prompt(candidate_source: str, cwe: str, line: int,
                          context: dict) -> str:
    ex = "\n".join(
        f"  vulnerable: {e.vulnerable}\n  fixed: {e.fixed}"
        for e in context.get("exemplars", [])
    )
    return (
        f"Reference — {cwe}: {context['cwe_description']}\n"
        + (f"Similar known cases:\n{ex}\n" if ex else "")
        + f"\nNow judge ONLY whether line {line} of this program is a real, "
        f"reachable {cwe}. Use the references; do not invent issues.\n"
        f"```st\n{candidate_source}\n```"
    )
