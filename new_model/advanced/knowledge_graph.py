"""Persistent vulnerability knowledge graph — institutional memory a chat model
cannot have.

A frontier LLM is amnesiac between calls: it can't accumulate what it has seen
across codebases, link a local pattern to the CVE it caused elsewhere, or answer
"have we seen this before?". A specialist keeps a persistent graph and grows
smarter with every scan.

Nodes:  Pattern · CWE · CVE · Component · Finding
Edges:  Pattern—INSTANCE_OF→CWE · CWE—CLASSIFIES→CVE · CVE—AFFECTS→Component
        Finding—MATCHES→Pattern · Finding—IN→Component

Cross-codebase queries this enables (each beyond a single forward pass):
  - cve_for_pattern(): "this code pattern previously caused which real CVEs?"
  - components_at_risk(): "given a pattern seen here, which deployed components
    share the same CWE-linked CVE history?"
  - recurring_patterns(): patterns that keep reappearing → systemic weakness.

Stored as JSON so it persists across runs and seeds the next scan's priors.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Set


@dataclass
class KnowledgeGraph:
    # adjacency: typed edges as sets of node ids ("type:id")
    edges: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # --- node id helpers ---
    @staticmethod
    def n(kind: str, name: str) -> str:
        return f"{kind}:{name}"

    def _link(self, a: str, b: str) -> None:
        self.edges[a].add(b)
        self.edges[b].add(a)

    # --- ingestion ---
    def add_cve(self, cve: str, cwe: str, component: str) -> None:
        c, w, comp = self.n("CVE", cve), self.n("CWE", cwe), self.n("Component", component)
        self._link(w, c)
        self._link(c, comp)

    def add_pattern(self, pattern_key: str, cwe: str) -> None:
        self._link(self.n("Pattern", pattern_key), self.n("CWE", cwe))

    def add_finding(self, finding_id: str, pattern_key: str, cwe: str,
                    component: str) -> None:
        f = self.n("Finding", finding_id)
        self._link(f, self.n("Pattern", pattern_key))
        self._link(f, self.n("CWE", cwe))
        if component:
            self._link(f, self.n("Component", component))
        self.add_pattern(pattern_key, cwe)
        self.counts[self.n("Pattern", pattern_key)] += 1

    # --- queries ---
    def _neighbors(self, node: str, kind: str) -> Set[str]:
        return {x for x in self.edges.get(node, set()) if x.startswith(kind + ":")}

    def cve_for_pattern(self, pattern_key: str) -> List[str]:
        """Real CVEs reachable from a code pattern via its CWE class."""
        cves: Set[str] = set()
        for cwe in self._neighbors(self.n("Pattern", pattern_key), "CWE"):
            cves |= self._neighbors(cwe, "CVE")
        return sorted(c.split(":", 1)[1] for c in cves)

    def components_at_risk(self, pattern_key: str) -> List[str]:
        """Components historically affected by CVEs of this pattern's CWE."""
        comps: Set[str] = set()
        for cwe in self._neighbors(self.n("Pattern", pattern_key), "CWE"):
            for cve in self._neighbors(cwe, "CVE"):
                comps |= self._neighbors(cve, "Component")
        return sorted(c.split(":", 1)[1] for c in comps)

    def recurring_patterns(self, min_count: int = 2) -> List[tuple]:
        return sorted(((k.split(":", 1)[1], v) for k, v in self.counts.items()
                       if v >= min_count), key=lambda x: -x[1])

    def seen_before(self, pattern_key: str) -> bool:
        return self.counts.get(self.n("Pattern", pattern_key), 0) > 0

    # --- persistence ---
    def save(self, path: str) -> None:
        data = {"edges": {k: sorted(v) for k, v in self.edges.items()},
                "counts": dict(self.counts)}
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)

    @classmethod
    def load(cls, path: str) -> "KnowledgeGraph":
        kg = cls()
        with open(path) as fh:
            data = json.load(fh)
        for k, vs in data.get("edges", {}).items():
            kg.edges[k] = set(vs)
        for k, v in data.get("counts", {}).items():
            kg.counts[k] = v
        return kg
