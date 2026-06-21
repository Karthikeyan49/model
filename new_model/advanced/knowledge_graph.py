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

# Named severities mapped to a normalised 0..1 weight. Numeric CVSS scores
# (0..10) are also accepted by add_cve and normalised by /10.
SEVERITY_WEIGHT = {
    "info": 0.1,
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}
_DEFAULT_SEVERITY = "medium"


def _severity_weight(severity) -> float:
    """Normalise a severity (named string or numeric CVSS 0..10) to 0..1."""
    if isinstance(severity, (int, float)):
        return max(0.0, min(1.0, float(severity) / 10.0))
    return SEVERITY_WEIGHT.get(str(severity).lower(), SEVERITY_WEIGHT[_DEFAULT_SEVERITY])


@dataclass
class KnowledgeGraph:
    # adjacency: typed edges as sets of node ids ("type:id")
    edges: Dict[str, Set[str]] = field(default_factory=lambda: defaultdict(set))
    counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    # per-CVE-node severity weight (0..1); populated by add_cve.
    severities: Dict[str, float] = field(default_factory=dict)

    # --- node id helpers ---
    @staticmethod
    def n(kind: str, name: str) -> str:
        return f"{kind}:{name}"

    def _link(self, a: str, b: str) -> None:
        self.edges[a].add(b)
        self.edges[b].add(a)

    # --- ingestion ---
    def add_cve(self, cve: str, cwe: str, component: str,
                severity=_DEFAULT_SEVERITY) -> None:
        """Link CVE—CWE—Component and record the CVE's severity.

        `severity` may be a named level ("info"|"low"|"medium"|"high"|
        "critical") or a numeric CVSS score (0..10). It defaults to "medium"
        so all pre-existing 3-arg calls keep working unchanged. The normalised
        weight (0..1) is stored on the CVE node and persisted via save/load.
        """
        c, w, comp = self.n("CVE", cve), self.n("CWE", cwe), self.n("Component", component)
        self._link(w, c)
        self._link(c, comp)
        self.severities[c] = _severity_weight(severity)

    def cve_severity(self, cve: str) -> float:
        """Normalised (0..1) severity weight stored for a CVE id."""
        return self.severities.get(self.n("CVE", cve), 0.0)

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

    def _cve_nodes_for_pattern(self, pattern_key: str) -> Set[str]:
        """CVE node ids reachable from a pattern via its CWE class(es)."""
        cves: Set[str] = set()
        for cwe in self._neighbors(self.n("Pattern", pattern_key), "CWE"):
            cves |= self._neighbors(cwe, "CVE")
        return cves

    def prioritize(self, pattern_key: str) -> float:
        """Urgency score for a recurring pattern — higher = fix first.

        Combines how *often* a pattern recurs with how *severe* the CVEs it is
        historically linked to are::

            recurrence  = log2(1 + count)        # diminishing returns on volume
            sev         = max severity weight (0..1) over reachable CVEs
            score       = recurrence * (0.5 + sev)

        The (0.5 + sev) factor guarantees a recurring pattern always scores
        above a never-recurring one, while a high-severity history pushes it
        further up. A pattern with no findings (count 0) scores 0.0.
        """
        import math
        count = self.counts.get(self.n("Pattern", pattern_key), 0)
        if count <= 0:
            return 0.0
        sevs = [self.severities.get(c, 0.0) for c in self._cve_nodes_for_pattern(pattern_key)]
        sev = max(sevs) if sevs else 0.0
        recurrence = math.log2(1 + count)
        return recurrence * (0.5 + sev)

    def explain(self, pattern_key: str) -> List[str]:
        """Deterministic provenance chains justifying a pattern's risk.

        Returns sorted human-readable strings of the form
        ``Pattern:<key> -> CWE:<cwe> -> CVE:<cve> (sev=<w>) -> Component:<comp>``
        — the institutional-memory trail linking the local pattern to the real
        CVEs/components that share its weakness class.
        """
        chains: List[str] = []
        p = self.n("Pattern", pattern_key)
        for cwe in self._neighbors(p, "CWE"):
            for cve in self._neighbors(cwe, "CVE"):
                comps = self._neighbors(cve, "Component")
                sev = self.severities.get(cve, 0.0)
                cwe_name, cve_name = cwe.split(":", 1)[1], cve.split(":", 1)[1]
                if comps:
                    for comp in comps:
                        chains.append(
                            f"Pattern:{pattern_key} -> CWE:{cwe_name} -> "
                            f"CVE:{cve_name} (sev={sev:.2f}) -> "
                            f"Component:{comp.split(':', 1)[1]}")
                else:
                    chains.append(
                        f"Pattern:{pattern_key} -> CWE:{cwe_name} -> "
                        f"CVE:{cve_name} (sev={sev:.2f})")
        return sorted(chains)

    # --- persistence ---
    def save(self, path: str) -> None:
        data = {"edges": {k: sorted(v) for k, v in self.edges.items()},
                "counts": dict(self.counts),
                "severities": dict(self.severities)}
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
        for k, v in data.get("severities", {}).items():
            kg.severities[k] = v
        return kg
