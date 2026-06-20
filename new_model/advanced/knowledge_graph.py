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

Evidence-based priors (institutional memory a stateless model cannot have):
  - record_outcome(): accumulate confirmed true-/false-positive labels per
    pattern as analysts triage findings over time.
  - pattern_prior(): a Beta-Bernoulli (Laplace-smoothed) posterior estimate of
    P(true positive | pattern) from those outcomes. A pattern historically
    confirmed real lends a new matching finding a higher prior; an unseen
    pattern gets a neutral 0.5. This is exactly the cross-session accumulation
    a single forward pass cannot do.
  - risk_score(): fuses the prior with real-world CVE linkage and recurrence
    into one bounded [0,1] triage score.
  - to_dot(): Graphviz export for analyst visualisation (pure string).

Caveat: priors are only as good as the triage labels fed in; garbage-in →
garbage-out. The smoothing keeps tiny samples from producing extreme priors.

Stored as JSON so it persists across runs and seeds the next scan's priors.
Back-compat: old JSON files without outcome keys load fine (defaulting empty).
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
    # confirmed-outcome tallies per pattern key (Beta-Bernoulli evidence)
    tp_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    fp_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))

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

    # --- evidence-based priors / risk ---
    def record_outcome(self, pattern_key: str, was_true_positive: bool) -> None:
        """Record a triaged outcome for a pattern: a confirmed true positive
        (real vulnerability) or a confirmed false positive (analyst dismissed).

        These tallies are the cross-session evidence a stateless model lacks;
        they feed the Beta-Bernoulli posterior in pattern_prior()."""
        if was_true_positive:
            self.tp_counts[pattern_key] += 1
        else:
            self.fp_counts[pattern_key] += 1

    def pattern_prior(self, pattern_key: str) -> float:
        """Smoothed posterior estimate of P(true positive | pattern).

        We model each triage outcome for a pattern as a Bernoulli trial
        (true-positive = 1, false-positive = 0). With a conjugate Beta(1,1)
        (uniform) prior, after observing tp successes and fp failures the
        posterior is Beta(1 + tp, 1 + fp); its mean (the point estimate) is the
        Laplace-smoothed fraction

            (tp + 1) / (tp + fp + 2).

        With no data this is (0+1)/(0+0+2) = 0.5 — a sensible neutral prior,
        never a crash. Smoothing keeps a single observation from snapping the
        estimate to 0 or 1, which matters when triage samples are tiny."""
        tp = self.tp_counts.get(pattern_key, 0)
        fp = self.fp_counts.get(pattern_key, 0)
        return (tp + 1) / (tp + fp + 2)

    def risk_score(self, pattern_key: str) -> float:
        """Bounded [0,1] triage score fusing three independent signals:

          - prior:     evidence-based P(true positive | pattern)        [0,1]
          - cve_link:  does this pattern's CWE map to a real CVE? (0/1)
          - recurrence: how often the pattern reappears (systemic weakness),
                        squashed to [0,1] as count/(count+3).

        Combined as a documented weighted average (weights sum to 1):

            0.5*prior + 0.3*cve_link + 0.2*recurrence

        The prior dominates (it is the most direct evidence), a real CVE link
        meaningfully boosts risk, and recurrence adds a smaller systemic nudge.
        Result is guaranteed within [0,1] since each term is in [0,1]."""
        prior = self.pattern_prior(pattern_key)
        cve_link = 1.0 if self.cve_for_pattern(pattern_key) else 0.0
        n = self.counts.get(self.n("Pattern", pattern_key), 0)
        recurrence = n / (n + 3)
        score = 0.5 * prior + 0.3 * cve_link + 0.2 * recurrence
        return max(0.0, min(1.0, score))

    # --- visualization ---
    def to_dot(self) -> str:
        """Export the graph as Graphviz DOT (pure string, no external libs).

        Nodes are shaped/coloured by kind so an analyst can eyeball how a
        pattern connects through its CWE to real CVEs and affected components."""
        style = {
            "Pattern":   ("box", "lightblue"),
            "CWE":       ("ellipse", "khaki"),
            "CVE":       ("doubleoctagon", "salmon"),
            "Component": ("folder", "palegreen"),
            "Finding":   ("note", "white"),
        }
        nodes: Set[str] = set()
        for a, bs in self.edges.items():
            nodes.add(a)
            nodes.update(bs)
        lines = ["digraph KnowledgeGraph {", "  rankdir=LR;"]
        for node in sorted(nodes):
            kind = node.split(":", 1)[0]
            shape, color = style.get(kind, ("box", "white"))
            label = node.replace('"', "'")
            lines.append(f'  "{node}" [label="{label}", shape={shape}, '
                         f'style=filled, fillcolor={color}];')
        seen_pairs: Set[tuple] = set()
        for a, bs in sorted(self.edges.items()):
            for b in sorted(bs):
                pair = tuple(sorted((a, b)))
                if pair in seen_pairs:
                    continue
                seen_pairs.add(pair)
                lines.append(f'  "{a}" -> "{b}";')
        lines.append("}")
        return "\n".join(lines)

    # --- persistence ---
    def save(self, path: str) -> None:
        data = {"edges": {k: sorted(v) for k, v in self.edges.items()},
                "counts": dict(self.counts),
                "tp_counts": dict(self.tp_counts),
                "fp_counts": dict(self.fp_counts)}
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
        # back-compat: old JSON files predate outcome tallies -> default empty
        for k, v in data.get("tp_counts", {}).items():
            kg.tp_counts[k] = v
        for k, v in data.get("fp_counts", {}).items():
            kg.fp_counts[k] = v
        return kg
