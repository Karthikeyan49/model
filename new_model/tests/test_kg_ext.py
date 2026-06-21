"""Tests for the additive knowledge-graph extensions: severity-weighted CVE edges
with persistence, prioritize() (recurrence x max reachable severity), and
explain() (deterministic Pattern->CWE->CVE->Component provenance chains)."""
import knowledge_graph as kg


def test_add_cve_severity_named_and_persisted(tmp_path):
    g = kg.KnowledgeGraph()
    g.add_cve("CVE-2020-7475", "CWE-787", "OpenPLC v3", severity="high")
    g.add_cve("CVE-2021-0001", "CWE-369", "Codesys", severity=2.0)  # numeric CVSS
    # legacy 3-arg call still works and defaults to medium
    g.add_cve("CVE-2019-9999", "CWE-125", "FactoryIO")
    assert g.cve_severity("CVE-2020-7475") == kg.SEVERITY_WEIGHT["high"]
    assert g.cve_severity("CVE-2021-0001") == 0.2          # 2.0 / 10
    assert g.cve_severity("CVE-2019-9999") == kg.SEVERITY_WEIGHT["medium"]

    p = tmp_path / "kg.json"
    g.save(str(p))
    g2 = kg.KnowledgeGraph.load(str(p))
    assert g2.cve_severity("CVE-2020-7475") == kg.SEVERITY_WEIGHT["high"]
    assert g2.cve_severity("CVE-2021-0001") == 0.2


def test_prioritize_ranks_high_sev_recurring_above_low_rare():
    g = kg.KnowledgeGraph()
    # high-severity, frequently recurring pattern
    g.add_cve("CVE-A", "CWE-787", "PLC-A", severity="critical")
    for i in range(4):
        g.add_finding(f"h{i}", "index-write|unguarded", "CWE-787", "PLC-A")
    # low-severity, rare pattern
    g.add_cve("CVE-B", "CWE-125", "PLC-B", severity="low")
    g.add_finding("l0", "index-read|unguarded", "CWE-125", "PLC-B")

    hi = g.prioritize("index-write|unguarded")
    lo = g.prioritize("index-read|unguarded")
    assert hi > lo
    # a never-seen pattern scores zero
    assert g.prioritize("nope") == 0.0


def test_explain_returns_pattern_cwe_cve_component_chain():
    g = kg.KnowledgeGraph()
    g.add_cve("CVE-2020-7475", "CWE-787", "OpenPLC v3", severity="high")
    g.add_finding("f1", "index-write|unguarded", "CWE-787", "OpenPLC v3")
    chains = g.explain("index-write|unguarded")
    assert chains == sorted(chains)            # deterministic ordering
    assert any("Pattern:index-write|unguarded" in c
               and "CWE:CWE-787" in c
               and "CVE:CVE-2020-7475" in c
               and "Component:OpenPLC v3" in c
               for c in chains)
