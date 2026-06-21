"""Tests for the additive extensions to the knowledge graph and variant hunter:
severity-weighted CVE edges + persistence, prioritize(), explain(), and the new
variant signature kinds (index-read / loop-index) plus offset sensitivity."""
import knowledge_graph as kg
import variant_hunt
from schema import Program


def P(s, pid="t.st"):
    return Program(pid, pid, s, [])


# --- knowledge graph: severity-weighted edges + persistence ------------------

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


# --- variant hunting: new sink kinds -----------------------------------------

def test_index_read_variant_matches_across_corpus():
    seed = P("y := a[i];", "seed.st")
    sig = variant_hunt.seed_signature(seed, 1)
    assert sig is not None and sig.kind == "index-read" and sig.cwe == "CWE-125"
    corpus = [P("out := buf[idx];", "c1.st"),                 # renamed -> match
              P("IF k<10 THEN z := arr[k]; END_IF;", "c2.st"),  # guarded -> excluded
              P("a[i]:=1;", "c3.st"),                          # write, not read
              P("q := r + 1;", "c4.st")]                       # unrelated
    pids = {h.pid for h in variant_hunt.hunt(sig, corpus)}
    assert "c1.st" in pids
    assert "c2.st" not in pids
    assert "c3.st" not in pids
    assert "c4.st" not in pids


def test_loop_index_variant_detected():
    src = ("FOR i := 0 TO n DO\n  a[i] := 1;\nEND_FOR;\n")
    seed = P(src, "seed.st")
    sig = variant_hunt.seed_signature(seed, 1)
    assert sig is not None and sig.kind == "loop-index" and sig.cwe == "CWE-787"
    corpus = [P("FOR j := 0 TO m DO\n  buf[j] := 9;\nEND_FOR;\n", "c1.st")]
    pids = {h.pid for h in variant_hunt.hunt(sig, corpus)}
    assert "c1.st" in pids


# --- variant hunting: offset sensitivity -------------------------------------

def test_offset_sensitivity_field_and_matching():
    off_seed = variant_hunt.seed_signature(P("a[i+1]:=1;"), 1)
    plain_seed = variant_hunt.seed_signature(P("a[i]:=1;"), 1)
    assert off_seed.has_offset is True
    assert plain_seed.has_offset is False
    # key() is unaffected by offset (backward compatibility)
    assert off_seed.key() == plain_seed.key()

    corpus = [P("buf[k+2]:=7;", "off.st"), P("buf[k]:=7;", "plain.st")]
    # default hunt ignores offset -> both match
    loose = {h.pid for h in variant_hunt.hunt(off_seed, corpus)}
    assert loose == {"off.st", "plain.st"}
    # offset-tight hunt only matches the offset-bearing variant
    tight = {h.pid for h in variant_hunt.hunt(off_seed, corpus, match_offset=True)}
    assert tight == {"off.st"}
