"""Extended tests for the knowledge-graph evidence priors and the richer
variant-hunt signatures. Complements tests/test_beyond_frontier.py (which must
also still pass)."""
import json

import knowledge_graph as kg
import variant_hunt
from schema import Program


def P(s, pid="t.st"):
    return Program(pid, pid, s, [])


# --- knowledge graph: Beta-Bernoulli prior ----------------------------------

def test_prior_neutral_with_no_data():
    g = kg.KnowledgeGraph()
    # Beta(1,1) mean with zero observations -> 0.5, and must not crash.
    assert g.pattern_prior("never-seen") == 0.5


def test_prior_rises_with_true_positives_falls_with_false_positives():
    g = kg.KnowledgeGraph()
    base = g.pattern_prior("p")
    for _ in range(5):
        g.record_outcome("p", was_true_positive=True)
    after_tp = g.pattern_prior("p")
    assert after_tp > base                      # confirmed reals lift the prior

    g2 = kg.KnowledgeGraph()
    for _ in range(5):
        g2.record_outcome("q", was_true_positive=False)
    after_fp = g2.pattern_prior("q")
    assert after_fp < base                      # dismissed FPs lower the prior

    # smoothing keeps it strictly inside (0, 1)
    assert 0.0 < after_tp < 1.0 and 0.0 < after_fp < 1.0


# --- knowledge graph: risk score --------------------------------------------

def test_risk_score_reflects_cve_linkage_and_recurrence():
    # Pattern with no CVE link and no recurrence.
    plain = kg.KnowledgeGraph()
    plain.add_finding("f0", "index-write|unguarded", "CWE-787", "")
    plain_score = plain.risk_score("index-write|unguarded")

    # Same pattern but with a real CVE linked and many recurrences.
    rich = kg.KnowledgeGraph()
    rich.add_cve("CVE-2020-7475", "CWE-787", "OpenPLC v3")
    for i in range(5):
        rich.add_finding(f"f{i}", "index-write|unguarded", "CWE-787", "OpenPLC v3")
    rich_score = rich.risk_score("index-write|unguarded")

    assert rich.cve_for_pattern("index-write|unguarded")  # CVE linkage present
    assert rich_score > plain_score
    assert 0.0 <= plain_score <= 1.0 and 0.0 <= rich_score <= 1.0


def test_risk_score_combines_with_prior():
    g = kg.KnowledgeGraph()
    g.add_finding("f0", "pat", "CWE-787", "")
    before = g.risk_score("pat")
    for _ in range(10):
        g.record_outcome("pat", was_true_positive=True)
    assert g.risk_score("pat") > before


# --- knowledge graph: DOT export --------------------------------------------

def test_to_dot_contains_node_ids_and_is_valid_looking():
    g = kg.KnowledgeGraph()
    g.add_cve("CVE-2020-7475", "CWE-787", "OpenPLC v3")
    g.add_finding("f1", "index-write|unguarded", "CWE-787", "OpenPLC v3")
    dot = g.to_dot()
    assert dot.startswith("digraph")
    assert dot.rstrip().endswith("}")
    assert "Pattern:index-write|unguarded" in dot
    assert "CWE:CWE-787" in dot
    assert "CVE:CVE-2020-7475" in dot
    assert "->" in dot           # has at least one edge


# --- knowledge graph: persistence of outcomes + back-compat ------------------

def test_save_load_round_trips_outcome_counts(tmp_path):
    g = kg.KnowledgeGraph()
    g.add_finding("f1", "index-write|unguarded", "CWE-787", "OpenPLC")
    g.record_outcome("index-write|unguarded", was_true_positive=True)
    g.record_outcome("index-write|unguarded", was_true_positive=True)
    g.record_outcome("index-write|unguarded", was_true_positive=False)
    expected = g.pattern_prior("index-write|unguarded")

    p = tmp_path / "kg.json"
    g.save(str(p))
    g2 = kg.KnowledgeGraph.load(str(p))
    assert g2.tp_counts.get("index-write|unguarded") == 2
    assert g2.fp_counts.get("index-write|unguarded") == 1
    assert g2.pattern_prior("index-write|unguarded") == expected


def test_load_old_style_json_without_new_keys(tmp_path):
    # Simulate a graph persisted before outcome tallies existed.
    old = {
        "edges": {
            "Pattern:index-write|unguarded": ["CWE:CWE-787"],
            "CWE:CWE-787": ["Pattern:index-write|unguarded"],
        },
        "counts": {"Pattern:index-write|unguarded": 2},
    }
    p = tmp_path / "old_kg.json"
    p.write_text(json.dumps(old))
    g = kg.KnowledgeGraph.load(str(p))           # must not raise
    assert g.seen_before("index-write|unguarded")
    assert g.pattern_prior("index-write|unguarded") == 0.5   # defaults empty
    assert dict(g.tp_counts) == {} and dict(g.fp_counts) == {}


# --- variant hunt: new index-READ kind (CWE-125) -----------------------------

def test_variant_hunt_finds_oob_read():
    seed = P("x := a[i+1];", "seed.st")
    sig = variant_hunt.seed_signature(seed, 1)
    assert sig is not None and sig.kind == "index-read" and sig.cwe == "CWE-125"
    corpus = [P("y := buf[idx+3];", "c1.st"),
              P("IF k<10 THEN z := arr[k]; END_IF;", "c2.st"),
              P("w := p + 1;", "c3.st")]
    hits = variant_hunt.hunt(sig, corpus)
    pids = {h.pid for h in hits}
    assert "c1.st" in pids        # renamed/reconst read variant matches
    assert "c2.st" not in pids    # guarded => excluded
    assert "c3.st" not in pids    # unrelated, no array read
    assert all(h.signature.cwe == "CWE-125" for h in hits)


def test_index_write_and_read_do_not_cross_match():
    write_seed = variant_hunt.seed_signature(P("a[i+1] := 1;"), 1)
    read_corpus = [P("x := a[i+1];", "r.st")]
    assert variant_hunt.hunt(write_seed, read_corpus) == []


# --- variant hunt: stricter offset abstraction -------------------------------

def test_offset_abstraction_strictness():
    seed = P("a[i+1] := 1;", "seed.st")
    corpus = [P("b[j+2] := 5;", "same_off.st"),   # also a positive offset
              P("c[k] := 9;", "no_off.st")]       # no offset

    # default (kind-guard): offset ignored -> both match
    loose = variant_hunt.seed_signature(seed, 1)
    loose_pids = {h.pid for h in variant_hunt.hunt(loose, corpus)}
    assert loose_pids == {"same_off.st", "no_off.st"}

    # strict (offset): require same offset sign/presence -> only same_off matches
    strict = variant_hunt.seed_signature(seed, 1, level="offset")
    strict_pids = {h.pid for h in variant_hunt.hunt(strict, corpus)}
    assert strict_pids == {"same_off.st"}
    assert "no_off.st" not in strict_pids


# --- variant hunt: original behaviour preserved ------------------------------

def test_default_behavior_matches_original_scenario():
    seed = P("a[i+1]:=1;", "seed.st")
    sig = variant_hunt.seed_signature(seed, 1)
    corpus = [P("buf[idx+3]:=9;", "c1.st"),
              P("IF k<10 THEN arr[k]:=2; END_IF;", "c2.st"),
              P("x:=y+1;", "c3.st")]
    hits = variant_hunt.hunt(sig, corpus)
    pids = {h.pid for h in hits}
    assert "c1.st" in pids
    assert "c2.st" not in pids
    assert "c3.st" not in pids
