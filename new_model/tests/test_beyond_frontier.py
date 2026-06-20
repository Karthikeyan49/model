"""Tests for the beyond-frontier capabilities: symbolic proof, variant hunting,
interprocedural taint, verified repair, knowledge graph."""
import interproc
import knowledge_graph as kg
import repair
import symbolic
import variant_hunt
from schema import Program


def P(s, pid="t.st"):
    return Program(pid, pid, s, [])


# --- symbolic: sound proofs with witnesses ----------------------------------

def test_symbolic_proves_violation_with_witness():
    prog = P("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n a[idx+2]:=1;\n")
    viol = [r for r in symbolic.check(prog) if r.cwe == "CWE-787" and r.status == "violated"]
    assert viol and viol[0].witness is not None and "idx" in viol[0].witness


def test_symbolic_proves_safe_when_guarded():
    prog = P("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n"
             "IF idx >= 0 THEN\n IF idx <= 7 THEN a[idx+2]:=1; END_IF; END_IF;\n")
    statuses = {r.status for r in symbolic.check(prog) if r.cwe == "CWE-787"}
    assert "violated" not in statuses and "safe" in statuses


def test_symbolic_div_zero_and_exclusion():
    prog = P("VAR\n x:INT; y:INT; r:INT;\nEND_VAR\n r:=x/y;\n")
    assert any(r.cwe == "CWE-369" and r.status == "violated" for r in symbolic.check(prog))
    safe = P("VAR\n x:INT; y:INT; r:INT;\nEND_VAR\n IF y <> 0 THEN r:=x/y; END_IF;\n")
    assert all(r.status != "violated" for r in symbolic.check(safe) if r.cwe == "CWE-369")


def test_symbolic_unknown_not_false_safe():
    # non-linear index -> must be 'unknown', never a false 'safe'
    prog = P("VAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n a[idx*idx]:=1;\n")
    assert any(r.cwe == "CWE-787" and r.status == "unknown" for r in symbolic.check(prog))


# --- verified repair: synthesize + re-prove ----------------------------------

def test_repair_oob_verified():
    prog = P("PROGRAM p\nVAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n"
             " a[idx+2]:=1;\nEND_PROGRAM\n")
    patches = repair.repair_all(prog)
    assert patches and patches[0].verified
    # the proof is real: re-checking the patched source yields no violation
    patched = P(patches[0].patched_source)
    assert all(r.status != "violated" for r in symbolic.check(patched)
               if r.cwe == "CWE-787")


def test_repair_div_verified():
    prog = P("PROGRAM p\nVAR\n x:INT; y:INT; r:INT;\nEND_VAR\n r:=x/y;\nEND_PROGRAM\n")
    patches = repair.repair_all(prog)
    assert patches and patches[0].verified and patches[0].cwe == "CWE-369"


def test_repair_preserves_original_statement():
    prog = P("PROGRAM p\nVAR\n a:ARRAY[0..9] OF INT;\n idx:INT;\nEND_VAR\n"
             " a[idx+2]:=1;\nEND_PROGRAM\n")
    pt = repair.repair_all(prog)[0]
    assert "a[idx+2]:=1;" in pt.patched_source   # structure preserved


# --- interprocedural taint ---------------------------------------------------

def test_interproc_traces_across_call():
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[pos]:=7;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR_INPUT\n field:INT;\nEND_VAR\n"
           "Writer(pos := field);\nEND_PROGRAM\n")
    findings = interproc.analyze(P(src))
    assert findings and "Writer" in " ".join(findings[0].path)


def test_interproc_no_taint_when_untainted_arg():
    src = ("FUNCTION_BLOCK Writer\nVAR_INPUT\n pos:INT;\nEND_VAR\n"
           "VAR\n buf:ARRAY[0..9] OF INT;\nEND_VAR\n buf[pos]:=7;\nEND_FUNCTION_BLOCK\n"
           "PROGRAM main\nVAR\n localc:INT;\nEND_VAR\n"
           "Writer(pos := localc);\nEND_PROGRAM\n")
    # localc is a local (not VAR_INPUT) -> not tainted -> no finding
    assert interproc.analyze(P(src)) == []


# --- variant hunting ---------------------------------------------------------

def test_variant_hunt_structural_match():
    seed = P("a[i+1]:=1;", "seed.st")
    sig = variant_hunt.seed_signature(seed, 1)
    corpus = [P("buf[idx+3]:=9;", "c1.st"),
              P("IF k<10 THEN arr[k]:=2; END_IF;", "c2.st"),
              P("x:=y+1;", "c3.st")]
    hits = variant_hunt.hunt(sig, corpus)
    pids = {h.pid for h in hits}
    assert "c1.st" in pids        # renamed/reconst variant matches
    assert "c2.st" not in pids    # guarded => fixed variant excluded
    assert "c3.st" not in pids    # unrelated


# --- knowledge graph ---------------------------------------------------------

def test_kg_links_pattern_to_cve_and_components():
    g = kg.KnowledgeGraph()
    g.add_cve("CVE-2020-7475", "CWE-787", "OpenPLC v3")
    g.add_finding("f1", "index-write|unguarded", "CWE-787", "OpenPLC v3")
    assert "CVE-2020-7475" in g.cve_for_pattern("index-write|unguarded")
    assert "OpenPLC v3" in g.components_at_risk("index-write|unguarded")
    assert g.seen_before("index-write|unguarded")
    assert not g.seen_before("never-seen")


def test_kg_recurring_and_persistence(tmp_path):
    g = kg.KnowledgeGraph()
    for i in range(3):
        g.add_finding(f"f{i}", "index-write|unguarded", "CWE-787", "OpenPLC")
    assert ("index-write|unguarded", 3) in g.recurring_patterns(min_count=2)
    p = tmp_path / "kg.json"
    g.save(str(p))
    g2 = kg.KnowledgeGraph.load(str(p))
    assert g2.seen_before("index-write|unguarded")
    assert "CWE-787" in " ".join(g2.cve_for_pattern("index-write|unguarded")) or \
           g2.counts  # persisted
