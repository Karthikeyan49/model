"""End-to-end integration test for the deep-scan chain (deepscan.run):

    symbolic proof → verified repair → non-termination → variant hunt → KG

There was previously no test exercising the wiring that chains the beyond-frontier
modules together; this locks in that the stages compose and that each stage's
output is recorded into the persistent knowledge graph.
"""
import json
import os

import deepscan
import knowledge_graph as kgmod


def _write_corpus(d):
    """A tiny ST corpus that triggers every deep-scan stage."""
    # An out-of-bounds write (CWE-787) that is also a variant-hunt seed + repairable.
    (d / "oob.st").write_text(
        "PROGRAM oob\n"
        "VAR a:ARRAY[0..9] OF INT; idx:INT; END_VAR\n"
        " a[idx+2] := 1;\n"
        "END_PROGRAM\n"
    )
    # A clone of the same structural bug (renamed/reconstanted) for variant hunting.
    (d / "clone.st").write_text(
        "PROGRAM clone\n"
        "VAR buf:ARRAY[0..5] OF INT; k:INT; END_VAR\n"
        " buf[k+3] := 9;\n"
        "END_PROGRAM\n"
    )
    # A provably non-terminating loop (CWE-835): constant-true guard, no EXIT.
    (d / "loop.st").write_text(
        "PROGRAM loop\n"
        "VAR x:INT; END_VAR\n"
        "WHILE TRUE DO\n"
        " x := x + 1;\n"
        "END_WHILE;\n"
        "END_PROGRAM\n"
    )
    (d / "labels.json").write_text(json.dumps({}))


def test_deepscan_end_to_end(tmp_path):
    target = tmp_path / "corpus"
    target.mkdir()
    _write_corpus(target)
    kg_path = tmp_path / "kg.json"

    proven, patches, infinite = deepscan.run(str(target), str(kg_path))

    # --- symbolic stage: the OOB write is proven with a concrete witness ---
    assert any(r.cwe == "CWE-787" and r.status == "violated" and r.witness
               for _, r in proven)

    # --- repair stage: at least one synthesized patch verifies ---
    assert any(pt.verified for _, pt in patches)

    # --- non-termination stage: the WHILE TRUE loop is proven infinite ---
    assert infinite and any(r.cwe == "CWE-835" for _, r in infinite)

    # --- persistence: the KG was written and reloads with recorded findings ---
    assert os.path.exists(str(kg_path))
    kg = kgmod.KnowledgeGraph.load(str(kg_path))
    # the index-write pattern recurs across oob.st + clone.st (a real systemic weakness)
    recurring = dict(kg.recurring_patterns(min_count=2))
    assert any("index-write" in pat for pat in recurring)
    # the infinite-loop pattern was recorded too
    assert kg.seen_before("infinite-loop|while")


def test_deepscan_runs_on_bundled_sample():
    """The chain runs end-to-end on the bundled sample dir without a KG path."""
    base = os.path.dirname(os.path.dirname(deepscan.__file__))
    sample = os.path.join(base, "baseline", "data", "sample")
    proven, patches, infinite = deepscan.run(sample, None)
    # the bundled sample has known OOB / div-zero seeds -> non-empty proven set
    assert proven
