"""Extended variant-hunting tests: out-of-bounds READ (CWE-125) signatures,
strict per-kind matching, guard-aware exclusion, and dual write+read emission."""
import variant_hunt
from schema import Program


def P(s, pid="t.st"):
    return Program(pid, pid, s, [])


def test_index_read_seed_matches_renamed_reconstanted_clone():
    seed = P("x := a[i+1];", "seed.st")
    sig = variant_hunt.seed_signature(seed, 1)
    assert sig is not None and sig.kind == "index-read" and sig.cwe == "CWE-125"
    corpus = [P("y := buf[idx+3];", "c1.st"),       # renamed + reconstanted read
              P("z := w + 1;", "c2.st")]            # unrelated
    hits = variant_hunt.hunt(sig, corpus)
    pids = {h.pid for h in hits}
    assert "c1.st" in pids
    assert "c2.st" not in pids
    assert all(h.signature.cwe == "CWE-125" for h in hits)


def test_index_read_does_not_match_index_write_seed():
    # No cross-kind match: a read seed must not pull in writes and vice versa.
    read_seed = variant_hunt.seed_signature(P("x := a[i+1];", "s.st"), 1)
    write_corpus = [P("a[i+1] := 1;", "w.st")]
    assert variant_hunt.hunt(read_seed, write_corpus) == []

    write_seed = variant_hunt.seed_signature(P("a[i+1] := 1;", "s.st"), 1)
    read_corpus = [P("x := a[i+1];", "r.st")]
    assert variant_hunt.hunt(write_seed, read_corpus) == []


def test_guarded_read_excluded_as_fixed():
    seed = variant_hunt.seed_signature(P("x := a[i+1];", "seed.st"), 1)
    corpus = [P("IF k < 10 THEN x := a[k]; END_IF;", "g.st")]
    hits = variant_hunt.hunt(seed, corpus)  # require_unguarded=True default
    assert hits == []
    # but it IS detected as a (guarded) signature when not filtering:
    all_hits = variant_hunt.hunt(seed, corpus, require_unguarded=False)
    assert any(h.pid == "g.st" and h.signature.guarded_var for h in all_hits)


def test_line_with_both_write_and_read_emits_both():
    prog = P("a[i] := b[j];", "both.st")
    sigs = variant_hunt._signatures_in(prog)
    kinds = {s.signature.kind for s in sigs}
    assert "index-write" in kinds and "index-read" in kinds
    cwes = {s.signature.cwe for s in sigs}
    assert cwes == {"CWE-787", "CWE-125"}


def test_array_declaration_not_flagged():
    decl = P("VAR\n arr : ARRAY[0..9] OF INT;\nEND_VAR\n", "d.st")
    assert variant_hunt._signatures_in(decl) == []
