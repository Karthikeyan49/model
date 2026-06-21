# Advanced techniques — beyond traditional SAST+LLM

These layers are what push the specialist *past* a traditional hybrid. Each is
research-grounded, runnable on mock backends, and unit-tested. They all serve one
goal: **high recall with a statistically controlled false-positive rate** — the
moat a sellable security tool lives or dies on.

## The flow (advanced/pipeline.py)

```
grounded candidates (analyzer + verify)
  ├─ self-consistency vote (N samples)  → per-finding LLM confidence
  ├─ dataflow taint analysis            → reachability True/False/None
  ▼
ensemble fusion (analyzer · llm · reachability · severity)
  ▼
conformal calibration (target FP budget α)  → FP-bounded threshold
  ▼
EMIT (≥ threshold)   +   ABSTAIN (< threshold → human review)
```

## Techniques & why each is non-traditional

| Module | Technique | Why it beats the traditional approach | Grounding |
|---|---|---|---|
| `conformal.py` | **Conformal selective prediction** | Derives the decision threshold from a *target FP budget* with a finite-sample guarantee, and **abstains** under uncertainty instead of emitting noise. Traditional tools hand-pick a fixed threshold. | Conformal Abstention Framework 2026; arXiv [2405.01563](https://arxiv.org/pdf/2405.01563) |
| `selfconsistency.py` | **N-sample majority voting** | Free calibrated confidence; chosen over multi-agent *debate*, which a controlled study found **underperforms** plain self-consistency at equal compute. | arXiv [2511.07784](https://arxiv.org/pdf/2511.07784), [2310.01798](https://arxiv.org/pdf/2310.01798) |
| `dataflow.py` | **Intraprocedural taint/def-use** | Replaces line-heuristic reachability with a real source→sink data path (with sanitization), so "is it reachable?" has evidence behind it. | classic taint analysis; MAVUL |
| `mockcourt.py` | **Prosecutor/defense/judge verifier** | Optional path for *hard* cases; the defense consumes real reachability evidence so it can veto an over-eager detector. Used sparingly (debate caveat above). | MAVUL [2510.00317](https://arxiv.org/pdf/2510.00317); Mock-Court [2505.10961](https://arxiv.org/pdf/2505.10961) |
| `ensemble.py` | **Weighted multi-signal fusion** | Precision comes from combining independent signals (SAST + LLM + dataflow + prior), not one model. Weights tunable/learnable on calibration. | hybrid SAST+LLM FP studies |
| `moe_routing.yaml` + `router.py` | **Per-CWE LoRA expert MoE** | Small specialised adapters per weakness family, hot-swapped on one base model (vLLM multi-LoRA) — MoE behaviour at LoRA cost, experts retrained independently. | PEFT / vLLM multi-LoRA |

## Reliability layer — knowing when the model is wrong

Advanced detection is worthless if you can't trust it. These modules make the
system *reliable*, not just clever:

| Module | Technique | What reliability problem it solves |
|---|---|---|
| `calibration_metrics.py` | ECE / MCE / Brier / reliability diagram | Is a "0.8 confidence" actually right 80% of the time? Prerequisite for the conformal bound to mean anything. |
| `metamorphic.py` | Semantics-preserving mutation testing | Does the verdict survive renaming/comments? Flags brittle detections that can't be trusted. |
| `drift.py` | PSI + KS distribution-drift detection | Conformal's guarantee assumes iid; this detects when production data drifts and the bound goes stale → RECALIBRATE. |
| `active_learning.py` | Margin / entropy sampling + diversity | Turns the abstain bucket into the most informative labels — the data flywheel with minimal human effort. |
| `provenance.py` | Hashed, replayable evidence chain | Every finding carries why it fired (rule → votes → taint → signals → threshold); tamper-evident audit trail. |
| `rag_triage.py` | BM25-grounded triage (CWE KB + exemplars) | Cuts hallucinated verdicts by grounding the LLM in real CWE references and known cases. |
| `regression_gate.py` | Golden-set CI gate | Fails the build if a change silently lowers recall/precision or loses a known bug — evaluation discipline enforced. |
| `mondrian_conformal.py` | Class-conditional (Mondrian) conformal | One global FP budget over-emits one CWE while over-abstaining another; this calibrates a separate threshold *per CWE* so α holds within each class (Vovk et al.). Small classes fall back to a pooled threshold, flagged. |
| `risk_control.py` | Conformal Risk Control + Learn-then-Test | `conformal.py` bounds false positives among emitted; this bounds the **miss-rate** (false negatives) — the other safety axis — with a finite-sample guarantee, and certifies thresholds with FWER control. (arXiv 2208.02814, 2110.01052) |
| `venn_abers.py` | Venn-Abers probability intervals | Turns any scorer's confidence into a *provably calibrated* probability interval `[p0,p1]` (isotonic/PAV); interval width is an honest epistemic-uncertainty signal. (Vovk & Petej 2014) |

## Accuracy / sound-analysis additions

These sharpen the static/symbolic side — fewer false positives without ever sacrificing soundness.

| Module | Technique | What it improves |
|---|---|---|
| `relational.py` | Octagon/DBM relational domain | The interval domain over-approximates `a[i+j]` to `violated` even when guards bound `i+j`; this relational refinement (Miné 2006) *proves* such indices safe — but only downgrades `violated→safe` when rigorously provable, never a false `safe`. |
| `slicing.py` | Static backward program slicing | Backward slice from a sink over data + control dependences (Weiser 1981; Horwitz-Reps-Binkley PDG/SDG) → minimal operator-readable evidence and a precise reachability input. Over-approximates (includes when in doubt). |

See [`RESEARCH.md`](RESEARCH.md) for the cited SOTA survey and prioritized roadmap behind these.

## Beyond-frontier capabilities — what a stateless LLM structurally cannot do

A frontier chat model is single-pass, amnesiac, and gives no formal guarantees.
These modules do things that are *categorically* out of reach for a forward pass —
they require explicit graphs, constraint solving, fixpoints, and verification loops.
Run the whole stack with `python deepscan.py --target <dir> --kg kg.json`.

| Module | Capability | Why a frontier LLM can't match it |
|---|---|---|
| `symbolic.py` | **Sound bounded model-check with concrete witness** | Proves CWE-787 (array write), CWE-369 (div-zero) **and CWE-190 (16-bit INT overflow/underflow)** violated *and* emits a replayable counterexample input; proves `safe` when guarded. Guards are now **flow/block-scoped** (a guard only constrains the statements it textually encloses — a non-dominating `IF` can no longer produce a false `safe`). Handles multi-variable indices `a[i+j+c]` via interval arithmetic. Sound for the fragment; never a false `safe` (→ `unknown`). |
| `repair.py` | **Verified repair (synthesize + re-prove)** | Generates a patch, then re-runs the prover to *prove* the vulnerability is gone and the code is preserved. LLMs suggest fixes they cannot verify. |
| `interproc.py` | **Whole-program interprocedural taint** | Compositional function summaries + call-graph fixpoint track taint across calls that don't fit one context window. Reports the **full source→call-chain→sink path** with the **correct CWE per sink kind** (index→CWE-787, division→CWE-369), and suppresses params **sanitized by an enclosing callee-side guard**. Scales past any prompt length. |
| `variant_hunt.py` | **Variant analysis from a seed bug** | Extracts a structural signature and enumerates *every* clone across the corpus (renamed/reconstanted match; guarded = fixed, excluded). Covers index-write (CWE-787), division (CWE-369) **and index-read (CWE-125)**, with an optional stricter offset-abstraction match level. No persistent index in an LLM. |
| `knowledge_graph.py` | **Persistent cross-codebase memory** | Links Pattern↔CWE↔CVE↔Component↔Finding and answers "has this pattern caused a real CVE before?". Now also accumulates per-pattern TP/FP outcomes into a **Beta-Bernoulli prior** `pattern_prior()`, a blended `risk_score()` (prior × CVE-linkage × recurrence), and a **Graphviz `to_dot()`** export — institutional memory that grows per scan. |
| `mondrian_conformal.py` | **Class-conditional (Mondrian) conformal prediction** | Calibrates a separate FP-budget threshold **per CWE** so the α guarantee holds *within* each weakness class, not just marginally. Small/unseen classes fall back to a pooled threshold, flagged `used_fallback` so operators see where the bound is only marginal. Complements `conformal.py`. |

Each is a *lightweight but genuine* implementation over the IEC 61131-3 ST fragment:
the point is to demonstrate capabilities that are categorically beyond a forward
pass, then deepen the engines as the domain widens. They are sound where they claim
to be (`symbolic` returns `unknown` rather than a false `safe`).

### Honest caveats on the beyond-frontier layer
- **Symbolic** uses non-relational interval analysis: correlated operands (e.g. `i+j`
  where `i = -j`) are summed as full ranges, so it may over-approximate to `violated`
  where a relational prover would prove `safe` — never the reverse. `ELSE`/`ELSIF`
  branch negations are not modeled (the guard is dropped, conservatively).
- **Interproc** sanitization only checks that an enclosing guard *references* the sink
  param by name; it does not prove the guard is *sufficient* (so `IF p>=0 THEN buf[p]`
  with no upper bound is treated as sanitized). Detection prefers over-reporting.
- **Mondrian** class-conditional validity holds only for groups meeting `min_group`;
  smaller groups inherit the pooled, marginal-only threshold.

## Honest caveats (kept in the code on purpose)

- **Multi-agent debate is not magic.** Evidence says it often ties or loses to
  self-consistency. `mockcourt.py` is therefore optional and only justified when
  its defense has *real evidence* (dataflow) to act on.
- **Conformal guarantees are marginal and assume iid** calibration↔test. Drift
  between PLC codebases can break the bound — recalibrate per domain/customer.
- **Mock scorers are for plumbing, not results.** Confidence numbers become
  meaningful only when `scoring.MockScorer` / the mock sampler are replaced with
  real LLM logprobs or sampled verdicts.

## Run it

```bash
cd advanced
python pipeline.py --target ../baseline/data/sample --alpha 0.1
```
