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

## Beyond-frontier capabilities — what a stateless LLM structurally cannot do

A frontier chat model is single-pass, amnesiac, and gives no formal guarantees.
These modules do things that are *categorically* out of reach for a forward pass —
they require explicit graphs, constraint solving, fixpoints, and verification loops.
Run the whole stack with `python deepscan.py --target <dir> --kg kg.json`.

| Module | Capability | Why a frontier LLM can't match it |
|---|---|---|
| `symbolic.py` | **Sound bounded model-check with concrete witness** | Proves a bounds/div-zero property is violated *and* emits a replayable counterexample input; proves `safe` when guarded. An LLM guesses; this is sound for the fragment and never returns a false `safe` (→ `unknown`). |
| `repair.py` | **Verified repair (synthesize + re-prove)** | Generates a patch, then re-runs the prover to *prove* the vulnerability is gone and the code is preserved. LLMs suggest fixes they cannot verify. |
| `interproc.py` | **Whole-program interprocedural taint** | Compositional function summaries + call-graph fixpoint track taint across calls that don't fit one context window. Scales past any prompt length. |
| `variant_hunt.py` | **Variant analysis from a seed bug** | Extracts a structural signature and enumerates *every* clone across the corpus (renamed/reconstanted match; guarded = fixed, excluded). No persistent index in an LLM. |
| `knowledge_graph.py` | **Persistent cross-codebase memory** | Links Pattern↔CWE↔CVE↔Component↔Finding and answers "has this pattern caused a real CVE before?" — institutional memory that grows per scan. |

Each is a *lightweight but genuine* implementation over the IEC 61131-3 ST fragment:
the point is to demonstrate capabilities that are categorically beyond a forward
pass, then deepen the engines as the domain widens. They are sound where they claim
to be (`symbolic` returns `unknown` rather than a false `safe`).

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
