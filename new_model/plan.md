# Cybersecurity Specialist Model — Build Plan (v2)

> Goal: a domain-specialist system that **beats frontier models on defensive
> cybersecurity benchmarks** in a narrow slice first, then expands to cover
> multiple areas on **one shared engine**.

---

## Build status (scaffolded & smoke-tested)

| Component | Where | State |
|---|---|---|
| Phase 1 — hybrid baseline (A/B/C arms) | `baseline/` | ✅ runs end-to-end (mock backends) |
| PLC-BEAD importer | `baseline/download_plc_bead.py` | ✅ git/dir/zip + manifest |
| iec-checker rule→CWE map | `baseline/rule_map.json` | ✅ ~19 rules |
| Phase 2 — data converter + curation | `training/convert.py`, `curate.py` | ✅ tested |
| Phase 3 — 7B QLoRA config | `training/qlora_7b.yaml` | ✅ Axolotl-ready |
| Retrieval — live CVE index | `retrieval/cve_index.py` | ✅ build+lookup tested |
| Phase 4 — correlation engine | `engine/correlate.py` | ✅ corroboration+ranking tested |
| Phase 5 — FP-hardening sweep | `baseline/sweep.py` | ✅ precision/recall curve |
| Reachability reasoning | `baseline/reachability.py` | ✅ drops dead code, annotates |
| Phase 6 — SARIF output | `baseline/sarif.py` | ✅ SARIF 2.1.0 |
| Phase 6 — unified scan CLI | `scan.py` | ✅ end-to-end |
| Synthetic ST generator | `tools/gen_synthetic.py` | ✅ enriches corpus |
| **Advanced — conformal abstention** | `advanced/conformal.py` | ✅ FP-rate bound calibrated |
| **Advanced — self-consistency** | `advanced/selfconsistency.py` | ✅ N-sample voting |
| **Advanced — dataflow taint reachability** | `advanced/dataflow.py` | ✅ propagation+sanitization |
| **Advanced — mock-court verifier** | `advanced/mockcourt.py` | ✅ evidence-aware |
| **Advanced — ensemble fusion** | `advanced/ensemble.py` | ✅ multi-signal |
| **Advanced — per-CWE LoRA MoE** | `advanced/moe_routing.yaml`, `router.py` | ✅ rule router |
| **Advanced — full pipeline** | `advanced/pipeline.py` | ✅ end-to-end |
| Test suite + CI | `tests/`, `.github/workflows/ci.yml` | ✅ 22 passing |
| Task runner | `Makefile` | ✅ |

Remaining (needs real assets/compute, not code): obtain PLC-BEAD source + vuln
manifest, install iec-checker, wire a real LLM provider, download ICS Advisory
CSV, then run the gate (Phase 3 → re-eval). Offensive exploit-generation remains
out of scope by design.

---

## 0. Operating boundary (fixed)

This system does, and is trained for:

- **Detection** of vulnerabilities across code, dependencies, OS, firmware,
  OT/PLC, and configuration.
- **Correlation** across layers into prioritised, real exposures.
- **Reachability / exploitability *reasoning*** — "is this finding actually real
  and reachable?" (the question that decides whether a bug matters).
- **Remediation** — location, severity, plain-language explanation, fix.
- **Authorized validation only** — proving a specific finding is exploitable on a
  target you are explicitly authorised to assess (CTF, scoped pentest, lab).

It deliberately does **not** include an open-ended exploit-generation /
weaponization model. The verification work is scoped to authorised targets, never
arbitrary ones.

Why this boundary is also good product strategy: the market punishes
false positives, not missing esoteric attacks. Precision-at-high-recall is the
sellable metric, and it lives entirely inside this boundary.

---

## 1. Why narrow-first (non-negotiable)

You cannot beat a frontier lab on the *broad average* of cybersecurity — they have
~10,000× the compute and the whole internet of data. You beat them in **one slice
where you have data or structure they lack**, then reuse the engine to expand.

So: **all three target domains, but sequenced on one engine — not three models at
once.**

| Order | Domain | Why this order |
|---|---|---|
| **1st** | **OT / PLC / firmware** | Real moat. Frontier models have little training data here → a specialist genuinely wins. Smaller dataset, but that's the point. |
| **2nd** | **Source code + dependency CVE** | Best public data + benchmarks. Reuses the engine; mostly swap parser + dataset. |
| **3rd** | **Cloud / IaC misconfig** | Structured inputs ground well; strong demand. Same engine again. |

---

## 2. Architecture: one engine, swappable domain packs

```
Target → [Ingestion] → [Deterministic analyzer] → [Retrieval: live CVE/NVD/GHSA]
                              ↓                            ↓
                       [Fine-tuned LLM triage + reasoning]
                              ↓
                  [Verification loop: discard anything unproven]
                              ↓
              [Correlation engine] → [Report: location / severity / fix]
```

- **Deterministic analyzer** grounds the LLM (AST / taint / SAST for code;
  PLC/firmware parser for OT). This is what kills false positives.
- **Verification loop** drops findings the analyzer can't ground or reach.
  *This is where the frontier-beating precision comes from — not model size.*
- A **domain pack** = parser + dataset + rules + eval set. Adding a domain reuses
  the whole engine.

Research basis: hybrid SAST+LLM eliminates **94–98% of false positives** while
keeping recall; bare fine-tunes plateau at ~0.66 F1 (commodity). The edge is the
architecture, not the weights.

---

## 3. Phase plan

### Phase 0 — Define "winning" (week 1)
- Headline metric: **precision at fixed high recall** + **false-positive rate**.
- Pick held-out benchmarks per domain (SecBench, repo-level vuln sets, OT/PLC sets).
- Write target numbers down before any compute.

### Phase 1 — Hybrid baseline, ZERO training (week 1–2) ← START HERE
- Wire existing open model + deterministic analyzer for **OT/PLC**, no fine-tuning.
- Measure FP-rate + recall. Hybrid alone may already beat a frontier model →
  validates the whole thesis before spending a dollar. (Detailed below in §6.)

### Phase 2 — Data assembly, domain #1 (week 2–8) — *the real work*
- CVE/NVD/GHSA, CWE/OWASP, vulnerable↔fixed code pairs, PLC/firmware corpora.
- Curate ruthlessly. Format: finding → location → severity → explanation → fix.
- Hold out an eval split the model never sees.

### Phase 3 — Prove small (week 6–10)
- LoRA fine-tune a **7B** on domain #1 (~$100–300).
- **Gate:** no edge over frontier ⇒ fix the *data*, do not scale.

### Phase 4 — Scale the engine (week 10–16)
- LoRA a **14–32B** code-capable base. Build correlation + verification +
  retrieval layers properly. Track every run (W&B).

### Phase 5 — FP hardening (week 14–20)
- Grind FP-rate down on real codebases with known issues.
- Head-to-head vs frontier + existing tools; document wins.

### Phase 6 — Add domain packs #2 then #3 (week 18+)
- Reuse the engine. New parser + dataset + eval per domain.

### Phase 7 — Authorized validation (optional, scoped)
- Only with a real authorised engagement/CTF: reachability-proof / scoped PoC,
  bounded by that permission.

---

## 4. Stack

- **Base model:** open 14–32B, code-capable (Qwen / Mistral / Gemma family).
- **Tuning:** LoRA / QLoRA via HF PEFT + Transformers; Axolotl for config-driven runs.
- **Serving:** vLLM + quantization (FP8/Q4) → single 80GB GPU (or 48GB quantized).
- **Retrieval:** vector store + live CVE/NVD/GHSA feeds.
- **Compute:** neo-clouds (RunPod / Lambda / Vast / CoreWeave), spot + checkpointing.
- **Tracking:** Weights & Biases or MLflow.

---

## 5. Budget & timeline

| Item | Estimate |
|---|---|
| Phase 1 — hybrid baseline | ~$0 (inference only) |
| Phase 3 — 7B proof | $100–300 |
| Phase 4 — 14–32B fine-tuning (several runs) | $1,000–3,000 |
| Serving during dev | $1–4/hr (auto-stop idle) |
| **Total compute to working v1 (domain #1)** | **~$3,000–8,000** |
| Domains #2–3 | mostly *your time* on data, little new compute |
| Calendar (part-time) | ~6–8 months to all three on one engine |

Biggest cost is your time on data curation — which is also the biggest source of
advantage.

---

## 6. Phase 1 detail — the one-week OT/PLC hybrid baseline

The goal of this week: **prove the hybrid (static analyzer + off-the-shelf LLM)
beats a bare frontier model on PLC vuln detection — with zero training.** If it
does, the thesis holds and Phase 2+ is justified. If it doesn't, the problem is
the grounding design, and you fix it here for ~$0.

### 6.1 Concrete components (all real, available now)

**Datasets (label source of truth):**
- **PLC-BEAD** — 700+ IEC 61131-3 Structured Text programs, 2,431 binaries, with
  ST source. Primary corpus. (arXiv 2502.19725)
- **PLC ST vuln dataset** — real + synthetic ST across 5 vulnerability types, used
  in the LoRA fine-tune study (CodeLlama / Qwen2.5-Coder / Starcoder2).
  (doi.org/10.3390/math13193211)
- **ICS Advisory Project** — CISA ICS-CERT advisories as CSV (CVE, CWE, CVSS,
  product). Backbone for known-vuln correlation. (github.com/icsadvprj/ICS-Advisory-Project)
- **CSAF 2.0** JSON advisories — machine-readable feed for the retrieval layer.

**Deterministic analyzer (the grounding):**
- **iec-checker** — open-source static analyzer for IEC 61131-3 programs
  (github.com/jubnzv/iec-checker). This is the SAST half of the hybrid.
- Optional later: symbolic-execution ST analysis (IEEE 10831127) for deeper paths.

**LLM (no fine-tune in Phase 1):**
- One open code model — **Qwen2.5-Coder** (or DeepSeek-R1 class) — served via vLLM.
- One **frontier model** as the head-to-head baseline to beat.

### 6.2 Pipeline to build this week

```
ST program ──► iec-checker ──► candidate findings (grounded locations)
     │                                │
     └────────────► LLM triage ◄──────┘   (LLM judges each candidate:
                         │                 real? severity? explanation? fix?)
                         ▼
                 Verification filter ──► drop findings with no grounded location
                         │
                         ▼
                 Report + score vs labels
```

Key rule: **the LLM only triages/explains candidates the analyzer surfaced** — it
does not free-scan. That is the 94–98% FP-reduction recipe from the literature.

### 6.3 Three arms to compare (the experiment)

| Arm | What it is | Expected |
|---|---|---|
| **A** | Frontier model, free-scan, no grounding | High recall, **bad precision** |
| **B** | iec-checker alone | Good precision, **limited recall** |
| **C** | Hybrid (iec-checker → LLM triage → verify) | **Best precision-at-recall** |

Thesis confirmed if **C beats A** on precision-at-fixed-recall and FP-rate.

### 6.4 Eval harness (what to build)

- `ingest.py` — load PLC-BEAD ST + labels into a common schema.
- `analyzer.py` — run iec-checker, normalise findings to `{file, line, type}`.
- `triage.py` — prompt LLM per candidate → `{is_real, severity, why, fix}`.
- `verify.py` — drop ungrounded findings; merge analyzer + LLM verdicts.
- `eval.py` — compute **precision, recall, F1, FP-rate** per arm; emit a table.
- `report.py` — render findings (location / severity / explanation / fix).
- Held-out split fixed up front; never used for any prompt tuning.

### 6.5 Definition of done (week 1)
- Table of A vs B vs C on the held-out split, with FP-rate as the headline.
- A go/no-go call: does grounding beat the frontier model? If yes → Phase 2 data
  assembly. If no → iterate grounding before any training spend.

