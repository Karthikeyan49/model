# Architecture

End-to-end view of the cybersecurity specialist model. Defensive scope only:
detect · correlate · reason about reachability · remediate · authorized-validate.
No exploit generation.

## System diagram

```
                         ┌────────────────────── TARGET ──────────────────────┐
                         │  PLC ST source · dependency/component manifest      │
                         └───────────────┬─────────────────────────────────────┘
                                         │
                    ┌────────────────────▼─────────────────────┐
                    │ INGESTION (baseline/ingest.py)            │
                    └────────────────────┬─────────────────────┘
                                         │
        ┌────────────────────────────────▼────────────────────────────────┐
        │ GROUNDING — deterministic analyzer (baseline/analyzer.py)        │
        │   iec-checker rules → candidate findings (line, CWE), grounded   │
        └────────────────────────────────┬────────────────────────────────┘
                                         │ candidates
   ┌─────────────────────────────────────▼─────────────────────────────────────┐
   │ ADVANCED REASONING (advanced/)                                             │
   │   self-consistency vote ─┐                                                 │
   │   dataflow taint ────────┤→ ensemble fusion → conformal abstention         │
   │   (mock-court, hard cases)┘            │              │                    │
   │                                    EMIT            ABSTAIN→human review     │
   └────────────────────────────────────┬──────────────────────────────────────┘
                                         │ high-confidence findings
        ┌────────────────────────────────▼────────────────────────────────┐
        │ CORRELATION (engine/correlate.py)  ◄── retrieval/cve_index.py    │
        │   code findings × known component CVEs → prioritised exposures   │
        └────────────────────────────────┬────────────────────────────────┘
                                         │
        ┌────────────────────────────────▼────────────────────────────────┐
        │ REPORTING — markdown (report.py) + SARIF (sarif.py) → CI/CD      │
        └─────────────────────────────────────────────────────────────────┘

   TRAINING (offline):  training/convert.py → curate.py → qlora_7b.yaml
                        advanced/moe_routing.yaml (per-CWE LoRA experts)
```

## Module map

| Layer | Dir | Modules |
|---|---|---|
| Ingestion / grounding | `baseline/` | `ingest`, `analyzer`, `rule_map.json`, `verify` |
| Triage / output | `baseline/` | `triage`, `reachability`, `eval`, `sweep`, `report`, `sarif` |
| Advanced reasoning | `advanced/` | `scoring`, `selfconsistency`, `dataflow`, `ensemble`, `conformal`, `mockcourt`, `router`, `pipeline` |
| Reliability | `advanced/` | `calibration_metrics`, `metamorphic`, `drift`, `active_learning`, `provenance`, `rag_triage`, `regression_gate` |
| Beyond-frontier | `advanced/` | `symbolic` (CWE-787/369/190/191, block-scoped guards), `termination` (CWE-835), `repair`, `interproc` (CWE-refined + sanitization), `variant_hunt` (CWE-787/125), `knowledge_graph`, `deepscan` |
| Retrieval | `retrieval/` | `cve_index` |
| Correlation | `engine/` | `correlate` |
| Training | `training/` | `prompts`, `convert`, `curate`, `qlora_7b.yaml` |
| Interface | top level | `scan.py` (CLI), `Makefile`, CI |
| Tooling / tests | `tools/`, `tests/` | `gen_synthetic`, 93 unit tests |

## Two design invariants

1. **Grounding before generation.** No finding ships unless a deterministic
   analyzer located it. The LLM triages and explains; it does not free-invent.
2. **Abstain over guess.** Under calibrated uncertainty the system routes a
   candidate to human review rather than emitting a low-confidence positive.
   This is the false-positive moat made into an architectural rule.

## Confidence flows as a first-class value

`ScoredFinding(finding, confidence)` is the spine connecting the advanced layers:
self-consistency produces it, ensemble fuses it, conformal thresholds it. Swapping
mock backends for real LLM logprobs changes the *numbers*, not the *wiring*.
