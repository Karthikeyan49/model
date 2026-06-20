# Phase 1 — OT/PLC Hybrid Baseline (zero-training)

Goal: prove that **static analyzer (iec-checker) + off-the-shelf LLM triage**
beats a bare frontier model on PLC (IEC 61131-3 Structured Text) vulnerability
detection — measured on **precision-at-recall + false-positive rate**, with
**no fine-tuning**.

Scope: detection / triage / explanation / remediation only. No exploit generation.

## The experiment (three arms)

| Arm | What it is | Hypothesis |
|---|---|---|
| **A** | LLM free-scan, no grounding | high recall, bad precision |
| **B** | iec-checker alone | good precision, limited recall |
| **C** | Hybrid: iec-checker → LLM triage → verify | best precision-at-recall |

Thesis confirmed if **C beats A** on precision-at-fixed-recall and FP-rate.

## Pipeline

```
ingest → analyzer (iec-checker) → triage (LLM) → verify → eval → report
```

## Quick start

```bash
cd new_model/baseline
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Runs end-to-end on bundled sample data using mock backends
# (no iec-checker / no LLM key required) so you can see the harness work:
python run.py --config config.yaml
```

Then wire the real backends:
- Install **iec-checker** and set `analyzer.binary` in `config.yaml`.
- Set `triage.provider` + `ANTHROPIC_API_KEY` (or a vLLM endpoint) for real LLM
  triage, and `baseline.frontier_*` for the Arm-A comparison.
- Download **PLC-BEAD** into `data/plc_bead/` and point `ingest.dataset_path` at it.

## Layout

```
baseline/
  config.yaml      # all knobs: dataset, analyzer, LLM, eval thresholds
  schema.py        # shared dataclasses: Program, Finding, Verdict, Result
  ingest.py        # load ST programs + ground-truth labels
  analyzer.py      # run iec-checker, normalise findings
  triage.py        # LLM judges each candidate (real? severity? why? fix?)
  verify.py        # drop ungrounded findings, merge analyzer+LLM verdicts
  eval.py          # precision / recall / F1 / FP-rate per arm
  report.py        # render findings (location/severity/explanation/fix)
  run.py           # orchestrator: runs arms A/B/C and prints the table
  data/sample/     # tiny bundled ST + labels for a smoke test
```

## Definition of done (week 1)

A table of A vs B vs C on a fixed held-out split, FP-rate as headline, and a
documented go/no-go: does grounding beat the frontier model?
