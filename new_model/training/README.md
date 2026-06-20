# Phase 2–3 — Training data pipeline & 7B proof-of-concept

Turns labeled PLC programs into a curated instruction/response set, then QLoRA
fine-tunes a 7B as the **gate**: if a small fine-tune + the hybrid shows no edge
over a general model, fix the *data* here cheaply before scaling to 20B.

## Pipeline

```
labeled ST (baseline/data/...)        ICS Advisory CSV
        │ convert.py                         │ retrieval/cve_index.py build
        ▼                                     ▼
   data/train.jsonl                     retrieval/index.json
        │ curate.py                          (live known-CVE correlation)
        ▼
 data/train.curated.jsonl + data/val.jsonl
        │ axolotl (qlora_7b.yaml)
        ▼
   out/qlora-7b-poc/  → evaluate via baseline/run.py (triage.provider=vllm)
```

## Steps

```bash
cd new_model/training

# 1. Build training pairs from the SAME split as the baseline (eval half held out)
python convert.py --config ../baseline/config.yaml --out-dir data

# 2. Curate: dedup + carve a training-time val split
python curate.py --in data/train.jsonl --out-dir data

# 3. (parallel) Build the live-CVE index
python ../retrieval/cve_index.py build --csv ICS-CERT_ADV.csv --out ../retrieval/index.json

# 4. Fine-tune the 7B proof (single 24-48GB GPU, spot instance)
pip install axolotl
accelerate launch -m axolotl.cli.train qlora_7b.yaml

# 5. Serve the adapter with vLLM, point baseline config triage.provider=vllm,
#    and re-run baseline/run.py to measure the fine-tuned hybrid vs frontier.
```

## The gate (do not skip)

Proceed to the 14–32B fine-tune **only if** step 5 shows the fine-tuned hybrid
beats the general frontier model on precision-at-recall + FP-rate on the held-out
eval split. Otherwise the bottleneck is data quality — iterate `fixes.json`
curation and labels, not model size.

## Scope

Detection / explanation / remediation only. The training data teaches the model
to *report and fix* vulnerabilities, never to exploit them.
