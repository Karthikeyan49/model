# Cybersecurity Specialist Model

A domain-specialist system that aims to **beat frontier models on defensive
cybersecurity** in a narrow slice (OT/PLC first), on one shared engine that
expands to more domains. See [plan.md](plan.md) for the full strategy and
build status.

## Scope (fixed)

Detection · correlation · reachability/exploitability *reasoning* · remediation ·
authorized validation only. **No exploit-generation / weaponization** — by design.

## How the pieces fit

```
            ┌── baseline/ ───────────────┐     ┌── retrieval/ ──────┐
target ───▶ │ analyzer → LLM triage →    │     │ ICS Advisory CSV → │
            │ verify (drop ungrounded)   │     │ component→CVE index│
            └────────────┬───────────────┘     └─────────┬──────────┘
                         │ code findings                  │ known CVEs
                         ▼                                 ▼
                   ┌── engine/correlate.py ──────────────────┐
                   │ cross-layer correlation + risk ranking   │
                   └──────────────────┬──────────────────────┘
                                      ▼
                          prioritised exposure report
```

## Directory map

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system diagram.

| Dir | Purpose | Entry point |
|---|---|---|
| [baseline/](baseline/) | Phase 1 hybrid baseline + FP-hardening sweep | `run.py`, `sweep.py` |
| [advanced/](advanced/) | Conformal abstention · self-consistency · dataflow taint · ensemble · per-CWE LoRA MoE | `pipeline.py` |
| [training/](training/) | Phase 2 data pipeline + Phase 3 QLoRA config | `convert.py`, `curate.py`, `qlora_7b.yaml` |
| [retrieval/](retrieval/) | Live known-CVE correlation index | `cve_index.py` |
| [engine/](engine/) | Phase 4 cross-layer correlation engine | `correlate.py` |
| [scan.py](scan.py) | Unified scan CLI (markdown + SARIF) | `scan.py` |

## Run the whole thing on mock data (zero setup)

```bash
cd baseline && python run.py --config config.yaml   # A/B/C arms + go/no-go
python sweep.py --config config.yaml                # precision/recall curve

cd ../training && python convert.py --config ../baseline/config.yaml --out-dir data
python curate.py --in data/train.jsonl --out-dir data
```

## Go-live checklist (real assets, not code)

1. Import PLC-BEAD: `baseline/download_plc_bead.py --source <repo/dir/zip>`.
2. Install **iec-checker**; extend `baseline/rule_map.json`.
3. Wire a real LLM: set `triage.provider` (anthropic/vllm) in `baseline/config.yaml`.
4. Build CVE index: `retrieval/cve_index.py build --csv ICS-CERT_ADV.csv`.
5. Run the **gate** (Phase 3 fine-tune → re-eval). Scale to 14–32B only if the
   fine-tuned hybrid beats frontier on precision-at-recall.
