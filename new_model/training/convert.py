"""Phase 2 converter: labeled ST programs -> instruction/response training pairs.

Input: a dataset dir in baseline format (*.st + labels.json), optionally enriched
with explanations/fixes via a fixes.json sidecar:
    { "<name>.st": { "<line>": {"explanation": "...", "fix": "..."} } }
If no explanation/fix is supplied, a CWE-derived default is used (curate later).

Output: train.jsonl / val.jsonl in chat format (prompts.to_chat_record).

This reuses baseline.ingest so the schema never diverges.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Allow importing the baseline package alongside training/.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "baseline"))

import ingest  # noqa: E402  (from baseline/)
import prompts  # noqa: E402

# Minimal CWE -> generic remediation, used when no curated fix is supplied.
CWE_DEFAULTS = {
    "CWE-787": ("Out-of-bounds write: an index can exceed the array's declared range.",
                "Bounds-check the index against the array limits before writing."),
    "CWE-369": ("Division by zero: the divisor can be zero at runtime.",
                "Guard the division with a check that the divisor is non-zero."),
    "CWE-457": ("Use of uninitialized variable.",
                "Initialize the variable in its VAR declaration before use."),
    "CWE-190": ("Integer overflow in arithmetic on a bounded type.",
                "Use a wider type or validate operands before the operation."),
    "CWE-835": ("Loop with unreachable exit condition (possible infinite loop).",
                "Ensure the loop has a guaranteed terminating condition."),
}


def _load_fixes(dataset_path: str) -> dict:
    p = os.path.join(dataset_path, "fixes.json")
    if os.path.exists(p):
        with open(p) as fh:
            return json.load(fh)
    return {}


def _finding_dict(label, fixes_for_file: dict) -> dict:
    entry = fixes_for_file.get(str(label.line), {})
    expl, fix = CWE_DEFAULTS.get(label.cwe, ("Potential security issue.",
                                             "Review and remediate per CWE guidance."))
    return {
        "line": label.line,
        "cwe": label.cwe,
        "severity": label.severity,
        "explanation": entry.get("explanation", expl),
        "fix": entry.get("fix", fix),
    }


def build_records(cfg: dict):
    programs = ingest.load(cfg)
    # Use the SAME fixed split as the baseline: only the train half becomes
    # training data; the eval half is held out and never trained on.
    train, _val_holdout = ingest.holdout_split(
        programs, cfg["ingest"]["holdout_seed"], cfg["ingest"]["holdout_frac"]
    )
    fixes = _load_fixes(cfg["ingest"]["dataset_path"])
    records = []
    for p in train:
        findings = [_finding_dict(l, fixes.get(p.pid, {})) for l in p.labels]
        records.append(prompts.to_chat_record(p.source, findings))
    return records, len(programs), len(train)


def main() -> None:
    import yaml

    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join("..", "baseline", "config.yaml"))
    ap.add_argument("--out-dir", default="data")
    args = ap.parse_args()
    with open(args.config) as fh:
        cfg = yaml.safe_load(fh)
    # ingest paths are relative to the baseline dir; resolve them.
    base = os.path.join(os.path.dirname(__file__), "..", "baseline")
    cfg["ingest"]["dataset_path"] = os.path.join(base, cfg["ingest"]["dataset_path"])

    records, n_all, n_train = build_records(cfg)
    os.makedirs(args.out_dir, exist_ok=True)
    out = os.path.join(args.out_dir, "train.jsonl")
    with open(out, "w") as fh:
        fh.write(prompts.dumps_jsonl(records))
    print(f"built {len(records)} training records from {n_train}/{n_all} programs "
          f"(eval half held out) -> {out}")


if __name__ == "__main__":
    main()
