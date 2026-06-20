"""Load PLC Structured Text programs + ground-truth labels into the common schema.

Two sources:
  - "sample": the bundled smoke-test set (data/sample/*.st + labels.json)
  - "plc_bead": the PLC-BEAD corpus once downloaded (arXiv 2502.19725)

A held-out split is fixed by seed so the eval set is never tuned on.
"""
from __future__ import annotations

import json
import os
import random
from typing import List, Tuple

from schema import Label, Program


def _load_dir(path: str) -> List[Program]:
    """Load *.st files in `path` with a sibling labels.json:
        { "<filename>.st": [ {"line": 12, "cwe": "CWE-787", "severity": "high"}, ... ] }
    Files with no entry are treated as clean (empty label list).
    """
    labels_file = os.path.join(path, "labels.json")
    labels_map = {}
    if os.path.exists(labels_file):
        with open(labels_file) as fh:
            labels_map = json.load(fh)

    programs: List[Program] = []
    for name in sorted(os.listdir(path)):
        if not name.endswith(".st"):
            continue
        fpath = os.path.join(path, name)
        with open(fpath, encoding="utf-8", errors="replace") as fh:
            source = fh.read()
        labels = [
            Label(line=l["line"], cwe=l["cwe"], severity=l.get("severity", "medium"))
            for l in labels_map.get(name, [])
        ]
        programs.append(Program(pid=name, path=fpath, source=source, labels=labels))
    return programs


def load(cfg: dict) -> List[Program]:
    dataset = cfg["ingest"]["dataset"]
    path = cfg["ingest"]["dataset_path"]
    if dataset == "plc_bead":
        # PLC-BEAD ships ST source per program; adapt its manifest to labels.json
        # during download. Until then we load whatever .st + labels.json exist.
        return _load_dir(path)
    return _load_dir(path)


def holdout_split(
    programs: List[Program], seed: int, frac: float
) -> Tuple[List[Program], List[Program]]:
    """Deterministic train/eval split. Phase 1 only uses the eval half, but the
    split is fixed now so later phases never leak it."""
    rng = random.Random(seed)
    shuffled = programs[:]
    rng.shuffle(shuffled)
    cut = int(len(shuffled) * (1 - frac))
    return shuffled[:cut], shuffled[cut:]


if __name__ == "__main__":
    import yaml

    with open("config.yaml") as fh:
        cfg = yaml.safe_load(fh)
    progs = load(cfg)
    train, evalset = holdout_split(
        progs, cfg["ingest"]["holdout_seed"], cfg["ingest"]["holdout_frac"]
    )
    print(f"loaded {len(progs)} programs; {len(train)} train / {len(evalset)} eval")
    for p in evalset:
        print(f"  eval: {p.pid} ({len(p.labels)} labels)")
