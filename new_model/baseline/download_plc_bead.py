"""Import PLC-BEAD (or any ST corpus) into the baseline's expected layout.

PLC-BEAD (arXiv 2502.19725) ships source/binary pairs, not vulnerability labels.
So this helper does two things:
  1. Collect every .st program from a source (git repo, local dir, or archive)
     into data/plc_bead/.
  2. Build data/plc_bead/labels.json. If the source carries a manifest of known
     issues (CSV or JSON, see --manifest), it is adapted into our label schema.
     Otherwise an EMPTY label skeleton is written for you to fill — programs with
     no labels are treated as clean.

Label schema (per file):
  { "<name>.st": [ {"line": 12, "cwe": "CWE-787", "severity": "high"}, ... ] }

Usage:
  python download_plc_bead.py --source https://github.com/<org>/<plc-bead-repo>.git
  python download_plc_bead.py --source /path/to/local/plc_bead_dir
  python download_plc_bead.py --source corpus.zip
  python download_plc_bead.py --source <dir> --manifest issues.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from collections import defaultdict
from typing import Dict, List

DEST = "data/plc_bead"


def _materialize_source(source: str) -> str:
    """Return a local directory containing the corpus, fetching/extracting if needed."""
    if source.endswith(".git") or source.startswith(("http://", "https://")) and source.endswith(".git"):
        tmp = tempfile.mkdtemp(prefix="plcbead_")
        subprocess.run(["git", "clone", "--depth", "1", source, tmp], check=True)
        return tmp
    if source.endswith(".zip") and os.path.isfile(source):
        tmp = tempfile.mkdtemp(prefix="plcbead_")
        with zipfile.ZipFile(source) as zf:
            zf.extractall(tmp)
        return tmp
    if os.path.isdir(source):
        return source
    raise SystemExit(f"unrecognized source: {source} (expect .git URL, dir, or .zip)")


def _collect_st(root: str, dest: str) -> List[str]:
    os.makedirs(dest, exist_ok=True)
    names: List[str] = []
    for dirpath, _, files in os.walk(root):
        for fn in files:
            if not fn.lower().endswith(".st"):
                continue
            # Flatten with a parent-dir prefix to avoid name collisions.
            parent = os.path.basename(dirpath)
            out_name = f"{parent}__{fn}" if parent else fn
            shutil.copy2(os.path.join(dirpath, fn), os.path.join(dest, out_name))
            names.append(out_name)
    return names


def _load_manifest(path: str) -> Dict[str, List[dict]]:
    """Adapt a CSV/JSON issue manifest into our label schema.
    CSV columns expected: file, line, cwe, severity (severity optional)."""
    labels: Dict[str, List[dict]] = defaultdict(list)
    if path.endswith(".json"):
        with open(path) as fh:
            return json.load(fh)
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            fname = row["file"]
            if not fname.endswith(".st"):
                fname += ".st"
            labels[fname].append({
                "line": int(row["line"]),
                "cwe": row["cwe"],
                "severity": row.get("severity", "medium") or "medium",
            })
    return dict(labels)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, help=".git URL, local dir, or .zip")
    ap.add_argument("--manifest", help="optional CSV/JSON of known issues to label")
    ap.add_argument("--dest", default=DEST)
    args = ap.parse_args()

    root = _materialize_source(args.source)
    names = _collect_st(root, args.dest)
    print(f"collected {len(names)} .st programs into {args.dest}/")

    if args.manifest:
        labels = _load_manifest(args.manifest)
        # Drop labels whose file wasn't collected; warn on missing.
        missing = [f for f in labels if f not in names]
        if missing:
            print(f"  warning: {len(missing)} manifest files not found in corpus")
        labels = {f: labels.get(f, []) for f in names}
    else:
        labels = {f: [] for f in names}
        print("  no manifest: wrote EMPTY label skeleton — fill in known vulns, "
              "or treat all as clean for an FP-only baseline.")

    with open(os.path.join(args.dest, "labels.json"), "w") as fh:
        json.dump(labels, fh, indent=2)
    print(f"wrote {args.dest}/labels.json ({sum(len(v) for v in labels.values())} labels)")
    print("Next: set ingest.dataset: plc_bead and ingest.dataset_path: "
          f"{args.dest} in config.yaml, then `python run.py`.")


if __name__ == "__main__":
    main()
