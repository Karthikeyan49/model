"""Unified scan CLI — Phase 6 interface.

Runs the full defensive pipeline over a target directory of IEC 61131-3 ST files:

    analyzer (grounding) -> LLM triage -> verify -> reachability
        -> [optional] CVE correlation -> report (markdown + SARIF)

Defensive only: detects, explains, prioritises, and suggests fixes. No exploit
generation.

Usage:
  python scan.py --target path/to/st_dir
  python scan.py --target path/to/st_dir --manifest components.json --index retrieval/index.json
  python scan.py --target path/to/st_dir --sarif out.sarif --config baseline/config.yaml
"""
from __future__ import annotations

import argparse
import json
import os
import sys

BASE = os.path.dirname(__file__)
for sub in ("baseline", "retrieval", "engine"):
    sys.path.insert(0, os.path.join(BASE, sub))

import analyzer            # noqa: E402
import ingest              # noqa: E402
import reachability        # noqa: E402
import report as reporter  # noqa: E402
import sarif               # noqa: E402
import triage              # noqa: E402
import verify              # noqa: E402


def _load_cfg(path: str) -> dict:
    import yaml
    with open(path) as fh:
        return yaml.safe_load(fh)


def scan(target: str, cfg: dict):
    cfg = json.loads(json.dumps(cfg))  # shallow copy
    cfg["ingest"]["dataset"] = "sample"
    cfg["ingest"]["dataset_path"] = target
    programs = ingest.load(cfg)
    if not programs:
        print(f"no .st programs under {target}")
        return [], programs

    candidates = analyzer.analyze(programs, cfg)
    triaged = triage.triage_candidates(candidates, programs, cfg)
    grounded = verify.verify(triaged, cfg)
    findings = reachability.annotate(grounded, programs)
    return findings, programs


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="dir of .st files (and labels.json if scoring)")
    ap.add_argument("--config", default=os.path.join(BASE, "baseline", "config.yaml"))
    ap.add_argument("--manifest", help="component manifest JSON for CVE correlation")
    ap.add_argument("--index", help="retrieval index.json for CVE correlation")
    ap.add_argument("--out", default="scan_report.md")
    ap.add_argument("--sarif", help="also write SARIF to this path")
    args = ap.parse_args()

    cfg = _load_cfg(args.config)
    findings, programs = scan(args.target, cfg)
    print(f"[scan] {len(programs)} programs, {len(findings)} findings after "
          "triage+verify+reachability")

    md = reporter.render_findings(findings)

    # Optional cross-layer CVE correlation
    if args.manifest and args.index:
        import correlate
        import cve_index
        with open(args.manifest) as fh:
            manifest = json.load(fh)
        manifest.setdefault("code_findings", [])
        manifest["code_findings"] += [
            {"pid": f.pid, "line": f.line, "cwe": f.cwe, "severity": f.severity,
             "explanation": f.explanation, "fix": f.fix} for f in findings
        ]
        exposures = correlate.correlate(manifest, cve_index.load(args.index))
        md += "\n\n" + correlate.render(exposures)
        print(f"[scan] correlated into {len(exposures)} prioritised exposures")

    with open(args.out, "w") as fh:
        fh.write(md)
    print(f"[scan] markdown report -> {args.out}")

    if args.sarif:
        sarif.write_sarif(findings, args.sarif)
        print(f"[scan] SARIF -> {args.sarif}")


if __name__ == "__main__":
    main()
