"""Phase 4 — cross-layer correlation engine (the key differentiator).

Combines two evidence sources into one prioritised exposure list:
  1. CODE findings  — from the hybrid analyzer+LLM (baseline pipeline).
  2. COMPONENT findings — known CVEs for declared dependencies/firmware/products,
     via the live retrieval index (retrieval/cve_index.py).

A general frontier model does not do this out of the box: it sees code OR a CVE
feed, not the correlated exposure. Correlation = combine + prioritise:
  - boost severity when a code weakness lines up with a known-CVE component
    (CWE match = strong corroboration),
  - rank by a transparent risk score (severity x corroboration x exploit-known).

Input target manifest (JSON):
  {
    "components": [ {"vendor": "OpenPLC", "product": "OpenPLC v3", "version": "3.0"} ],
    "code_findings": [ {"pid": "...", "line": 6, "cwe": "CWE-787",
                        "severity": "high", "explanation": "...", "fix": "..."} ]
  }
(code_findings is exactly baseline Finding output; produce it with baseline/run.py.)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "retrieval"))
import cve_index  # noqa: E402

SEV_SCORE = {"info": 0.2, "low": 0.4, "medium": 0.6, "high": 0.8, "critical": 1.0}


def _cvss_float(s: str) -> float:
    try:
        return float(s)
    except (TypeError, ValueError):
        return 0.0


def correlate(manifest: dict, index: dict) -> list[dict]:
    exposures: list[dict] = []

    # 1. Component-level: look up known CVEs for each declared component.
    component_cwes: dict[str, list[dict]] = {}
    for comp in manifest.get("components", []):
        query = comp.get("product") or comp.get("vendor", "")
        advisories = cve_index.lookup(index, query) if query else []
        for adv in advisories:
            component_cwes.setdefault(adv.get("cwe", ""), []).append(adv)
            exposures.append({
                "kind": "component-cve",
                "component": query,
                "cve": adv.get("cve"),
                "cwe": adv.get("cwe"),
                "cvss": _cvss_float(adv.get("cvss")),
                "severity": _sev_from_cvss(_cvss_float(adv.get("cvss"))),
                "corroborated_by_code": False,
                "explanation": f"Known CVE {adv.get('cve')} affects {query}.",
                "fix": "Upgrade/patch the component to a fixed version.",
            })

    # 2. Code-level + correlation: a code weakness whose CWE matches a known-CVE
    #    on a declared component is a corroborated, prioritised exposure.
    for cf in manifest.get("code_findings", []):
        corroborating = component_cwes.get(cf.get("cwe", ""), [])
        boosted = bool(corroborating)
        exposures.append({
            "kind": "code-finding",
            "location": f"{cf.get('pid', '?')}:{cf.get('line', '?')}",
            "cwe": cf.get("cwe"),
            "severity": _bump(cf.get("severity", "medium")) if boosted else cf.get("severity", "medium"),
            "corroborated_by_code": boosted,
            "corroborating_cves": [a.get("cve") for a in corroborating],
            "explanation": cf.get("explanation", ""),
            "fix": cf.get("fix", ""),
        })

    for e in exposures:
        e["risk"] = _risk(e)
    exposures.sort(key=lambda e: e["risk"], reverse=True)
    return exposures


def _sev_from_cvss(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _bump(sev: str) -> str:
    order = ["info", "low", "medium", "high", "critical"]
    i = order.index(sev) if sev in order else 2
    return order[min(i + 1, len(order) - 1)]


def _risk(e: dict) -> float:
    base = SEV_SCORE.get(e.get("severity", "medium"), 0.6)
    corroboration = 1.3 if e.get("corroborated_by_code") else 1.0
    exploit_known = 1.2 if e.get("kind") == "component-cve" else 1.0
    return round(base * corroboration * exploit_known, 3)


def render(exposures: list[dict]) -> str:
    if not exposures:
        return "No exposures correlated.\n"
    lines = ["# Correlated exposures (prioritised)\n"]
    for i, e in enumerate(exposures, 1):
        loc = e.get("location") or e.get("component") or "?"
        tag = " [CORROBORATED]" if e.get("corroborated_by_code") else ""
        lines.append(
            f"## {i}. risk={e['risk']} — {e['cwe']} ({e['severity']}){tag}\n"
            f"- Where: {loc} ({e['kind']})\n"
            + (f"- Corroborating CVEs: {', '.join(c for c in e.get('corroborating_cves', []) if c)}\n"
               if e.get("corroborating_cves") else "")
            + (f"- CVE: {e['cve']} (CVSS {e['cvss']})\n" if e.get("cve") else "")
            + f"- Why: {e['explanation']}\n- Fix: {e['fix']}\n"
        )
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True, help="target manifest JSON")
    ap.add_argument("--index", required=True, help="retrieval index.json")
    ap.add_argument("--out", default="correlated_report.md")
    args = ap.parse_args()
    with open(args.manifest) as fh:
        manifest = json.load(fh)
    index = cve_index.load(args.index)
    exposures = correlate(manifest, index)
    report = render(exposures)
    with open(args.out, "w") as fh:
        fh.write(report)
    print(report)
    print(f"[engine] {len(exposures)} exposures -> {args.out}")


if __name__ == "__main__":
    main()
