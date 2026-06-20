"""Provenance & reproducible evidence chain — trust through traceability.

A security finding is only actionable if the owner can see WHY it was raised and
reproduce it. This records, per finding, the full chain of evidence that led to it:

  analyzer rule → self-consistency votes → taint path → ensemble components
    → calibrated threshold → emit/abstain decision

plus a content hash over the inputs + decision, so a finding is reproducible and
tamper-evident (an audit requirement called out in the plan's guardrails). No
hidden model magic: every emitted finding can be explained and replayed.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import List, Optional

from schema import Finding


@dataclass
class Evidence:
    analyzer_rule: Optional[str] = None
    grounded: bool = False
    self_consistency_votes: Optional[str] = None     # e.g. "6/7"
    taint_path: List[str] = field(default_factory=list)
    ensemble_components: dict = field(default_factory=dict)
    threshold: Optional[float] = None
    decision: str = "emit"                            # emit | abstain
    confidence: Optional[float] = None


@dataclass
class ProvenanceRecord:
    pid: str
    line: int
    cwe: str
    severity: str
    evidence: Evidence
    record_hash: str = ""


def _hash(pid: str, line: int, cwe: str, evidence: Evidence) -> str:
    payload = json.dumps(
        {"pid": pid, "line": line, "cwe": cwe, "evidence": asdict(evidence)},
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def build(finding: Finding, evidence: Evidence) -> ProvenanceRecord:
    rec = ProvenanceRecord(finding.pid, finding.line, finding.cwe, finding.severity,
                           evidence)
    rec.record_hash = _hash(finding.pid, finding.line, finding.cwe, evidence)
    return rec


def verify(record: ProvenanceRecord) -> bool:
    """Re-derive the hash to confirm the record wasn't altered."""
    return record.record_hash == _hash(record.pid, record.line, record.cwe,
                                       record.evidence)


def to_json(records: List[ProvenanceRecord]) -> str:
    return json.dumps([asdict(r) for r in records], indent=2)


def render(record: ProvenanceRecord) -> str:
    e = record.evidence
    parts = [f"{record.pid}:{record.line} {record.cwe} ({record.severity}) "
             f"[{record.record_hash}]",
             f"  decision: {e.decision} (conf={e.confidence}, thr={e.threshold})"]
    if e.analyzer_rule:
        parts.append(f"  analyzer: {e.analyzer_rule} (grounded={e.grounded})")
    if e.self_consistency_votes:
        parts.append(f"  votes: {e.self_consistency_votes}")
    if e.taint_path:
        parts.append("  taint: " + " → ".join(e.taint_path))
    if e.ensemble_components:
        comp = ", ".join(f"{k}={v:.2f}" for k, v in e.ensemble_components.items())
        parts.append(f"  signals: {comp}")
    return "\n".join(parts)
