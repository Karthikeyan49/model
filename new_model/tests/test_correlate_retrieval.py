"""Tests for the retrieval index and correlation engine."""
import cve_index
import correlate


def _index():
    raw = {
        "openplc": [
            {"vendor": "OpenPLC", "product": "OpenPLC v3", "cve": "CVE-1",
             "cwe": "CWE-787", "cvss": "9.8", "advisory": "A1"},
            {"vendor": "OpenPLC", "product": "OpenPLC Runtime", "cve": "CVE-2",
             "cwe": "CWE-306", "cvss": "8.1", "advisory": "A2"},
        ],
        "openplc v3": [
            {"vendor": "OpenPLC", "product": "OpenPLC v3", "cve": "CVE-1",
             "cwe": "CWE-787", "cvss": "9.8", "advisory": "A1"},
        ],
        "schneider": [
            {"vendor": "Schneider", "product": "M340", "cve": "CVE-9",
             "cwe": "CWE-22", "cvss": "7.5", "advisory": "A9"},
        ],
    }
    return raw


def test_lookup_unions_vendor_wide():
    idx = _index()
    cves = {a["cve"] for a in cve_index.lookup(idx, "OpenPLC v3")}
    assert cves == {"CVE-1", "CVE-2"}          # product + vendor-wide
    assert "CVE-9" not in cves                  # other vendor excluded


def test_lookup_dedups_by_cve():
    idx = _index()
    hits = cve_index.lookup(idx, "openplc")
    assert len(hits) == len({h["cve"] for h in hits})


def test_correlation_boosts_matching_cwe():
    idx = _index()
    manifest = {
        "components": [{"vendor": "OpenPLC", "product": "OpenPLC v3"}],
        "code_findings": [
            {"pid": "p.st", "line": 6, "cwe": "CWE-787", "severity": "high",
             "explanation": "oob", "fix": "clamp"},
            {"pid": "p.st", "line": 9, "cwe": "CWE-561", "severity": "low",
             "explanation": "dead", "fix": "remove"},
        ],
    }
    exposures = correlate.correlate(manifest, idx)
    # the CWE-787 code finding must be corroborated and ranked first
    top = exposures[0]
    assert top["kind"] == "code-finding"
    assert top["corroborated_by_code"] is True
    assert "CVE-1" in top["corroborating_cves"]
    assert top["severity"] == "critical"        # bumped from high
    # uncorroborated low finding ranks last
    assert exposures[-1]["cwe"] == "CWE-561"


def test_sev_from_cvss():
    assert correlate._sev_from_cvss(9.9) == "critical"
    assert correlate._sev_from_cvss(7.0) == "high"
    assert correlate._sev_from_cvss(4.0) == "medium"
    assert correlate._sev_from_cvss(0.0) == "info"
