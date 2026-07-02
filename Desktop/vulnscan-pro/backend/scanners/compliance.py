"""
PCI-DSS Compliance Mapper
--------------------------
Maps vulnerability types to PCI-DSS v4.0 requirements and produces a
structured compliance report for a given scan.

Requirement coverage (spec table)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
6.5.1  – SQL Injection, XSS
6.5.7  – XSS / CSP
11.2   – Automated scanning (always passes when a scan is run)
4.1    – Encryption / TLS
2.1    – Default credentials / hardcoded secrets
2.2.4  – System configuration (outdated servers, weak ciphers)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PCI-DSS requirement definitions
# ---------------------------------------------------------------------------

PCI_REQUIREMENTS: dict[str, dict] = {
    "4.1": {
        "title": "Use strong cryptography for data in transit",
        "description": (
            "All cardholder data transmitted over open, public networks must be "
            "protected with strong cryptography (TLS 1.2+)."
        ),
        "vuln_types": {
            "expired_cert", "invalid_cert", "self_signed_cert",
            "expiring_cert_soon", "missing_hsts", "weak_hsts",
        },
        "category": "Encryption",
    },
    "2.1": {
        "title": "Do not use vendor-supplied defaults for passwords or security parameters",
        "description": "Default credentials must be changed before deployment.",
        "vuln_types": {"default_credentials", "hardcoded_secret"},
        "category": "Secure Defaults",
    },
    "2.2.4": {
        "title": "Configure system components to prevent known vulnerabilities",
        "description": "Disable all unnecessary functionality and patch known vulnerabilities.",
        "vuln_types": {
            "outdated_server", "server_version_disclosure",
            "http_trace_enabled", "deprecated_xxp",
        },
        "category": "System Configuration",
    },
    "6.5.1": {
        "title": "Address common coding vulnerabilities — Injection flaws",
        "description": (
            "Prevent injection flaws (SQL, OS, LDAP) by using validated input, "
            "parameterised queries, and stored procedures."
        ),
        "vuln_types": {"sqli_reflection", "potential_sqli", "command_injection"},
        "category": "Secure Coding",
    },
    "6.5.7": {
        "title": "Address common coding vulnerabilities — XSS",
        "description": (
            "Validate all input and encode all output. Implement Content-Security-Policy."
        ),
        "vuln_types": {
            "xss_reflection", "potential_xss", "missing_csp",
            "missing_xcto", "missing_xfo",
        },
        "category": "Secure Coding",
    },
    "6.5.9": {
        "title": "Protect against CSRF",
        "description": "Implement CSRF tokens and SameSite cookie attributes.",
        "vuln_types": {
            "cors_wildcard", "cors_reflected_origin",
            "cookie_missing_samesite",
        },
        "category": "Secure Coding",
    },
    "6.5.10": {
        "title": "Address broken authentication and session management",
        "description": "Protect credentials and session tokens in cookies.",
        "vuln_types": {
            "cookie_missing_httponly", "cookie_missing_secure",
            "cookie_missing_samesite",
        },
        "category": "Authentication",
    },
    "11.2": {
        "title": "Run internal and external network vulnerability scans regularly",
        "description": (
            "Automated vulnerability scans must be run at least quarterly and after "
            "significant changes."
        ),
        "vuln_types": set(),   # This requirement passes automatically when a scan is performed
        "auto_pass": True,
        "category": "Vulnerability Scanning",
    },
    "6.3.3": {
        "title": "All software components protected from known vulnerabilities",
        "description": (
            "Install applicable security patches/updates. Critical patches within 1 month."
        ),
        "vuln_types": {"outdated_dependency", "vulnerable_package"},
        "category": "Patch Management",
    },
}


# ---------------------------------------------------------------------------
# Mapping helpers
# ---------------------------------------------------------------------------

def map_to_pci_dss(vulnerabilities: list) -> dict:
    """
    Takes a list of Vulnerability ORM objects or dicts.
    Returns a dict keyed by PCI requirement ID.

    {
        '6.5.1': {'status': 'pass' | 'fail', 'findings': [...]},
        ...
    }
    """
    # Normalise to dicts
    vuln_dicts = [
        v.to_dict() if hasattr(v, "to_dict") else v
        for v in vulnerabilities
    ]

    result = {}

    for req_id, meta in PCI_REQUIREMENTS.items():
        if meta.get("auto_pass"):
            result[req_id] = {
                "status": "pass",
                "findings": [],
                "notes": "Automated scan performed — requirement considered met.",
            }
            continue

        mapped = [
            v for v in vuln_dicts
            if (v.get("vuln_type") or v.get("category", "")) in meta["vuln_types"]
        ]

        # Also accept pci_requirement field set on the vuln directly
        direct = [
            v for v in vuln_dicts
            if (v.get("pci_requirement") or "").startswith(req_id)
        ]

        all_mapped = list({v.get("id", id(v)): v for v in mapped + direct}.values())

        critical_or_high = any(
            v.get("severity") in ("critical", "high") for v in all_mapped
        )

        result[req_id] = {
            "status": "fail" if critical_or_high else ("warn" if all_mapped else "pass"),
            "findings": all_mapped,
            "notes": _build_notes(req_id, all_mapped, meta),
        }

    return result


def build_compliance_report(scan_id: int, vulnerabilities: list) -> dict:
    """Return the full compliance report structure expected by the API."""
    mapping = map_to_pci_dss(vulnerabilities)
    total = len(mapping)
    passed = sum(1 for v in mapping.values() if v["status"] == "pass")
    compliance_pct = round(passed / total * 100) if total else 0

    findings = []
    for req_id, data in mapping.items():
        meta = PCI_REQUIREMENTS[req_id]
        findings.append({
            "pci_requirement": req_id,
            "requirement_title": meta["title"],
            "category": meta.get("category", ""),
            "status": "compliant" if data["status"] == "pass" else "non_compliant",
            "vulnerabilities": [
                {
                    "title": v.get("title"),
                    "severity": v.get("severity"),
                    "remediation": v.get("remediation"),
                }
                for v in data["findings"]
            ],
            "notes": data["notes"],
        })

    return {
        "scan_id": scan_id,
        "report_type": "pci_dss_v4",
        "findings": findings,
        "overall_compliance_percentage": compliance_pct,
        "passed_requirements": passed,
        "total_requirements": total,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_notes(req_id: str, findings: list, meta: dict) -> str:
    if not findings:
        if not meta["vuln_types"]:
            return "No applicable checks for this requirement in the current scan type."
        return "No vulnerabilities detected for this requirement."
    titles = [f.get("title", "unknown") for f in findings[:3]]
    more = len(findings) - 3
    note = "Findings: " + "; ".join(titles)
    if more > 0:
        note += f" (+{more} more)"
    return note


def pci_requirement_title(req_id: str) -> Optional[str]:
    return PCI_REQUIREMENTS.get(req_id, {}).get("title")
