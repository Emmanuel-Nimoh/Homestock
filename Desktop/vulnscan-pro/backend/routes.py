"""
Flask API routes for SentinelScan.

Endpoints
---------
POST  /api/scan/web-api             Start a web API security scan
POST  /api/scan/dependencies        Start a dependency vulnerability scan
GET   /api/scan/<scan_id>           Get scan results (with vulnerabilities)
GET   /api/compliance/report/<id>  Get PCI-DSS compliance report for a scan
GET   /api/reports/pdf/<scan_id>   Download PDF report (generates on demand)
GET   /api/scans                    List scan history (?limit=10&offset=0)
"""

import logging
import os
import threading
from datetime import datetime, timezone
from functools import wraps

from flask import Blueprint, current_app, jsonify, request, send_file

from database import db
from models import ComplianceMapping, Scan, Vulnerability
from scanners.api_scanner import scan_web_api
from scanners.compliance import build_compliance_report, map_to_pci_dss, pci_requirement_title
from scanners.dependency_scanner import scan_dependencies
from utils.report_generator import generate_pdf_report
from utils.validators import (
    validate_dependency_payload,
    validate_pagination,
    validate_web_api_payload,
)

logger = logging.getLogger(__name__)
api = Blueprint("api", __name__, url_prefix="/api")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _error(message: str, code: str = "ERROR", status: int = 400):
    return jsonify({"error": message, "error_code": code, "status_code": status}), status


def _now():
    return datetime.now(timezone.utc)


# Simple in-memory rate limiter (per-IP, resets when the process restarts)
_scan_timestamps: dict[str, list] = {}
_rate_lock = threading.Lock()


def _rate_limit(ip: str, limit: int, window_seconds: int = 3600) -> bool:
    """Return True if the request should be blocked."""
    now = _now().timestamp()
    with _rate_lock:
        times = _scan_timestamps.get(ip, [])
        times = [t for t in times if now - t < window_seconds]
        if len(times) >= limit:
            return True
        times.append(now)
        _scan_timestamps[ip] = times
    return False


def _persist_findings(scan: Scan, findings: list[dict]) -> None:
    """Save scanner findings as Vulnerability + ComplianceMapping rows."""
    for f in findings:
        vuln = Vulnerability(
            scan_id=scan.id,
            vuln_type=f.get("vuln_type", "unknown"),
            severity=f.get("severity", "low"),
            title=f.get("title", ""),
            description=f.get("description"),
            remediation=f.get("remediation"),
            affected_component=f.get("affected_component"),
            cve_id=f.get("cve_id"),
            cvss_score=f.get("cvss_score"),
        )
        db.session.add(vuln)
        db.session.flush()  # get vuln.id

        # Map to PCI-DSS requirements
        from scanners.compliance import PCI_REQUIREMENTS
        for req_id, meta in PCI_REQUIREMENTS.items():
            if f.get("vuln_type") in meta.get("vuln_types", set()):
                db.session.add(ComplianceMapping(
                    vulnerability_id=vuln.id,
                    pci_requirement=req_id,
                    requirement_title=meta["title"],
                    status="open",
                ))


def _run_api_scan(app, scan_id: int, url: str, scan_depth: str) -> None:
    """Background thread: run the API scanner and persist results."""
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return

        scan.status = "in_progress"
        scan.started_at = _now() if hasattr(scan, "started_at") else None
        db.session.commit()

        try:
            result = scan_web_api(url, scan_depth=scan_depth,
                                  timeout=app.config.get("SCAN_TIMEOUT", 30))

            if result.get("error") and not result.get("findings"):
                scan.status = "failed"
                scan.summary = result["error"]
            else:
                _persist_findings(scan, result.get("findings", []))
                scan.status = "completed"
                scan.risk_score = result.get("risk_score", 0)
                scan.summary = (
                    f"{len(result.get('findings', []))} findings detected. "
                    f"Risk score: {result.get('risk_score', 0)}/100."
                )

        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("API scan %d failed", scan_id)
            scan.status = "failed"
            scan.summary = str(exc)

        db.session.commit()


def _run_dependency_scan(app, scan_id: int, repo_url: str, package_type: str, packages) -> None:
    """Background thread: run the dependency scanner and persist results."""
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            return

        scan.status = "in_progress"
        db.session.commit()

        try:
            result = scan_dependencies(
                repo_url=repo_url or None,
                package_type=package_type,
                packages=packages or None,
                github_token=app.config.get("GITHUB_TOKEN"),
            )

            if result.get("error") and not result.get("packages"):
                scan.status = "failed"
                scan.summary = result["error"]
            else:
                # Convert dependency vulns to the standard finding format
                findings = []
                for pkg in result.get("packages", []):
                    for v in pkg.get("vulnerabilities", []):
                        findings.append({
                            "vuln_type": "vulnerable_package",
                            "severity": v.get("severity", "medium"),
                            "title": (
                                f"Vulnerable Dependency: {pkg['name']}@{pkg['current_version']}"
                            ),
                            "description": v.get("description", ""),
                            "remediation": (
                                f"Upgrade {pkg['name']} to "
                                f"{v.get('patched_version') or 'the latest secure version'}."
                            ),
                            "affected_component": f"{pkg['name']}@{pkg['current_version']}",
                            "cve_id": v.get("cve_id"),
                            "cvss_score": v.get("cvss_score"),
                        })

                _persist_findings(scan, findings)
                scan.status = "completed"
                scan.risk_score = min(
                    result["critical_count"] * 40 + result["high_count"] * 20 +
                    result["medium_count"] * 8 + result["low_count"] * 3,
                    100,
                )
                scan.summary = (
                    f"{result['total_vulnerabilities']} vulnerabilities in "
                    f"{result.get('vulnerable_packages_count', len(set(p['name'] for p in result.get('packages', []))))} "
                    f"packages."
                )

        except Exception as exc:  # pylint: disable=broad-except
            logger.exception("Dependency scan %d failed", scan_id)
            scan.status = "failed"
            scan.summary = str(exc)

        db.session.commit()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@api.post("/scan/web-api")
def start_web_api_scan():
    """POST /api/scan/web-api — start an API security scan."""
    data = request.get_json(silent=True) or {}

    ok, err = validate_web_api_payload(data)
    if not ok:
        return _error(err, "INVALID_INPUT", 400)

    ip = request.remote_addr or "unknown"
    limit = current_app.config.get("RATE_LIMIT_SCANS", 10)
    if _rate_limit(ip, limit):
        return _error(
            "Rate limit exceeded. Please wait before starting another scan.",
            "RATE_LIMITED", 429,
        )

    url = data["url"].strip()
    scan_depth = data.get("scan_depth", "full")

    scan = Scan(scan_type="api", target=url, status="pending")
    db.session.add(scan)
    db.session.commit()

    thread = threading.Thread(
        target=_run_api_scan,
        args=(current_app._get_current_object(), scan.id, url, scan_depth),
        daemon=True,
    )
    thread.start()

    logger.info("Started API scan %d for %s", scan.id, url)
    return jsonify({"scan_id": scan.id, "status": "in_progress", "message": "Scan started"}), 202


@api.post("/scan/dependencies")
def start_dependency_scan():
    """POST /api/scan/dependencies — start a dependency vulnerability scan."""
    data = request.get_json(silent=True) or {}

    ok, err = validate_dependency_payload(data)
    if not ok:
        return _error(err, "INVALID_INPUT", 400)

    ip = request.remote_addr or "unknown"
    if _rate_limit(ip, current_app.config.get("RATE_LIMIT_SCANS", 10)):
        return _error("Rate limit exceeded.", "RATE_LIMITED", 429)

    repo_url = (data.get("repo_url") or "").strip()
    package_type = data.get("package_type", "auto")
    packages = data.get("packages")
    target = repo_url or f"inline-packages ({len(packages or [])} items)"

    scan = Scan(scan_type="dependency", target=target, status="pending")
    db.session.add(scan)
    db.session.commit()

    thread = threading.Thread(
        target=_run_dependency_scan,
        args=(current_app._get_current_object(), scan.id, repo_url, package_type, packages),
        daemon=True,
    )
    thread.start()

    logger.info("Started dependency scan %d for %s", scan.id, target)
    return jsonify({"scan_id": scan.id, "status": "in_progress", "message": "Dependency scan started"}), 202


@api.get("/scan/<int:scan_id>")
def get_scan(scan_id: int):
    """GET /api/scan/<scan_id> — retrieve scan with all vulnerability details."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return _error(f"Scan {scan_id} not found.", "NOT_FOUND", 404)

    vulns = [v.to_dict() for v in scan.vulnerabilities]

    # Build inline compliance_status from vuln data
    pci_map = map_to_pci_dss(scan.vulnerabilities)
    compliance_status = {
        f"requirement_{req_id.replace('.', '_')}": data["status"]
        for req_id, data in pci_map.items()
    }

    result = scan.to_dict(include_vulns=False)
    result["vulnerabilities"] = vulns
    result["compliance_status"] = {"pci_dss": compliance_status}

    return jsonify(result)


@api.get("/compliance/report/<int:scan_id>")
def get_compliance_report(scan_id: int):
    """GET /api/compliance/report/<scan_id> — full PCI-DSS compliance report."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return _error(f"Scan {scan_id} not found.", "NOT_FOUND", 404)

    if scan.status != "completed":
        return _error(
            f"Scan is not yet complete (status: {scan.status}).",
            "SCAN_NOT_COMPLETE", 409,
        )

    report = build_compliance_report(scan_id, list(scan.vulnerabilities))
    return jsonify(report)


@api.get("/reports/pdf/<int:scan_id>")
def download_pdf_report(scan_id: int):
    """GET /api/reports/pdf/<scan_id> — generate and stream a PDF report."""
    scan = db.session.get(Scan, scan_id)
    if not scan:
        return _error(f"Scan {scan_id} not found.", "NOT_FOUND", 404)

    if scan.status != "completed":
        return _error(
            f"Scan is not yet complete (status: {scan.status}).",
            "SCAN_NOT_COMPLETE", 409,
        )

    reports_dir = current_app.config.get("REPORTS_DIR", "reports")
    pdf_path = os.path.join(reports_dir, f"scan_{scan_id}.pdf")

    try:
        vulns = [v.to_dict() for v in scan.vulnerabilities]
        compliance = build_compliance_report(scan_id, list(scan.vulnerabilities))
        generate_pdf_report(scan.to_dict(), vulns, compliance, pdf_path)
    except RuntimeError as exc:
        return _error(str(exc), "PDF_UNAVAILABLE", 503)
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("PDF generation failed for scan %d", scan_id)
        return _error("Failed to generate PDF report.", "INTERNAL_ERROR", 500)

    return send_file(
        pdf_path,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"sentinelscan_report_{scan_id}.pdf",
    )


@api.get("/scans")
def list_scans():
    """GET /api/scans?limit=10&offset=0 — paginated scan history."""
    limit_str = request.args.get("limit", "10")
    offset_str = request.args.get("offset", "0")

    ok, err, limit, offset = validate_pagination(limit_str, offset_str)
    if not ok:
        return _error(err, "INVALID_INPUT", 400)

    total = db.session.query(Scan).count()
    scans = (
        db.session.query(Scan)
        .order_by(Scan.created_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )

    return jsonify({
        "scans": [s.to_dict() for s in scans],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@api.get("/health")
def health():
    return jsonify({"status": "ok", "service": "sentinelscan-api"})
