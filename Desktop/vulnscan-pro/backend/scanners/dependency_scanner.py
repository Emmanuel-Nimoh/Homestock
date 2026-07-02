"""
Dependency Vulnerability Scanner
---------------------------------
Fetches package files from a public GitHub repo (or accepts a raw package list),
then queries the OSV.dev API for known vulnerabilities.

Supported package managers
~~~~~~~~~~~~~~~~~~~~~~~~~~~
- npm  (package.json)
- pip  (requirements.txt)
- auto (tries both)
"""

import json
import logging
import re
import time
from typing import Optional

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_SINGLE_URL = "https://api.osv.dev/v1/query"
TIMEOUT = 30
BATCH_SIZE = 50


# ---------------------------------------------------------------------------
# Helpers — GitHub raw file fetching
# ---------------------------------------------------------------------------

def _github_raw_url(repo_url: str, filepath: str, token: Optional[str] = None) -> Optional[str]:
    """
    Convert a GitHub repo URL to a raw.githubusercontent.com URL for *filepath*.
    Returns None if the URL is not a recognisable GitHub repo.
    """
    match = re.match(
        r"https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$",
        repo_url.strip(),
    )
    if not match:
        return None
    owner, repo = match.group(1), match.group(2)
    return f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{filepath}"


def _fetch_file(raw_url: str, token: Optional[str] = None) -> Optional[str]:
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    try:
        r = requests.get(raw_url, headers=headers, timeout=TIMEOUT)
        if r.status_code == 200:
            return r.text
    except RequestException as exc:
        logger.debug("Failed to fetch %s: %s", raw_url, exc)
    return None


# ---------------------------------------------------------------------------
# Package file parsers
# ---------------------------------------------------------------------------

def parse_requirements_txt(content: str) -> list[dict]:
    packages = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-", "git+")):
            continue
        match = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=<>!~]+\s*([^\s;#,]+)", line)
        if match:
            packages.append({
                "name": match.group(1),
                "version": match.group(2).strip(),
                "ecosystem": "PyPI",
            })
    return packages


def parse_package_json(content: str) -> list[dict]:
    packages = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return packages

    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            clean = re.sub(r"^[\^~>=<]", "", version).strip()
            packages.append({"name": name, "version": clean, "ecosystem": "npm"})
    return packages


# ---------------------------------------------------------------------------
# OSV query
# ---------------------------------------------------------------------------

def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _extract_cvss(osv_vuln: dict) -> Optional[float]:
    for db_spec in [osv_vuln.get("database_specific", {}), osv_vuln.get("ecosystem_specific", {})]:
        for key in ("cvss_score", "severity_score"):
            try:
                return float(db_spec[key])
            except (KeyError, TypeError, ValueError):
                pass
    return None


def _fixed_versions(osv_vuln: dict, name: str, ecosystem: str) -> list[str]:
    fixed = []
    for affected in osv_vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("name", "").lower() != name.lower():
            continue
        for rng in affected.get("ranges", []):
            for evt in rng.get("events", []):
                if "fixed" in evt:
                    fixed.append(evt["fixed"])
    return fixed


def _query_osv(packages: list[dict]) -> list[dict]:
    """
    Query OSV in batches. Returns a flat list of vulnerability dicts, each with
    extra keys: package_name, package_version, ecosystem.
    """
    all_vulns = []

    for i in range(0, len(packages), BATCH_SIZE):
        batch = packages[i : i + BATCH_SIZE]
        queries = [
            {
                "version": p["version"],
                "package": {"name": p["name"], "ecosystem": p["ecosystem"]},
            }
            for p in batch
            if p.get("name") and p.get("version")
        ]

        try:
            resp = requests.post(
                OSV_BATCH_URL,
                json={"queries": queries},
                timeout=TIMEOUT,
            )
            resp.raise_for_status()
            results = resp.json().get("results", [])
        except RequestException as exc:
            logger.error("OSV batch query failed: %s", exc)
            results = []

        for idx, result in enumerate(results):
            pkg = batch[idx]
            for v in result.get("vulns") or []:
                cvss = _extract_cvss(v)
                aliases = v.get("aliases", [])
                cve_ids = [a for a in aliases if a.startswith("CVE-")]
                all_vulns.append({
                    "package_name": pkg["name"],
                    "package_version": pkg["version"],
                    "ecosystem": pkg["ecosystem"],
                    "osv_id": v.get("id", ""),
                    "cve_id": cve_ids[0] if cve_ids else None,
                    "aliases": aliases,
                    "severity": _cvss_to_severity(cvss),
                    "cvss_score": cvss,
                    "summary": v.get("summary", ""),
                    "description": (v.get("details") or "")[:1000],
                    "fix_versions": _fixed_versions(v, pkg["name"], pkg["ecosystem"]),
                })

    return all_vulns


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def scan_dependencies(
    repo_url: Optional[str] = None,
    package_type: str = "auto",
    packages: Optional[list[dict]] = None,
    github_token: Optional[str] = None,
) -> dict:
    """
    Scan dependencies for known vulnerabilities.

    Parameters
    ----------
    repo_url     : Public GitHub repo URL. If provided, package files are fetched.
    package_type : 'node' | 'python' | 'auto'
    packages     : Explicit list of {name, version, ecosystem} dicts (skips repo fetch).
    github_token : Optional GitHub PAT to avoid rate limiting.

    Returns
    -------
    {
        "packages": [...],
        "total_vulnerabilities": int,
        "critical_count": int,
        "high_count": int,
        "medium_count": int,
        "low_count": int,
        "duration_seconds": float,
        "error": str | None,
    }
    """
    start = time.time()
    error = None

    # --- Resolve package list --------------------------------------------------
    if packages:
        pkg_list = packages
    elif repo_url:
        pkg_list, error = _fetch_packages_from_repo(repo_url, package_type, github_token)
        if error:
            return {
                "packages": [], "total_vulnerabilities": 0,
                "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
                "duration_seconds": round(time.time() - start, 2),
                "error": error,
            }
    else:
        return {
            "packages": [], "total_vulnerabilities": 0,
            "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
            "duration_seconds": 0.0,
            "error": "Either repo_url or packages must be provided.",
        }

    logger.info("Scanning %d packages via OSV", len(pkg_list))
    raw_vulns = _query_osv(pkg_list)

    # Group by package
    pkg_vuln_map: dict[str, list] = {}
    for pkg in pkg_list:
        key = f"{pkg['name']}@{pkg['version']}"
        pkg_vuln_map[key] = []

    for v in raw_vulns:
        key = f"{v['package_name']}@{v['package_version']}"
        pkg_vuln_map.setdefault(key, []).append({
            "cve_id": v["cve_id"],
            "osv_id": v["osv_id"],
            "severity": v["severity"],
            "description": v["summary"] or v["description"],
            "patched_version": v["fix_versions"][0] if v["fix_versions"] else None,
            "cvss_score": v["cvss_score"],
        })

    packages_out = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for pkg in pkg_list:
        key = f"{pkg['name']}@{pkg['version']}"
        vulns = pkg_vuln_map.get(key, [])
        packages_out.append({
            "name": pkg["name"],
            "current_version": pkg["version"],
            "ecosystem": pkg["ecosystem"],
            "vulnerabilities": vulns,
        })
        for v in vulns:
            sev = v.get("severity", "low")
            counts[sev] = counts.get(sev, 0) + 1

    return {
        "packages": packages_out,
        "total_vulnerabilities": len(raw_vulns),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "duration_seconds": round(time.time() - start, 2),
        "error": error,
    }


def _fetch_packages_from_repo(
    repo_url: str, package_type: str, token: Optional[str]
) -> tuple[list[dict], Optional[str]]:
    """Fetch and parse package files from a GitHub repo."""
    packages = []

    fetch_python = package_type in ("python", "auto")
    fetch_node = package_type in ("node", "auto")

    if fetch_python:
        raw_url = _github_raw_url(repo_url, "requirements.txt", token)
        if raw_url:
            content = _fetch_file(raw_url, token)
            if content:
                packages += parse_requirements_txt(content)
                logger.info("Parsed %d Python packages from requirements.txt", len(packages))

    if fetch_node:
        raw_url = _github_raw_url(repo_url, "package.json", token)
        if raw_url:
            content = _fetch_file(raw_url, token)
            if content:
                node_pkgs = parse_package_json(content)
                packages += node_pkgs
                logger.info("Parsed %d Node packages from package.json", len(node_pkgs))

    if not packages:
        return [], (
            "No supported package files found (requirements.txt, package.json). "
            "Ensure the repository is public and contains at least one."
        )

    return packages, None
