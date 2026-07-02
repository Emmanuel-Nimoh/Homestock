"""
Web API Security Scanner
------------------------
Performs the following checks against a target URL:

1. SSL/TLS certificate analysis
2. Security headers analysis
3. Server version detection
4. CORS misconfiguration
5. HTTP method detection
6. Cookie security
"""

import logging
import re
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Optional

import requests
from requests.exceptions import RequestException

logger = logging.getLogger(__name__)

TIMEOUT = 30  # seconds

# Severity weights used to compute the overall risk score (0-100)
SEVERITY_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 3}


# ---------------------------------------------------------------------------
# Result dataclass (plain dict so it serialises easily)
# ---------------------------------------------------------------------------

def _finding(vuln_type, severity, title, description, remediation,
             affected_component=None, cve_id=None, cvss_score=None) -> dict:
    return {
        "vuln_type": vuln_type,
        "severity": severity,
        "title": title,
        "description": description,
        "remediation": remediation,
        "affected_component": affected_component,
        "cve_id": cve_id,
        "cvss_score": cvss_score,
    }


# ---------------------------------------------------------------------------
# SSL / TLS
# ---------------------------------------------------------------------------

def check_ssl_certificate(url: str) -> list[dict]:
    """Analyse the TLS certificate for expiry, weak algorithms, and self-signing."""
    findings = []
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443

    if parsed.scheme != "https":
        return findings  # no cert to check on plain HTTP

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=TIMEOUT),
                             server_hostname=host) as sock:
            cert = sock.getpeercert()

        # Expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (not_after - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(_finding(
                    "expired_cert", "critical",
                    "TLS Certificate Expired",
                    f"The TLS certificate expired {abs(days_left)} day(s) ago.",
                    "Renew the TLS certificate immediately.",
                    affected_component=host,
                    cvss_score=9.1,
                ))
            elif days_left < 30:
                findings.append(_finding(
                    "expiring_cert_soon", "high",
                    "TLS Certificate Expiring Soon",
                    f"The TLS certificate expires in {days_left} day(s).",
                    "Renew the TLS certificate before it expires.",
                    affected_component=host,
                    cvss_score=7.0,
                ))

        # Self-signed: issuer == subject
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        if issuer == subject:
            findings.append(_finding(
                "self_signed_cert", "high",
                "Self-Signed TLS Certificate",
                "The certificate is self-signed and will not be trusted by browsers.",
                "Obtain a certificate from a trusted CA (e.g. Let's Encrypt).",
                affected_component=host,
                cvss_score=7.4,
            ))

    except ssl.SSLCertVerificationError as exc:
        findings.append(_finding(
            "invalid_cert", "critical",
            "TLS Certificate Validation Failure",
            f"Certificate could not be verified: {exc}",
            "Fix the certificate chain and ensure the CN/SAN matches the domain.",
            affected_component=host,
            cvss_score=9.1,
        ))
    except Exception as exc:  # pylint: disable=broad-except
        logger.debug("SSL check failed for %s: %s", host, exc)

    return findings


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

REQUIRED_HEADERS = {
    "strict-transport-security": {
        "vuln_type": "missing_hsts",
        "severity": "high",
        "title": "Missing HTTP Strict-Transport-Security (HSTS)",
        "description": (
            "HSTS is absent. Browsers may fall back to plain HTTP, "
            "enabling downgrade and MitM attacks."
        ),
        "remediation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
        "cvss_score": 7.5,
    },
    "content-security-policy": {
        "vuln_type": "missing_csp",
        "severity": "medium",
        "title": "Missing Content-Security-Policy (CSP)",
        "description": "No CSP header. XSS attacks have no browser-level mitigation.",
        "remediation": (
            "Add a restrictive CSP: Content-Security-Policy: default-src 'self'; "
            "script-src 'self'; object-src 'none'"
        ),
        "cvss_score": 6.1,
    },
    "x-content-type-options": {
        "vuln_type": "missing_xcto",
        "severity": "medium",
        "title": "Missing X-Content-Type-Options Header",
        "description": "Without 'nosniff', browsers may MIME-sniff responses.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
        "cvss_score": 5.3,
    },
    "x-frame-options": {
        "vuln_type": "missing_xfo",
        "severity": "medium",
        "title": "Missing X-Frame-Options Header",
        "description": "Endpoint may be embeddable in iframes, enabling clickjacking.",
        "remediation": "Add: X-Frame-Options: DENY",
        "cvss_score": 6.1,
    },
    "referrer-policy": {
        "vuln_type": "missing_referrer_policy",
        "severity": "low",
        "title": "Missing Referrer-Policy Header",
        "description": "Sensitive URLs may leak to third-party origins via the Referer header.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "cvss_score": 3.7,
    },
    "permissions-policy": {
        "vuln_type": "missing_permissions_policy",
        "severity": "low",
        "title": "Missing Permissions-Policy Header",
        "description": "Dangerous browser APIs (camera, microphone, geolocation) are not restricted.",
        "remediation": (
            "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()"
        ),
        "cvss_score": 3.1,
    },
}


def check_security_headers(response_headers: dict) -> list[dict]:
    """Return a finding for each missing or misconfigured security header."""
    findings = []
    lower = {k.lower(): v for k, v in response_headers.items()}

    for header, meta in REQUIRED_HEADERS.items():
        if header not in lower:
            findings.append(_finding(**meta, affected_component=header))

    # HSTS max-age must be >= 1 year
    hsts = lower.get("strict-transport-security", "")
    match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
    if match and int(match.group(1)) < 31536000:
        findings.append(_finding(
            "weak_hsts", "medium",
            "HSTS max-age Below Recommended Minimum",
            f"max-age={match.group(1)} is less than 31536000 (1 year).",
            "Set max-age to at least 31536000.",
            affected_component="Strict-Transport-Security",
            cvss_score=5.3,
        ))

    # X-XSS-Protection deprecated but flag if still set to non-zero value
    xxp = lower.get("x-xss-protection", "0")
    if xxp.strip() not in ("0", ""):
        findings.append(_finding(
            "deprecated_xxp", "low",
            "Deprecated X-XSS-Protection Header Enabled",
            "X-XSS-Protection is deprecated and can introduce vulnerabilities in older browsers.",
            "Set X-XSS-Protection: 0 and rely on CSP instead.",
            affected_component="X-XSS-Protection",
            cvss_score=2.6,
        ))

    return findings


# ---------------------------------------------------------------------------
# Server version detection
# ---------------------------------------------------------------------------

# Patterns: (server_regex, known_cves, recommended_version)
KNOWN_OUTDATED = [
    (re.compile(r"Apache/2\.[01]\.", re.I), ["CVE-2021-41773", "CVE-2021-42013"], "2.4.59"),
    (re.compile(r"Apache/2\.4\.([0-4]\d)\b", re.I), ["CVE-2023-25690"], "2.4.59"),
    (re.compile(r"nginx/1\.(1[0-9]|20)\.", re.I), ["CVE-2021-23017"], "1.25.3"),
    (re.compile(r"openssl/1\.[01]\.", re.I), ["CVE-2022-0778", "CVE-2021-3711"], "3.0.x"),
    (re.compile(r"IIS/[1-9]\.", re.I), ["CVE-2021-31166"], "IIS 10.0"),
]


def check_server_version(response_headers: dict) -> list[dict]:
    """Flag outdated server versions exposed in response headers."""
    findings = []
    lower = {k.lower(): v for k, v in response_headers.items()}

    server = lower.get("server", "")
    powered_by = lower.get("x-powered-by", "")

    for header_val in [server, powered_by]:
        if not header_val:
            continue

        for pattern, cves, recommended in KNOWN_OUTDATED:
            if pattern.search(header_val):
                findings.append(_finding(
                    "outdated_server", "high",
                    "Outdated Server Version Detected",
                    (
                        f"Server header '{header_val}' matches a version with known CVEs: "
                        f"{', '.join(cves[:3])}."
                    ),
                    f"Upgrade to {recommended} or later and suppress version disclosure.",
                    affected_component=header_val,
                    cve_id=cves[0] if cves else None,
                    cvss_score=8.1,
                ))
                break

        # Even if not outdated, version disclosure is a low finding
        if header_val and re.search(r"/[\d.]+", header_val):
            findings.append(_finding(
                "server_version_disclosure", "low",
                "Server Version Disclosed in Header",
                f"'{header_val}' reveals the exact server version, aiding targeted attacks.",
                "Configure the server to omit or genericise the version string.",
                affected_component=header_val,
                cvss_score=3.7,
            ))

    return findings


# ---------------------------------------------------------------------------
# CORS misconfiguration
# ---------------------------------------------------------------------------

def check_cors_configuration(response_headers: dict, probe_origin: str = "https://evil.test") -> list[dict]:
    findings = []
    lower = {k.lower(): v for k, v in response_headers.items()}

    acao = lower.get("access-control-allow-origin", "")
    acac = lower.get("access-control-allow-credentials", "")

    if acao == "*":
        findings.append(_finding(
            "cors_wildcard", "medium",
            "Wildcard CORS Policy (Access-Control-Allow-Origin: *)",
            "Any origin can make cross-origin requests. Sensitive data may be read by untrusted sites.",
            "Restrict CORS to specific trusted origins.",
            affected_component="Access-Control-Allow-Origin",
            cvss_score=6.5,
        ))

    if acao == probe_origin:
        sev = "high" if acac.lower() == "true" else "medium"
        findings.append(_finding(
            "cors_reflected_origin", sev,
            "Reflected Origin CORS Policy" + (" with Credentials" if acac.lower() == "true" else ""),
            (
                "The server mirrors the request Origin header without allowlist validation. "
                + ("Combined with Allow-Credentials: true this allows any site to perform "
                   "authenticated requests on behalf of a victim." if acac.lower() == "true" else "")
            ),
            "Validate the Origin header against an explicit server-side allowlist.",
            affected_component="Access-Control-Allow-Origin",
            cvss_score=8.1 if sev == "high" else 6.5,
        ))

    return findings


# ---------------------------------------------------------------------------
# HTTP method detection
# ---------------------------------------------------------------------------

DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "OPTIONS"}


def check_http_methods(url: str, session: requests.Session) -> list[dict]:
    """Test for dangerous HTTP methods accepted without authentication."""
    findings = []
    try:
        r = session.options(url, timeout=TIMEOUT)
        allow = r.headers.get("Allow", "") + r.headers.get("Access-Control-Allow-Methods", "")
        allowed = {m.strip().upper() for m in allow.split(",") if m.strip()}

        dangerous_found = allowed & DANGEROUS_METHODS
        if "TRACE" in dangerous_found:
            findings.append(_finding(
                "http_trace_enabled", "medium",
                "HTTP TRACE Method Enabled",
                "TRACE echoes the request back, enabling Cross-Site Tracing (XST) attacks.",
                "Disable the TRACE method in server configuration.",
                affected_component="HTTP Methods",
                cvss_score=5.8,
            ))

        for method in dangerous_found - {"TRACE", "OPTIONS"}:
            findings.append(_finding(
                f"http_{method.lower()}_enabled", "medium",
                f"HTTP {method} Method Available",
                f"The {method} method is available and may allow unauthorised data modification.",
                f"Disable {method} unless explicitly required, and enforce authentication.",
                affected_component="HTTP Methods",
                cvss_score=6.5,
            ))
    except RequestException as exc:
        logger.debug("HTTP methods check failed: %s", exc)

    return findings


# ---------------------------------------------------------------------------
# Cookie security
# ---------------------------------------------------------------------------

def check_cookie_security(response) -> list[dict]:
    """Inspect Set-Cookie headers for missing security flags."""
    findings = []
    raw_cookies = response.headers.get("Set-Cookie", "")
    if not raw_cookies:
        return findings

    # requests combines multiple Set-Cookie values; split heuristically
    cookie_headers = [response.headers.get("Set-Cookie", "")]
    # Use raw response headers if available (multiple values)
    if hasattr(response.raw, "headers"):
        cookie_headers = response.raw.headers.getlist("Set-Cookie") or cookie_headers

    for cookie_str in cookie_headers:
        lower_cookie = cookie_str.lower()
        cookie_name = cookie_str.split("=")[0].strip()

        if "httponly" not in lower_cookie:
            findings.append(_finding(
                "cookie_missing_httponly", "medium",
                f"Cookie Missing HttpOnly Flag: {cookie_name}",
                "Without HttpOnly, JavaScript can read this cookie, enabling XSS-based session theft.",
                "Set the HttpOnly flag on all session cookies.",
                affected_component=cookie_name,
                cvss_score=6.1,
            ))

        if "secure" not in lower_cookie:
            findings.append(_finding(
                "cookie_missing_secure", "medium",
                f"Cookie Missing Secure Flag: {cookie_name}",
                "The cookie can be transmitted over unencrypted HTTP connections.",
                "Set the Secure flag on all cookies.",
                affected_component=cookie_name,
                cvss_score=5.9,
            ))

        if "samesite" not in lower_cookie:
            findings.append(_finding(
                "cookie_missing_samesite", "low",
                f"Cookie Missing SameSite Attribute: {cookie_name}",
                "Without SameSite, cross-site request forgery (CSRF) may be possible.",
                "Set SameSite=Lax or SameSite=Strict on all cookies.",
                affected_component=cookie_name,
                cvss_score=4.3,
            ))

    return findings


# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

def calculate_risk_score(findings: list[dict]) -> int:
    """Compute a 0–100 risk score from a list of findings."""
    score = 0
    for f in findings:
        score += SEVERITY_WEIGHT.get(f.get("severity", "low"), 0)
    return min(score, 100)


# ---------------------------------------------------------------------------
# Main scanner entry point
# ---------------------------------------------------------------------------

def scan_web_api(url: str, scan_depth: str = "full", timeout: int = TIMEOUT) -> dict:
    """
    Run all security checks against *url*.

    Returns:
    {
        "findings": [...],
        "risk_score": int,
        "error": str | None,
        "duration_seconds": float,
    }
    """
    start = time.time()
    findings: list[dict] = []
    error = None

    session = requests.Session()
    session.headers["User-Agent"] = (
        "SentinelScan/1.0 (Security Audit; contact security@sentinelscan.io)"
    )

    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)

        findings += check_ssl_certificate(url)
        findings += check_security_headers(dict(response.headers))
        findings += check_server_version(dict(response.headers))
        findings += check_cookie_security(response)

        # Probe CORS with a crafted origin header
        try:
            probe_origin = "https://evil.sentinelscan-test.io"
            cors_resp = session.get(url, headers={"Origin": probe_origin}, timeout=timeout)
            findings += check_cors_configuration(dict(cors_resp.headers), probe_origin)
        except RequestException:
            pass

        if scan_depth == "full":
            findings += check_http_methods(url, session)

    except RequestException as exc:
        error = str(exc)
        logger.warning("scan_web_api failed for %s: %s", url, exc)

    risk_score = calculate_risk_score(findings)

    return {
        "findings": findings,
        "risk_score": risk_score,
        "error": error,
        "duration_seconds": round(time.time() - start, 2),
    }
