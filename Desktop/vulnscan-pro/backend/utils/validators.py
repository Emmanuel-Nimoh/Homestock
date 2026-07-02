"""Input validation helpers for SentinelScan API endpoints."""

import re
from typing import Optional

try:
    import validators as _v   # pip: validators==0.22.0
    _HAS_VALIDATORS = True
except ImportError:
    _HAS_VALIDATORS = False


# ---------------------------------------------------------------------------
# Private / loopback SSRF guard
# ---------------------------------------------------------------------------

_PRIVATE_PATTERNS = [
    re.compile(r"^localhost$", re.IGNORECASE),
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^::1$"),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^169\.254\."),
]

import urllib.parse


def _is_private_host(host: str) -> bool:
    return any(p.match(host) for p in _PRIVATE_PATTERNS)


def validate_url(url: str) -> tuple[bool, Optional[str]]:
    """Return (True, None) for a valid, public HTTPS URL."""
    if not url or not isinstance(url, str):
        return False, "URL is required."

    url = url.strip()
    if len(url) > 2048:
        return False, "URL exceeds 2048 characters."

    if _HAS_VALIDATORS:
        if not _v.url(url):
            return False, "Invalid URL format."
    else:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return False, "URL must start with http:// or https://."

    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""

    if _is_private_host(host):
        return False, (
            f"Scanning private or loopback addresses is not permitted ('{host}'). "
            "Only public hosts may be scanned."
        )

    return True, None


def validate_web_api_payload(data: dict) -> tuple[bool, Optional[str]]:
    url = (data.get("url") or "").strip()
    ok, err = validate_url(url)
    if not ok:
        return False, err

    scan_depth = data.get("scan_depth", "full")
    if scan_depth not in ("quick", "full"):
        return False, "'scan_depth' must be 'quick' or 'full'."

    return True, None


def validate_dependency_payload(data: dict) -> tuple[bool, Optional[str]]:
    repo_url = (data.get("repo_url") or "").strip()
    packages = data.get("packages")

    # Must provide either repo_url or inline packages
    if not repo_url and not packages:
        return False, "Either 'repo_url' or 'packages' must be provided."

    if repo_url:
        if not repo_url.startswith(("http://", "https://")):
            return False, "Invalid repo_url."

        parsed = urllib.parse.urlparse(repo_url)
        if _is_private_host(parsed.hostname or ""):
            return False, "Private repo URLs are not permitted."

    if packages is not None:
        ok, err = validate_packages(packages)
        if not ok:
            return False, err

    pkg_type = data.get("package_type", "auto")
    if pkg_type not in ("auto", "node", "python"):
        return False, "'package_type' must be 'auto', 'node', or 'python'."

    return True, None


def validate_packages(packages: list) -> tuple[bool, Optional[str]]:
    if not isinstance(packages, list):
        return False, "'packages' must be a JSON array."
    if not packages:
        return False, "At least one package must be provided."
    if len(packages) > 500:
        return False, "Maximum 500 packages per scan."

    valid_ecosystems = {
        "PyPI", "npm", "Maven", "NuGet", "RubyGems", "Go", "Cargo", "Hex", "Packagist",
    }
    for idx, pkg in enumerate(packages):
        if not isinstance(pkg, dict):
            return False, f"Item {idx} must be a JSON object."
        if not pkg.get("name"):
            return False, f"Item {idx} missing 'name'."
        if not pkg.get("version"):
            return False, f"Item {idx} missing 'version'."
        eco = pkg.get("ecosystem", "PyPI")
        if eco not in valid_ecosystems:
            return False, (
                f"Item {idx} has unsupported ecosystem '{eco}'. "
                f"Valid: {', '.join(sorted(valid_ecosystems))}"
            )

    return True, None


def validate_pagination(
    limit: str, offset: str
) -> tuple[bool, Optional[str], int, int]:
    try:
        lim = int(limit)
        off = int(offset)
    except (TypeError, ValueError):
        return False, "'limit' and 'offset' must be integers.", 10, 0

    if lim < 1 or lim > 100:
        return False, "'limit' must be between 1 and 100.", 10, 0
    if off < 0:
        return False, "'offset' must be >= 0.", 10, 0

    return True, None, lim, off
