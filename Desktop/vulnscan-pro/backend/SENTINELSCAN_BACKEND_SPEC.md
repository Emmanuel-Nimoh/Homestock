# SentinelScan Backend Specification

## Project Overview
SentinelScan is a vulnerability scanner for financial institutions with three core components:
1. **Web API Scanner** - Scans URLs/APIs for security misconfigurations
2. **Dependency Scanner** - Detects vulnerable packages in code repositories
3. **Compliance Dashboard** - Maps findings to PCI-DSS requirements and generates reports

---

## Backend Architecture

### Tech Stack
- **Framework:** Flask 3.0.0
- **Database:** SQLite3
- **HTTP Requests:** requests library
- **Validation:** validators library
- **PDF Generation:** reportlab
- **DNS Queries:** dnspython
- **CORS:** Flask-CORS

### Project Structure
```
backend/
├── venv/
├── app.py                 # Main Flask app
├── config.py              # Configuration
├── database.py            # Database setup
├── models.py              # Database models
├── routes.py              # API routes
├── scanners/
│   ├── __init__.py
│   ├── api_scanner.py     # Web API scanning logic
│   ├── dependency_scanner.py  # Package vulnerability checking
│   └── compliance.py      # PCI-DSS compliance mapping
├── utils/
│   ├── __init__.py
│   ├── validators.py      # Input validation
│   └── report_generator.py # PDF report generation
├── requirements.txt
└── run.py                 # Entry point
```

---

## Database Schema

### Table: scans
```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,  -- 'api' or 'dependency'
    target TEXT NOT NULL,     -- URL or repo path
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'pending',  -- pending, in_progress, completed, failed
    risk_score INTEGER DEFAULT 0,   -- 0-100
    summary TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Table: vulnerabilities
```sql
CREATE TABLE vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    vuln_type TEXT NOT NULL,  -- e.g., 'missing_hsts', 'cve_2024_xxxx'
    severity TEXT NOT NULL,   -- critical, high, medium, low
    title TEXT NOT NULL,
    description TEXT,
    remediation TEXT,
    affected_component TEXT,  -- header name, package name, etc.
    cve_id TEXT,
    cvss_score REAL,
    discovery_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

### Table: compliance_mappings
```sql
CREATE TABLE compliance_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id INTEGER NOT NULL,
    pci_requirement TEXT,  -- e.g., '6.5.1', '11.2'
    requirement_title TEXT,
    status TEXT DEFAULT 'open',  -- open, remediated
    mapped_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
);
```

---

## API Endpoints

### 1. Start Web API Scan
**Endpoint:** `POST /api/scan/web-api`

**Request:**
```json
{
  "url": "https://api.example-bank.com",
  "scan_depth": "full",  -- "quick" or "full"
  "include_subdomains": true
}
```

**Response:**
```json
{
  "scan_id": 1,
  "status": "in_progress",
  "message": "Scan started"
}
```

**Validations:**
- URL must be valid and HTTPS
- URL cannot be internal/private IP
- Rate limit: 1 scan per 10 seconds per IP

---

### 2. Start Dependency Scan
**Endpoint:** `POST /api/scan/dependencies`

**Request:**
```json
{
  "repo_url": "https://github.com/user/repo",
  "package_type": "auto",  -- "node", "python", "auto"
  "include_transitive": true
}
```

**Response:**
```json
{
  "scan_id": 2,
  "status": "in_progress",
  "message": "Dependency scan started"
}
```

**Validations:**
- Repo must be publicly accessible
- Must contain package files (package.json, requirements.txt, etc.)

---

### 3. Get Scan Results
**Endpoint:** `GET /api/scan/{scan_id}`

**Response:**
```json
{
  "scan_id": 1,
  "scan_type": "api",
  "target": "https://api.example-bank.com",
  "status": "completed",
  "risk_score": 72,
  "vulnerabilities": [
    {
      "id": 1,
      "vuln_type": "missing_hsts",
      "severity": "high",
      "title": "Missing HSTS Header",
      "description": "HTTP Strict-Transport-Security header not set. Browsers will not enforce HTTPS.",
      "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
      "cve_id": null,
      "cvss_score": 7.5
    },
    {
      "id": 2,
      "vuln_type": "outdated_server",
      "severity": "high",
      "title": "Outdated Server Version",
      "description": "Server running Apache/2.2.15 (outdated, multiple CVEs)",
      "remediation": "Upgrade to Apache 2.4.52 or later",
      "affected_component": "Apache",
      "cve_id": "CVE-2021-41773",
      "cvss_score": 8.1
    }
  ],
  "timestamp": "2024-06-22T10:30:00Z",
  "compliance_status": {
    "pci_dss": {
      "requirement_6_5_1": "failed",
      "requirement_11_2": "failed",
      "requirement_4_1": "passed"
    }
  }
}
```

---

### 4. Get Compliance Report
**Endpoint:** `GET /api/compliance/report/{scan_id}`

**Response:**
```json
{
  "scan_id": 1,
  "report_type": "pci_dss",
  "findings": [
    {
      "pci_requirement": "6.5.1",
      "requirement_title": "Injection Flaws",
      "status": "compliant",
      "vulnerabilities": [],
      "notes": "No SQL injection or command injection detected"
    },
    {
      "pci_requirement": "11.2",
      "requirement_title": "Run Automated Scanning Tools",
      "status": "non_compliant",
      "vulnerabilities": [
        {
          "title": "Missing HSTS Header",
          "severity": "high",
          "remediation": "Add HSTS header"
        }
      ],
      "notes": "Missing security headers leave application vulnerable to MitM attacks"
    }
  ],
  "overall_compliance_percentage": 65,
  "generated_at": "2024-06-22T10:35:00Z"
}
```

---

### 5. Export PDF Report
**Endpoint:** `GET /api/reports/pdf/{scan_id}`

**Response:** Binary PDF file

**Contents:**
- Scan summary (date, target, type)
- Vulnerability findings by severity
- PCI-DSS compliance mapping
- Remediation recommendations
- Risk timeline (if multiple scans available)

---

### 6. Get Scan History
**Endpoint:** `GET /api/scans?limit=10&offset=0`

**Response:**
```json
{
  "scans": [
    {
      "scan_id": 5,
      "scan_type": "api",
      "target": "https://api.example-bank.com",
      "risk_score": 72,
      "timestamp": "2024-06-22T10:30:00Z",
      "status": "completed",
      "vulnerability_count": 8
    }
  ],
  "total": 42,
  "limit": 10,
  "offset": 0
}
```

---

## Scanner Implementation Details

### Web API Scanner (`scanners/api_scanner.py`)

**Checks Performed:**

#### 1. SSL/TLS Certificate Analysis
- Certificate validity and expiration
- Signature algorithm strength (reject SHA-1)
- Certificate chain completeness
- Self-signed certificate detection

```python
def check_ssl_certificate(url):
    """
    Returns:
    {
        'vuln_type': 'expired_cert' | 'weak_signature' | None,
        'severity': 'critical' | 'high' | None,
        'details': {...}
    }
    """
```

#### 2. Security Headers Analysis
Check for presence and correct values:
- `Strict-Transport-Security` (HSTS) - must include max-age >= 31536000
- `Content-Security-Policy` (CSP) - must be reasonably restrictive
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY or SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy` - should restrict information leakage
- `Permissions-Policy` - should restrict dangerous APIs

```python
def check_security_headers(response_headers):
    """
    Returns list of missing/misconfigured headers with severity.
    """
```

#### 3. Server Version Detection
- Extract `Server` header
- Cross-reference against CVE database
- Flag if outdated version

```python
def check_server_version(server_header):
    """
    Returns:
    {
        'server': 'Apache/2.2.15',
        'is_outdated': True,
        'cves': ['CVE-2021-41773', ...],
        'recommended_version': '2.4.52'
    }
    """
```

#### 4. CORS Misconfiguration
- Check `Access-Control-Allow-Origin` header
- Flag if set to `*` or overly permissive
- Check `Access-Control-Allow-Credentials`

```python
def check_cors_configuration(response_headers):
    """
    Returns severity if misconfigured.
    """
```

#### 5. HTTP Method Detection
- Test for dangerous methods: PUT, DELETE, PATCH without auth
- Flag if methods allowed unnecessarily

```python
def check_http_methods(url):
    """
    Returns list of dangerous methods available without auth.
    """
```

#### 6. Cookie Security
- Check for HttpOnly flag
- Check for Secure flag
- Check for SameSite attribute

```python
def check_cookie_security(response_headers):
    """
    Returns cookie security issues.
    """
```

---

### Dependency Scanner (`scanners/dependency_scanner.py`)

**Supported Package Managers:**
- npm (Node.js) - reads `package.json`
- pip (Python) - reads `requirements.txt`
- Auto-detect based on available files

**Process:**
1. Clone/fetch repo
2. Parse package files
3. Query vulnerability databases
4. Return findings with CVE details

```python
def scan_dependencies(repo_url, package_type='auto'):
    """
    Returns:
    {
        'scan_id': 1,
        'packages': [
            {
                'name': 'lodash',
                'current_version': '4.17.19',
                'vulnerabilities': [
                    {
                        'cve_id': 'CVE-2021-23337',
                        'severity': 'high',
                        'description': 'Prototype pollution in lodash',
                        'patched_version': '4.17.21',
                        'cvss_score': 7.4
                    }
                ]
            }
        ],
        'total_vulnerabilities': 5,
        'critical_count': 1,
        'high_count': 2,
        'medium_count': 2,
        'low_count': 0
    }
    """
```

**Data Sources:**
- npm: `npm audit` API + npm advisories
- Python: Python advisory database (pyup.io or GitHub)

---

### Compliance Mapping (`scanners/compliance.py`)

**PCI-DSS Requirements Mapping:**

| Requirement | Vulnerability Type | Status Logic |
|-------------|-------------------|--------------|
| 6.5.1 | SQL Injection, XSS | Check for input validation issues |
| 6.5.7 | XSS | Check for CSP header, output encoding |
| 11.2 | Missing scanning tools | Automated scan performed = compliant |
| 4.1 | Encryption | Check for HTTPS, TLS 1.2+ |
| 2.1 | Default credentials | Check for hardcoded secrets |
| 2.2.4 | Configure system components | Check for outdated servers, weak ciphers |

```python
def map_to_pci_dss(vulnerabilities):
    """
    Takes list of vulnerabilities, returns PCI-DSS compliance status.
    
    Returns:
    {
        '6.5.1': {'status': 'pass', 'findings': []},
        '6.5.7': {'status': 'fail', 'findings': [...]},
        ...
    }
    """
```

---

## Configuration (`config.py`)

```python
import os

class Config:
    # Database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///sentinelscan.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
    
    # Scanning
    SCAN_TIMEOUT = 30  # seconds
    MAX_SCAN_SIZE = 1000  # MB for repos
    
    # Rate limiting
    RATE_LIMIT_SCANS = 10  # scans per hour per IP
    
    # External APIs
    NVD_API_KEY = os.environ.get('NVD_API_KEY')
    GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
```

---

## Error Handling

All endpoints return consistent error responses:

```json
{
  "error": "Invalid URL provided",
  "error_code": "INVALID_INPUT",
  "status_code": 400
}
```

**Common Errors:**
- `400 Bad Request` - Invalid input (missing fields, invalid URL)
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Scanning failure (timeout, network issue)
- `503 Service Unavailable` - External API failure

---

## Implementation Notes for Claude Code

1. **Start with database setup** - Create models.py, then database.py
2. **Build API scanner first** - Most straightforward scanning logic
3. **Build dependency scanner** - Requires package file parsing
4. **Build compliance mapper** - Maps vulnerabilities to PCI-DSS
5. **Build report generator** - PDF generation with findings
6. **Wire up routes** - Connect all scanners to Flask endpoints
7. **Add error handling** - Wrap all scanning logic in try/catch

---

## Testing Notes

- Mock HTTP responses for security header checks
- Use public, non-sensitive test URLs (example.com, httpbin.org)
- Test with known vulnerable packages (e.g., lodash 4.17.19)
- Validate database schema and relationships
- Test PDF generation with sample data
