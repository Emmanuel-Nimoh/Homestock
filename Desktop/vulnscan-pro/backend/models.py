"""SQLAlchemy ORM models — matches the schema defined in SENTINELSCAN_BACKEND_SPEC.md."""

from datetime import datetime, timezone

from database import db


def _now():
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_type = db.Column(db.String(20), nullable=False)   # 'api' | 'dependency'
    target = db.Column(db.Text, nullable=False)            # URL or repo path
    timestamp = db.Column(db.DateTime, default=_now)
    status = db.Column(db.String(20), default="pending")   # pending|in_progress|completed|failed
    risk_score = db.Column(db.Integer, default=0)          # 0–100
    summary = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=_now)

    vulnerabilities = db.relationship(
        "Vulnerability",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def vulnerability_count(self) -> int:
        return len(self.vulnerabilities)

    def to_dict(self, include_vulns: bool = False) -> dict:
        data = {
            "scan_id": self.id,
            "scan_type": self.scan_type,
            "target": self.target,
            "status": self.status,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "vulnerability_count": self.vulnerability_count(),
        }
        if include_vulns:
            data["vulnerabilities"] = [v.to_dict() for v in self.vulnerabilities]
        return data


# ---------------------------------------------------------------------------
# Vulnerability
# ---------------------------------------------------------------------------

class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    vuln_type = db.Column(db.String(100), nullable=False)  # e.g. 'missing_hsts', 'cve_2024_xxx'
    severity = db.Column(db.String(20), nullable=False)    # critical|high|medium|low
    title = db.Column(db.String(256), nullable=False)
    description = db.Column(db.Text, nullable=True)
    remediation = db.Column(db.Text, nullable=True)
    affected_component = db.Column(db.String(512), nullable=True)
    cve_id = db.Column(db.String(30), nullable=True)
    cvss_score = db.Column(db.Float, nullable=True)
    discovery_timestamp = db.Column(db.DateTime, default=_now)

    scan = db.relationship("Scan", back_populates="vulnerabilities")
    compliance_mappings = db.relationship(
        "ComplianceMapping",
        back_populates="vulnerability",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "affected_component": self.affected_component,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "discovery_timestamp": (
                self.discovery_timestamp.isoformat() if self.discovery_timestamp else None
            ),
        }


# ---------------------------------------------------------------------------
# ComplianceMapping
# ---------------------------------------------------------------------------

class ComplianceMapping(db.Model):
    __tablename__ = "compliance_mappings"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    vulnerability_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.id"), nullable=False)
    pci_requirement = db.Column(db.String(20), nullable=True)   # e.g. '6.5.1', '11.2'
    requirement_title = db.Column(db.String(256), nullable=True)
    status = db.Column(db.String(20), default="open")           # open | remediated
    mapped_at = db.Column(db.DateTime, default=_now)

    vulnerability = db.relationship("Vulnerability", back_populates="compliance_mappings")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "vulnerability_id": self.vulnerability_id,
            "pci_requirement": self.pci_requirement,
            "requirement_title": self.requirement_title,
            "status": self.status,
            "mapped_at": self.mapped_at.isoformat() if self.mapped_at else None,
        }
