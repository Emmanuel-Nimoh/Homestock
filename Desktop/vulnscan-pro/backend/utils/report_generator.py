"""
PDF Report Generator
---------------------
Produces a styled PDF vulnerability report using ReportLab.

Contents
~~~~~~~~
- Cover page: scan summary (date, target, type, risk score)
- Vulnerability findings grouped by severity
- PCI-DSS compliance mapping table
- Remediation recommendations
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable,
        PageBreak,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
    _REPORTLAB = True
except ImportError:
    _REPORTLAB = False
    logger.warning("reportlab not installed — PDF generation unavailable.")

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------

_BRAND_BLUE = colors.HexColor("#1a56db") if _REPORTLAB else None
_DARK       = colors.HexColor("#111827") if _REPORTLAB else None
_LIGHT_GRAY = colors.HexColor("#f3f4f6") if _REPORTLAB else None

_SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626") if _REPORTLAB else None,
    "high":     colors.HexColor("#ea580c") if _REPORTLAB else None,
    "medium":   colors.HexColor("#d97706") if _REPORTLAB else None,
    "low":      colors.HexColor("#16a34a") if _REPORTLAB else None,
    "info":     colors.HexColor("#6b7280") if _REPORTLAB else None,
}


def _styles():
    base = getSampleStyleSheet()
    custom = {
        "Title": ParagraphStyle(
            "Title", parent=base["Title"],
            fontSize=24, textColor=_BRAND_BLUE, spaceAfter=6,
        ),
        "Subtitle": ParagraphStyle(
            "Subtitle", parent=base["Normal"],
            fontSize=12, textColor=_DARK, spaceAfter=4,
        ),
        "H2": ParagraphStyle(
            "H2", parent=base["Heading2"],
            fontSize=14, textColor=_BRAND_BLUE, spaceBefore=12, spaceAfter=4,
        ),
        "Body": ParagraphStyle(
            "Body", parent=base["Normal"],
            fontSize=9, leading=13, spaceAfter=3,
        ),
        "BoldLabel": ParagraphStyle(
            "BoldLabel", parent=base["Normal"],
            fontSize=9, fontName="Helvetica-Bold",
        ),
        "SevBadge": ParagraphStyle(
            "SevBadge", parent=base["Normal"],
            fontSize=8, fontName="Helvetica-Bold", alignment=TA_CENTER,
        ),
    }
    return custom


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_pdf_report(
    scan: dict,
    vulnerabilities: list[dict],
    compliance_report: Optional[dict],
    output_path: str,
) -> str:
    """
    Generate a PDF report and write it to *output_path*.
    Returns the absolute path to the created file.
    Raises RuntimeError if reportlab is not available.
    """
    if not _REPORTLAB:
        raise RuntimeError(
            "reportlab is not installed. Run: pip install reportlab"
        )

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=f"SentinelScan Report – Scan #{scan.get('scan_id')}",
        author="SentinelScan",
    )

    s = _styles()
    story = []

    story += _cover_page(scan, vulnerabilities, s)
    story.append(PageBreak())
    story += _vulnerability_section(vulnerabilities, s)

    if compliance_report:
        story.append(PageBreak())
        story += _compliance_section(compliance_report, s)

    story += _remediation_section(vulnerabilities, s)

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    logger.info("PDF report written to %s", output_path)
    return output_path


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

def _cover_page(scan: dict, vulns: list[dict], s: dict) -> list:
    elements = []

    elements.append(Spacer(1, 2 * cm))
    elements.append(Paragraph("SentinelScan", s["Title"]))
    elements.append(Paragraph("Vulnerability Assessment Report", s["Subtitle"]))
    elements.append(HRFlowable(width="100%", thickness=2, color=_BRAND_BLUE, spaceAfter=12))

    # Summary table
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scan_time = scan.get("timestamp") or scan.get("created_at") or now_str
    rows = [
        ["Scan ID",    str(scan.get("scan_id", ""))],
        ["Scan Type",  scan.get("scan_type", "").upper()],
        ["Target",     scan.get("target", "")],
        ["Status",     scan.get("status", "").title()],
        ["Risk Score", f"{scan.get('risk_score', 0)} / 100"],
        ["Date",       scan_time],
    ]
    tbl = Table(rows, colWidths=[4 * cm, 12 * cm])
    tbl.setStyle(TableStyle([
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_LIGHT_GRAY, colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",(0, 0), (-1, -1), 6),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0,0), (-1, -1), 4),
    ]))
    elements.append(tbl)
    elements.append(Spacer(1, 0.5 * cm))

    # Severity summary
    counts = _count_by_severity(vulns)
    sev_rows = [["Severity", "Count"]]
    for sev in ("critical", "high", "medium", "low"):
        sev_rows.append([sev.title(), str(counts.get(sev, 0))])

    sev_tbl = Table(sev_rows, colWidths=[6 * cm, 6 * cm])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), _BRAND_BLUE),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("GRID",        (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_LIGHT_GRAY, colors.white]),
        ("ALIGN",       (1, 0), (1, -1), "CENTER"),
    ]))
    elements.append(Paragraph("Findings by Severity", s["H2"]))
    elements.append(sev_tbl)

    return elements


def _vulnerability_section(vulns: list[dict], s: dict) -> list:
    elements = [Paragraph("Vulnerability Findings", s["H2"]),
                HRFlowable(width="100%", thickness=1, color=_LIGHT_GRAY, spaceAfter=8)]

    if not vulns:
        elements.append(Paragraph("No vulnerabilities detected.", s["Body"]))
        return elements

    # Sort: critical → high → medium → low
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_vulns = sorted(vulns, key=lambda v: order.get(v.get("severity", "low"), 4))

    for v in sorted_vulns:
        sev = v.get("severity", "low")
        sev_color = _SEVERITY_COLORS.get(sev, colors.gray)

        header_data = [[
            Paragraph(f"<b>{v.get('title', 'Unknown')}</b>", s["Body"]),
            Paragraph(sev.upper(), s["SevBadge"]),
        ]]
        header_tbl = Table(header_data, colWidths=[14 * cm, 2 * cm])
        header_tbl.setStyle(TableStyle([
            ("BACKGROUND",   (1, 0), (1, 0), sev_color),
            ("TEXTCOLOR",    (1, 0), (1, 0), colors.white),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("LINEBELOW",    (0, 0), (-1, 0), 0.5, sev_color),
            ("LEFTPADDING",  (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ]))
        elements.append(header_tbl)

        detail_rows = []
        if v.get("affected_component"):
            detail_rows.append(["Component", v["affected_component"]])
        if v.get("cve_id"):
            detail_rows.append(["CVE", v["cve_id"]])
        if v.get("cvss_score") is not None:
            detail_rows.append(["CVSS", str(v["cvss_score"])])
        if v.get("description"):
            detail_rows.append(["Description", v["description"]])
        if v.get("remediation"):
            detail_rows.append(["Remediation", v["remediation"]])

        if detail_rows:
            dtbl = Table(
                [[Paragraph(r[0], s["BoldLabel"]),
                  Paragraph(str(r[1]), s["Body"])] for r in detail_rows],
                colWidths=[3.5 * cm, 12.5 * cm],
            )
            dtbl.setStyle(TableStyle([
                ("FONTSIZE",     (0, 0), (-1, -1), 8),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING",  (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING",   (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
            ]))
            elements.append(dtbl)

        elements.append(Spacer(1, 0.3 * cm))

    return elements


def _compliance_section(compliance_report: dict, s: dict) -> list:
    elements = [
        Paragraph("PCI-DSS Compliance Mapping", s["H2"]),
        Paragraph(
            f"Overall compliance: "
            f"<b>{compliance_report.get('overall_compliance_percentage', 0)}%</b>  "
            f"({compliance_report.get('passed_requirements', 0)} / "
            f"{compliance_report.get('total_requirements', 0)} requirements passed)",
            s["Body"],
        ),
        Spacer(1, 0.3 * cm),
    ]

    header = [["Requirement", "Title", "Status", "Findings"]]
    rows = header[:]
    for finding in compliance_report.get("findings", []):
        status = finding.get("status", "")
        status_color = (
            colors.HexColor("#16a34a") if status == "compliant"
            else colors.HexColor("#dc2626")
        )
        count = len(finding.get("vulnerabilities", []))
        rows.append([
            finding.get("pci_requirement", ""),
            finding.get("requirement_title", ""),
            Paragraph(
                f'<font color="{"#16a34a" if status == "compliant" else "#dc2626"}">'
                f"{'✓' if status == 'compliant' else '✗'} {status.replace('_', ' ').title()}"
                f"</font>",
                s["Body"],
            ),
            str(count),
        ])

    tbl = Table(rows, colWidths=[2.5 * cm, 8 * cm, 3 * cm, 2.5 * cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0), _BRAND_BLUE),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_LIGHT_GRAY, colors.white]),
        ("GRID",        (0, 0), (-1, -1), 0.25, colors.lightgrey),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING",(0, 0), (-1, -1), 4),
        ("TOPPADDING",  (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING",(0,0), (-1, -1), 3),
    ]))
    elements.append(tbl)
    return elements


def _remediation_section(vulns: list[dict], s: dict) -> list:
    remediations = [
        v for v in vulns
        if v.get("remediation") and v.get("severity") in ("critical", "high")
    ]
    if not remediations:
        return []

    elements = [
        PageBreak(),
        Paragraph("Priority Remediation Actions", s["H2"]),
        Paragraph(
            "The following critical and high severity issues require immediate attention.",
            s["Body"],
        ),
        Spacer(1, 0.3 * cm),
    ]

    for i, v in enumerate(remediations, 1):
        elements.append(Paragraph(
            f"{i}. <b>{v.get('title', '')}</b> "
            f"[{v.get('severity', '').upper()}]",
            s["Body"],
        ))
        elements.append(Paragraph(
            f"&nbsp;&nbsp;&nbsp;&nbsp;{v.get('remediation', '')}",
            s["Body"],
        ))
        elements.append(Spacer(1, 0.2 * cm))

    return elements


# ---------------------------------------------------------------------------
# Page decoration
# ---------------------------------------------------------------------------

def _header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4

    # Header
    canvas.setFillColor(_BRAND_BLUE)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(2 * cm, h - 1.3 * cm, "SentinelScan — Confidential Security Report")

    # Footer
    canvas.setFillColor(colors.gray)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(2 * cm, 1 * cm, f"Page {doc.page}")
    canvas.drawRightString(
        w - 2 * cm, 1 * cm,
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
    )
    canvas.restoreState()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _count_by_severity(vulns: list[dict]) -> dict:
    counts: dict = {}
    for v in vulns:
        sev = v.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
    return counts
