"""
TazoSploit SaaS v2 - PDF Report Generator
Produces professional pentest reports using reportlab
"""

import io
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

logger = logging.getLogger(__name__)

# =============================================================================
# BRANDING COLORS (dark theme matching GUI)
# =============================================================================

BRAND_BG = colors.HexColor("#0f0f23")
BRAND_SURFACE = colors.HexColor("#1a1a2e")
BRAND_ACCENT = colors.HexColor("#6366f1")
BRAND_TEXT = colors.HexColor("#e2e8f0")
BRAND_DIM = colors.HexColor("#94a3b8")

SEV_CRITICAL = colors.HexColor("#dc2626")
SEV_HIGH = colors.HexColor("#ea580c")
SEV_MEDIUM = colors.HexColor("#eab308")
SEV_LOW = colors.HexColor("#3b82f6")
SEV_INFO = colors.HexColor("#6b7280")

SEVERITY_COLORS = {
    "critical": SEV_CRITICAL,
    "high": SEV_HIGH,
    "medium": SEV_MEDIUM,
    "low": SEV_LOW,
    "info": SEV_INFO,
}


def _build_styles():
    """Create custom paragraph styles"""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        "BrandTitle",
        parent=styles["Title"],
        fontSize=28,
        textColor=BRAND_ACCENT,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=BRAND_ACCENT,
        spaceBefore=20,
        spaceAfter=10,
        borderWidth=0,
        borderPadding=0,
    ))
    styles.add(ParagraphStyle(
        "SubHeading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#818cf8"),
        spaceBefore=12,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "BodyDark",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.HexColor("#334155"),
        leading=14,
    ))
    styles.add(ParagraphStyle(
        "Evidence",
        parent=styles["Code"],
        fontSize=8,
        textColor=colors.HexColor("#22c55e"),
        backColor=colors.HexColor("#1e293b"),
        borderWidth=1,
        borderColor=colors.HexColor("#334155"),
        borderPadding=6,
        leading=11,
    ))
    return styles


def generate_pdf_report(
    job: Dict[str, Any],
    findings: List[Dict[str, Any]],
    credentials: List[Dict[str, Any]],
    tools_used: List[str],
    raw_output: str = "",
    mitre_techniques: Optional[List[Dict]] = None,
) -> bytes:
    """
    Generate a professional PDF pentest report.
    Returns raw PDF bytes.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=50,
        leftMargin=50,
        topMargin=60,
        bottomMargin=50,
    )
    styles = _build_styles()
    story: List = []

    # ------------------------------------------------------------------
    # COVER / TITLE
    # ------------------------------------------------------------------
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("TazoSploit", styles["BrandTitle"]))
    story.append(Paragraph("Penetration Test Report", styles["SectionHeading"]))
    story.append(Spacer(1, 0.3 * inch))
    story.append(HRFlowable(width="100%", thickness=2, color=BRAND_ACCENT))
    story.append(Spacer(1, 0.3 * inch))

    meta_data = [
        ["Target(s):", ", ".join(job.get("targets", []))],
        ["Phase:", job.get("phase", "N/A")],
        ["Status:", job.get("status", "N/A")],
        ["Created:", _fmt_dt(job.get("created_at"))],
        ["Completed:", _fmt_dt(job.get("completed_at"))],
        ["Job ID:", str(job.get("id", ""))[:8] + "..."],
    ]
    t = Table(meta_data, colWidths=[1.5 * inch, 4.5 * inch])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), BRAND_ACCENT),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(PageBreak())

    # ------------------------------------------------------------------
    # 1. EXECUTIVE SUMMARY
    # ------------------------------------------------------------------
    story.append(Paragraph("1. Executive Summary", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#334155")))

    sev_counts = _count_severities(findings)
    total_findings = sum(sev_counts.values())
    risk_rating = _overall_risk(sev_counts)

    summary_text = (
        f"A penetration test was conducted against <b>{', '.join(job.get('targets', ['N/A']))}</b> "
        f"using the <b>{job.get('phase', 'N/A')}</b> methodology. "
        f"The assessment identified <b>{total_findings}</b> findings: "
        f"<font color='#dc2626'>{sev_counts.get('critical', 0)} critical</font>, "
        f"<font color='#ea580c'>{sev_counts.get('high', 0)} high</font>, "
        f"<font color='#eab308'>{sev_counts.get('medium', 0)} medium</font>, "
        f"<font color='#3b82f6'>{sev_counts.get('low', 0)} low</font>, and "
        f"{sev_counts.get('info', 0)} informational. "
        f"Overall risk rating: <b>{risk_rating}</b>."
    )
    story.append(Paragraph(summary_text, styles["BodyDark"]))
    story.append(Spacer(1, 0.2 * inch))

    # Severity summary table
    sev_table_data = [["Severity", "Count"]]
    for sev in ["critical", "high", "medium", "low", "info"]:
        sev_table_data.append([sev.upper(), str(sev_counts.get(sev, 0))])
    st = Table(sev_table_data, colWidths=[2 * inch, 1.5 * inch])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BRAND_ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    # Color-code severity rows
    for idx, sev in enumerate(["critical", "high", "medium", "low", "info"], 1):
        st.setStyle(TableStyle([
            ("TEXTCOLOR", (0, idx), (0, idx), SEVERITY_COLORS.get(sev, SEV_INFO)),
        ]))
    story.append(st)
    story.append(PageBreak())

    # ------------------------------------------------------------------
    # 2. METHODOLOGY
    # ------------------------------------------------------------------
    story.append(Paragraph("2. Methodology", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#334155")))

    story.append(Paragraph(
        "This assessment was conducted using TazoSploit, an AI-driven automated penetration testing "
        "platform. The AI agent autonomously selects tools, analyzes results, and iterates through "
        "the MITRE ATT&CK framework to discover vulnerabilities.",
        styles["BodyDark"]
    ))
    story.append(Spacer(1, 0.15 * inch))

    if tools_used:
        story.append(Paragraph("<b>Tools Employed:</b>", styles["BodyDark"]))
        tools_text = ", ".join(tools_used)
        story.append(Paragraph(tools_text, styles["BodyDark"]))
        story.append(Spacer(1, 0.1 * inch))

    if mitre_techniques:
        story.append(Paragraph("<b>MITRE ATT&CK Techniques:</b>", styles["BodyDark"]))
        for tech in mitre_techniques[:15]:
            story.append(Paragraph(
                f"• <b>{tech.get('id', 'N/A')}</b> — {tech.get('name', 'Unknown')}",
                styles["BodyDark"]
            ))
    story.append(PageBreak())

    # ------------------------------------------------------------------
    # 3. FINDINGS
    # ------------------------------------------------------------------
    story.append(Paragraph("3. Findings", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#334155")))

    if not findings:
        story.append(Paragraph("No structured findings were recorded.", styles["BodyDark"]))
    else:
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "info").lower()
            sev_color = SEVERITY_COLORS.get(sev, SEV_INFO)

            block = []
            block.append(Paragraph(
                f'<font color="{sev_color.hexval()}">[{sev.upper()}]</font> '
                f'<b>{f.get("title", f"Finding {i}")}</b>',
                styles["SubHeading"]
            ))

            if f.get("description"):
                block.append(Paragraph(f.get("description", ""), styles["BodyDark"]))

            if f.get("target"):
                block.append(Paragraph(f"<b>Target:</b> {f['target']}", styles["BodyDark"]))

            if f.get("mitre_technique"):
                block.append(Paragraph(
                    f"<b>MITRE ATT&CK:</b> {f['mitre_technique']}", styles["BodyDark"]
                ))

            if f.get("evidence"):
                ev = f["evidence"][:600]
                block.append(Paragraph(f"<b>Evidence:</b>", styles["BodyDark"]))
                block.append(Paragraph(ev.replace("\n", "<br/>"), styles["Evidence"]))

            if f.get("remediation"):
                block.append(Paragraph(
                    f"<b>Remediation:</b> {f['remediation']}", styles["BodyDark"]
                ))

            block.append(Spacer(1, 0.15 * inch))
            block.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#e2e8f0")))
            block.append(Spacer(1, 0.1 * inch))
            story.append(KeepTogether(block))

    story.append(PageBreak())

    # ------------------------------------------------------------------
    # 4. CREDENTIALS DISCOVERED
    # ------------------------------------------------------------------
    story.append(Paragraph("4. Credentials Discovered", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#334155")))

    if credentials:
        cred_data = [["Service", "Username", "Password", "Source"]]
        for c in credentials:
            cred_data.append([
                str(c.get("service", "N/A")),
                str(c.get("username", "N/A")),
                "[REDACTED - available in platform]",
                str(c.get("source", "N/A"))[:40],
            ])
        ct = Table(cred_data, colWidths=[1.3 * inch, 1.5 * inch, 2 * inch, 1.5 * inch])
        ct.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_ACCENT),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#334155")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("TEXTCOLOR", (2, 1), (2, -1), colors.HexColor("#ef4444")),
        ]))
        story.append(ct)
    else:
        story.append(Paragraph("No credentials were discovered during this assessment.", styles["BodyDark"]))

    story.append(PageBreak())

    # ------------------------------------------------------------------
    # 5. ATTACK PATH
    # ------------------------------------------------------------------
    story.append(Paragraph("5. Attack Path", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#334155")))

    attack_path = job.get("result", {}).get("attack_path", "")
    if attack_path:
        story.append(Paragraph(str(attack_path), styles["BodyDark"]))
    else:
        story.append(Paragraph(
            "The AI agent autonomously progressed through reconnaissance, vulnerability scanning, "
            "and exploitation phases. Refer to the raw output in the appendix for the complete "
            "step-by-step attack narrative.",
            styles["BodyDark"]
        ))

    # ------------------------------------------------------------------
    # 6. RECOMMENDATIONS
    # ------------------------------------------------------------------
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph("6. Recommendations", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#334155")))

    recs = _generate_recommendations(findings, credentials, sev_counts)
    for idx, rec in enumerate(recs, 1):
        story.append(Paragraph(f"<b>{idx}.</b> {rec}", styles["BodyDark"]))
    story.append(PageBreak())

    # ------------------------------------------------------------------
    # 7. APPENDIX
    # ------------------------------------------------------------------
    story.append(Paragraph("7. Appendix — Agent Output Logs", styles["SectionHeading"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#334155")))

    if raw_output:
        # Truncate to avoid massive PDFs
        truncated = raw_output[:8000]
        if len(raw_output) > 8000:
            truncated += "\n\n... [truncated — full output available in platform]"
        story.append(Paragraph(truncated.replace("\n", "<br/>"), styles["Evidence"]))
    else:
        story.append(Paragraph("Full output available in the TazoSploit platform.", styles["BodyDark"]))

    # ------------------------------------------------------------------
    # FOOTER
    # ------------------------------------------------------------------
    story.append(Spacer(1, 0.5 * inch))
    story.append(HRFlowable(width="100%", thickness=1, color=BRAND_ACCENT))
    story.append(Paragraph(
        f"Report generated by TazoSploit on {datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=BRAND_DIM, alignment=TA_CENTER),
    ))

    # BUILD
    doc.build(story)
    return buf.getvalue()


# =============================================================================
# HELPERS
# =============================================================================

def _fmt_dt(dt) -> str:
    if not dt:
        return "N/A"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except Exception:
            return dt
    return dt.strftime("%B %d, %Y %H:%M UTC")


def _count_severities(findings: List[Dict]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1
    return counts


def _overall_risk(sev_counts: Dict[str, int]) -> str:
    if sev_counts.get("critical", 0) > 0:
        return "CRITICAL"
    if sev_counts.get("high", 0) > 0:
        return "HIGH"
    if sev_counts.get("medium", 0) > 0:
        return "MEDIUM"
    if sev_counts.get("low", 0) > 0:
        return "LOW"
    return "INFORMATIONAL"


def _generate_recommendations(
    findings: List[Dict],
    credentials: List[Dict],
    sev_counts: Dict[str, int],
) -> List[str]:
    recs = []

    if sev_counts.get("critical", 0) > 0:
        recs.append(
            "<font color='#dc2626'>IMMEDIATE:</font> Remediate all critical findings within 24-48 hours. "
            "These represent direct paths to system compromise."
        )
    if sev_counts.get("high", 0) > 0:
        recs.append(
            "Address high-severity findings within 1-2 weeks. Prioritize those with known exploits."
        )
    if credentials:
        recs.append(
            "Rotate all discovered credentials immediately. Implement strong password policies and MFA."
        )
    recs.append("Implement network segmentation to limit lateral movement potential.")
    recs.append("Deploy a Web Application Firewall (WAF) for public-facing services.")
    recs.append("Enable logging and monitoring across all services to detect future intrusions.")
    recs.append("Schedule regular penetration tests (quarterly recommended) to track improvement.")

    if sev_counts.get("medium", 0) > 0:
        recs.append("Remediate medium-severity findings within 30 days.")

    return recs
