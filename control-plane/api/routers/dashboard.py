"""
TazoSploit SaaS v2 - Dashboard Router
Stats, MITRE heatmap data, and PDF report generation
"""

import uuid
import json
from datetime import datetime
from typing import List, Optional, Dict
from fastapi import APIRouter, HTTPException, Depends, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
import structlog
import io

from ..database import get_db
from ..models import Job, JobStatus, Finding, Tenant, Severity, CommandLog, MitreTechniqueHit
from ..auth import get_current_user

logger = structlog.get_logger()
router = APIRouter()

# Static tool → technique mapping (same as tool_technique_mapping.json but inline for speed)
TOOL_TECHNIQUE_MAP = {
    "nmap": [("T1046", "Network Service Discovery"), ("T1595", "Active Scanning")],
    "sqlmap": [("T1190", "Exploit Public-Facing Application"), ("T1213", "Data from Information Repositories")],
    "hydra": [("T1110", "Brute Force")],
    "nikto": [("T1595", "Active Scanning"), ("T1190", "Exploit Public-Facing Application")],
    "gobuster": [("T1083", "File and Directory Discovery"), ("T1595", "Active Scanning")],
    "dirb": [("T1083", "File and Directory Discovery")],
    "ffuf": [("T1083", "File and Directory Discovery")],
    "curl": [("T1071", "Application Layer Protocol"), ("T1213", "Data from Information Repositories")],
    "wget": [("T1071", "Application Layer Protocol")],
    "wpscan": [("T1595", "Active Scanning"), ("T1190", "Exploit Public-Facing Application")],
    "nuclei": [("T1595", "Active Scanning"), ("T1190", "Exploit Public-Facing Application")],
    "metasploit": [("T1190", "Exploit Public-Facing Application"), ("T1059", "Command and Scripting Interpreter")],
    "crackmapexec": [("T1021", "Remote Services"), ("T1110", "Brute Force")],
    "enum4linux": [("T1087", "Account Discovery"), ("T1135", "Network Share Discovery")],
    "smbclient": [("T1021", "Remote Services"), ("T1135", "Network Share Discovery")],
    "john": [("T1110", "Brute Force")],
    "hashcat": [("T1110", "Brute Force")],
    "searchsploit": [("T1588", "Obtain Capabilities")],
    "whatweb": [("T1595", "Active Scanning")],
    "masscan": [("T1046", "Network Service Discovery")],
    "ssh": [("T1021", "Remote Services")],
    "netcat": [("T1071", "Application Layer Protocol"), ("T1059", "Command and Scripting Interpreter")],
    "responder": [("T1557", "Adversary-in-the-Middle")],
    "mimikatz": [("T1003", "OS Credential Dumping")],
    "bloodhound": [("T1087", "Account Discovery")],
    "impacket": [("T1021", "Remote Services")],
    "linpeas": [("T1082", "System Information Discovery"), ("T1083", "File and Directory Discovery")],
    "winpeas": [("T1082", "System Information Discovery"), ("T1083", "File and Directory Discovery")],
}

# MITRE tactics ordered
MITRE_TACTICS = [
    {"id": "reconnaissance", "name": "Reconnaissance", "shortName": "Recon"},
    {"id": "resource-development", "name": "Resource Development", "shortName": "Resource Dev"},
    {"id": "initial-access", "name": "Initial Access", "shortName": "Initial Access"},
    {"id": "execution", "name": "Execution", "shortName": "Execution"},
    {"id": "persistence", "name": "Persistence", "shortName": "Persistence"},
    {"id": "privilege-escalation", "name": "Privilege Escalation", "shortName": "Priv Esc"},
    {"id": "defense-evasion", "name": "Defense Evasion", "shortName": "Def Evasion"},
    {"id": "credential-access", "name": "Credential Access", "shortName": "Cred Access"},
    {"id": "discovery", "name": "Discovery", "shortName": "Discovery"},
    {"id": "lateral-movement", "name": "Lateral Movement", "shortName": "Lateral Move"},
    {"id": "collection", "name": "Collection", "shortName": "Collection"},
    {"id": "command-and-control", "name": "Command and Control", "shortName": "C2"},
    {"id": "exfiltration", "name": "Exfiltration", "shortName": "Exfiltration"},
    {"id": "impact", "name": "Impact", "shortName": "Impact"},
]

# Technique → tactic mapping (simplified)
TECHNIQUE_TACTIC = {
    "T1595": "reconnaissance",
    "T1592": "reconnaissance",
    "T1589": "reconnaissance",
    "T1590": "reconnaissance",
    "T1593": "reconnaissance",
    "T1588": "resource-development",
    "T1190": "initial-access",
    "T1133": "initial-access",
    "T1059": "execution",
    "T1203": "execution",
    "T1078": "persistence",
    "T1068": "privilege-escalation",
    "T1548": "privilege-escalation",
    "T1082": "discovery",
    "T1083": "discovery",
    "T1046": "discovery",
    "T1087": "discovery",
    "T1135": "discovery",
    "T1057": "discovery",
    "T1018": "discovery",
    "T1110": "credential-access",
    "T1003": "credential-access",
    "T1557": "credential-access",
    "T1558": "credential-access",
    "T1040": "credential-access",
    "T1021": "lateral-movement",
    "T1071": "command-and-control",
    "T1213": "collection",
    "T1218": "defense-evasion",
    "T1027": "defense-evasion",
}


# =============================================================================
# RESPONSE MODELS
# =============================================================================

class DashboardStats(BaseModel):
    total_pentests: int
    active_scans: int
    total_findings: int
    critical_findings: int
    high_findings: int
    completed_jobs: int

class MitreHeatmapCell(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    count: int
    jobs: List[str]  # job IDs

class MitreHeatmapResponse(BaseModel):
    tactics: List[dict]
    techniques: List[MitreHeatmapCell]

class ActivityItem(BaseModel):
    id: str
    type: str  # finding, job_completed, job_started
    title: str
    detail: str
    severity: Optional[str] = None
    timestamp: str

class SeverityDistribution(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    info: int


# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get dashboard statistics"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id

    result = await db.execute(select(Job).where(Job.tenant_id == tenant_id))
    jobs = result.scalars().all()

    total = len(jobs)
    active = sum(1 for j in jobs if j.status in (JobStatus.running, JobStatus.queued, JobStatus.pending))
    completed = sum(1 for j in jobs if j.status == JobStatus.completed)
    total_findings = sum(j.findings_count or 0 for j in jobs)
    critical = sum(j.critical_count or 0 for j in jobs)
    high = sum(j.high_count or 0 for j in jobs)

    return DashboardStats(
        total_pentests=total,
        active_scans=active,
        total_findings=total_findings,
        critical_findings=critical,
        high_findings=high,
        completed_jobs=completed,
    )


@router.get("/severity-distribution", response_model=SeverityDistribution)
async def get_severity_distribution(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get finding severity distribution across all jobs"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id

    result = await db.execute(
        select(Finding).where(Finding.tenant_id == tenant_id)
    )
    findings = result.scalars().all()

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        if sev in counts:
            counts[sev] += 1

    return SeverityDistribution(**counts)


@router.get("/mitre-heatmap", response_model=MitreHeatmapResponse)
async def get_mitre_heatmap(
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get MITRE ATT&CK heatmap data based on tool usage across all jobs"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id

    # Get all jobs with results
    result = await db.execute(
        select(Job).where(Job.tenant_id == tenant_id)
    )
    jobs = result.scalars().all()

    # Also get findings with mitre_technique
    findings_result = await db.execute(
        select(Finding).where(Finding.tenant_id == tenant_id)
    )
    findings = findings_result.scalars().all()

    # Aggregate technique hits
    # technique_id -> {name, count, jobs}
    technique_hits: Dict[str, dict] = {}

    for job in jobs:
        job_result = job.result or {}
        tools_used = job_result.get("tools_used", [])
        raw_output = job_result.get("raw_output", "") or job_result.get("output", "") or ""

        # Check tool-technique mapping
        matched_tools = set()
        for tool_name in tools_used:
            tool_lower = tool_name.lower().strip()
            matched_tools.add(tool_lower)

        # Also scan raw output for tool names
        raw_lower = raw_output.lower() if raw_output else ""
        for tool_name in TOOL_TECHNIQUE_MAP:
            if tool_name in raw_lower:
                matched_tools.add(tool_name)

        # Map tools to techniques
        for tool_name in matched_tools:
            if tool_name in TOOL_TECHNIQUE_MAP:
                for tech_id, tech_name in TOOL_TECHNIQUE_MAP[tool_name]:
                    if tech_id not in technique_hits:
                        technique_hits[tech_id] = {
                            "name": tech_name,
                            "count": 0,
                            "jobs": set(),
                        }
                    technique_hits[tech_id]["count"] += 1
                    technique_hits[tech_id]["jobs"].add(str(job.id)[:8])

    # Add from findings with mitre_technique
    for f in findings:
        if f.mitre_technique:
            tech_id = f.mitre_technique.split(".")[0] if "." in f.mitre_technique else f.mitre_technique
            if tech_id not in technique_hits:
                technique_hits[tech_id] = {
                    "name": tech_id,
                    "count": 0,
                    "jobs": set(),
                }
            technique_hits[tech_id]["count"] += 1
            if f.job_id:
                technique_hits[tech_id]["jobs"].add(str(f.job_id)[:8])

    # Build response
    cells = []
    for tech_id, data in technique_hits.items():
        tactic = TECHNIQUE_TACTIC.get(tech_id, "discovery")
        cells.append(MitreHeatmapCell(
            technique_id=tech_id,
            technique_name=data["name"],
            tactic=tactic,
            count=data["count"],
            jobs=list(data["jobs"]),
        ))

    # Sort by tactic then by count desc
    tactic_order = {t["id"]: i for i, t in enumerate(MITRE_TACTICS)}
    cells.sort(key=lambda c: (tactic_order.get(c.tactic, 99), -c.count))

    return MitreHeatmapResponse(tactics=MITRE_TACTICS, techniques=cells)


@router.get("/activity", response_model=List[ActivityItem])
async def get_recent_activity(
    limit: int = Query(20, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get recent activity feed"""
    tenant_id = uuid.UUID(current_user.tenant_id) if isinstance(current_user.tenant_id, str) else current_user.tenant_id

    items: List[ActivityItem] = []

    # Recent completed/failed jobs
    result = await db.execute(
        select(Job).where(
            and_(Job.tenant_id == tenant_id, Job.status.in_([JobStatus.completed, JobStatus.failed]))
        ).order_by(Job.completed_at.desc()).limit(limit)
    )
    for j in result.scalars().all():
        items.append(ActivityItem(
            id=str(j.id),
            type="job_completed" if j.status == JobStatus.completed else "job_failed",
            title=f"{'✅' if j.status == JobStatus.completed else '❌'} {j.name}",
            detail=f"{j.findings_count or 0} findings, {j.phase}",
            timestamp=(j.completed_at or j.created_at).isoformat(),
        ))

    # Recent critical/high findings
    findings_result = await db.execute(
        select(Finding).where(
            and_(
                Finding.tenant_id == tenant_id,
                Finding.severity.in_([Severity.critical, Severity.high])
            )
        ).order_by(Finding.created_at.desc()).limit(limit)
    )
    for f in findings_result.scalars().all():
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
        items.append(ActivityItem(
            id=str(f.id),
            type="finding",
            title=f"🔍 {f.title}",
            detail=f.target or "",
            severity=sev,
            timestamp=f.created_at.isoformat() if f.created_at else "",
        ))

    # Sort by timestamp desc
    items.sort(key=lambda x: x.timestamp, reverse=True)
    return items[:limit]


# =============================================================================
# PDF REPORT ENDPOINT
# =============================================================================

@router.get("/jobs/{job_id}/report")
async def download_report(
    job_id: str,
    format: str = Query("pdf", pattern="^(pdf|html)$"),
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Generate and download a pentest report for a job"""
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or str(job.tenant_id) != str(current_user.tenant_id):
        raise HTTPException(status_code=404, detail="Job not found")

    # Gather data
    result_data = job.result or {}
    comp = result_data.get("comprehensive_findings", {})

    # Findings from DB
    findings_result = await db.execute(
        select(Finding).where(Finding.job_id == uuid.UUID(job_id))
    )
    db_findings = findings_result.scalars().all()
    findings_list = [
        {
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
            "target": f.target,
            "evidence": f.evidence,
            "mitre_technique": f.mitre_technique,
            "remediation": f.remediation,
        }
        for f in db_findings
    ]

    # Also include inline findings from result JSON
    for rf in result_data.get("findings", []):
        findings_list.append({
            "title": rf.get("title", rf.get("name", "Finding")),
            "description": rf.get("description", ""),
            "severity": rf.get("severity", "info"),
            "target": rf.get("target", ""),
            "evidence": rf.get("evidence", ""),
            "mitre_technique": rf.get("mitre_technique", ""),
            "remediation": rf.get("remediation", ""),
        })

    # Credentials
    credentials = comp.get("credentials", result_data.get("credentials", []))

    # Tools used
    tools_used = result_data.get("tools_used", [])

    # Raw output
    raw_output = result_data.get("raw_output", result_data.get("output", ""))

    # Build job dict
    job_dict = {
        "id": str(job.id),
        "name": job.name,
        "phase": job.phase,
        "targets": job.targets,
        "status": job.status.value if hasattr(job.status, 'value') else str(job.status),
        "created_at": job.created_at,
        "completed_at": job.completed_at,
        "result": result_data,
    }

    if format == "pdf":
        from services.pdf_report import generate_pdf_report
        pdf_bytes = generate_pdf_report(
            job=job_dict,
            findings=findings_list,
            credentials=credentials,
            tools_used=tools_used,
            raw_output=raw_output,
        )
        filename = f"TazoSploit_Report_{job.name.replace(' ', '_')}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    else:
        # HTML fallback
        from services.report_generator import ReportGenerator
        risk_score = {
            "overall_score": 50,
            "risk_level": "medium",
            "attack_surface_score": 40,
            "exploitability_score": 50,
            "impact_score": 60,
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "total_findings": len(findings_list),
        }
        exec_summary = ReportGenerator.generate_executive_summary(job_dict, findings_list, risk_score)
        detailed = ReportGenerator.generate_detailed_report(job_dict, findings_list, risk_score)
        html = ReportGenerator.generate_html_report(job_dict, findings_list, risk_score, exec_summary, detailed)
        return StreamingResponse(
            io.BytesIO(html.encode()),
            media_type="text/html",
        )
