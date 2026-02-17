"""
TazoSploit SaaS v2 - Reports Router
API endpoints for risk scoring and report generation
"""

import io
import uuid
import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Response
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from ..database import get_db
from ..models import Job, Finding, RiskScore
from ..auth import get_current_user
from services.risk_scoring_service import RiskScoringService
from services.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

router = APIRouter()

# =============================================================================
# RESPONSE MODELS
# =============================================================================

class RiskScoreResponse(BaseModel):
    overall_score: int
    attack_surface_score: int
    exploitability_score: int
    impact_score: int
    severity_breakdown: dict
    risk_level: str
    total_findings: int
    recommendations: list
    calculated_at: str

# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/jobs/{job_id}/risk-score", response_model=RiskScoreResponse)
async def get_job_risk_score(
    job_id: str,
    recalculate: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get or calculate risk score for a job"""
    
    tenant_id = current_user.tenant_id
    
    # Get job
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Check if we have a cached score
    if not recalculate:
        result = await db.execute(
            select(RiskScore).where(RiskScore.job_id == uuid.UUID(job_id))
        )
        cached_score = result.scalar_one_or_none()
        
        if cached_score:
            return RiskScoreResponse(
                overall_score=cached_score.overall_score,
                attack_surface_score=cached_score.attack_surface_score,
                exploitability_score=cached_score.exploitability_score,
                impact_score=cached_score.impact_score,
                severity_breakdown=cached_score.severity_breakdown,
                risk_level=cached_score.risk_level,
                total_findings=cached_score.total_findings,
                recommendations=cached_score.recommendations,
                calculated_at=cached_score.calculated_at.isoformat()
            )
    
    # Get findings
    result = await db.execute(
        select(Finding).where(Finding.job_id == uuid.UUID(job_id))
    )
    findings = result.scalars().all()
    
    # Convert to dict for scoring
    findings_dict = [
        {
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, 'value') else f.severity,
            "finding_type": f.finding_type,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "mitre_technique": f.mitre_technique,
            "target": f.target,
            "evidence": f.evidence,
            "remediation": f.remediation
        }
        for f in findings
    ]
    
    # Calculate risk score
    risk_data = RiskScoringService.calculate_job_risk_score(
        findings=findings_dict,
        targets=job.targets,
        phase=job.phase
    )
    
    # Generate recommendations
    recommendations = RiskScoringService.generate_recommendations(
        risk_data, findings_dict
    )
    
    # Save to database
    risk_score = RiskScore(
        job_id=uuid.UUID(job_id),
        tenant_id=tenant_id,
        overall_score=risk_data["overall_score"],
        attack_surface_score=risk_data["attack_surface_score"],
        exploitability_score=risk_data["exploitability_score"],
        impact_score=risk_data["impact_score"],
        risk_level=risk_data["risk_level"],
        severity_breakdown=risk_data["severity_breakdown"],
        total_findings=risk_data["total_findings"],
        recommendations=recommendations
    )
    
    # Delete old score if exists
    if recalculate:
        await db.execute(
            select(RiskScore).where(RiskScore.job_id == uuid.UUID(job_id))
        )
        old_score = result.scalar_one_or_none()
        if old_score:
            await db.delete(old_score)
    
    db.add(risk_score)
    await db.commit()
    await db.refresh(risk_score)
    
    return RiskScoreResponse(
        overall_score=risk_score.overall_score,
        attack_surface_score=risk_score.attack_surface_score,
        exploitability_score=risk_score.exploitability_score,
        impact_score=risk_score.impact_score,
        severity_breakdown=risk_score.severity_breakdown,
        risk_level=risk_score.risk_level,
        total_findings=risk_score.total_findings,
        recommendations=risk_score.recommendations,
        calculated_at=risk_score.calculated_at.isoformat()
    )

@router.get("/jobs/{job_id}/report/executive")
async def get_executive_summary(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get executive summary for a job"""
    
    tenant_id = current_user.tenant_id
    
    # Get job
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Get findings
    result = await db.execute(
        select(Finding).where(Finding.job_id == uuid.UUID(job_id))
    )
    findings = result.scalars().all()
    
    # Get risk score
    result = await db.execute(
        select(RiskScore).where(RiskScore.job_id == uuid.UUID(job_id))
    )
    risk_score = result.scalar_one_or_none()
    
    if not risk_score:
        # Calculate if not exists
        risk_score_response = await get_job_risk_score(job_id, False, db, current_user)
        risk_score_dict = risk_score_response.dict()
    else:
        risk_score_dict = {
            "overall_score": risk_score.overall_score,
            "attack_surface_score": risk_score.attack_surface_score,
            "exploitability_score": risk_score.exploitability_score,
            "impact_score": risk_score.impact_score,
            "severity_breakdown": risk_score.severity_breakdown,
            "risk_level": risk_score.risk_level,
            "total_findings": risk_score.total_findings
        }
    
    # Convert job and findings to dict
    job_dict = {
        "id": str(job.id),
        "name": job.name,
        "targets": job.targets,
        "phase": job.phase,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at
    }
    
    findings_dict = [
        {
            "title": f.title,
            "severity": f.severity.value if hasattr(f.severity, 'value') else f.severity,
            "finding_type": f.finding_type,
            "cve_id": f.cve_id,
            "mitre_technique": f.mitre_technique,
            "target": f.target,
            "evidence": f.evidence,
            "remediation": f.remediation
        }
        for f in findings
    ]
    
    # Generate summary
    summary = ReportGenerator.generate_executive_summary(
        job_dict, findings_dict, risk_score_dict
    )
    
    return {"summary": summary, "format": "markdown"}

@router.get("/jobs/{job_id}/report/detailed")
async def get_detailed_report(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get detailed technical report for a job"""
    
    tenant_id = current_user.tenant_id
    
    # Get job
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Get findings
    result = await db.execute(
        select(Finding).where(Finding.job_id == uuid.UUID(job_id))
    )
    findings = result.scalars().all()
    
    # Get risk score
    result = await db.execute(
        select(RiskScore).where(RiskScore.job_id == uuid.UUID(job_id))
    )
    risk_score = result.scalar_one_or_none()
    
    if not risk_score:
        risk_score_response = await get_job_risk_score(job_id, False, db, current_user)
        risk_score_dict = risk_score_response.dict()
    else:
        risk_score_dict = {
            "overall_score": risk_score.overall_score,
            "attack_surface_score": risk_score.attack_surface_score,
            "exploitability_score": risk_score.exploitability_score,
            "impact_score": risk_score.impact_score,
            "severity_breakdown": risk_score.severity_breakdown,
            "risk_level": risk_score.risk_level,
            "total_findings": risk_score.total_findings
        }
    
    # Convert to dict
    job_dict = {
        "id": str(job.id),
        "name": job.name,
        "targets": job.targets,
        "phase": job.phase,
        "intensity": job.intensity,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at
    }
    
    findings_dict = [
        {
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value if hasattr(f.severity, 'value') else f.severity,
            "finding_type": f.finding_type,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "mitre_technique": f.mitre_technique,
            "target": f.target,
            "evidence": f.evidence,
            "remediation": f.remediation
        }
        for f in findings
    ]
    
    # Generate report
    report = ReportGenerator.generate_detailed_report(
        job_dict, findings_dict, risk_score_dict
    )
    
    return {"report": report, "format": "markdown"}

@router.get("/jobs/{job_id}/report/html", response_class=HTMLResponse)
async def get_html_report(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get HTML report for a job"""
    
    tenant_id = current_user.tenant_id
    
    # Get job
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Get findings
    result = await db.execute(
        select(Finding).where(Finding.job_id == uuid.UUID(job_id))
    )
    findings = result.scalars().all()
    
    # Get risk score
    result = await db.execute(
        select(RiskScore).where(RiskScore.job_id == uuid.UUID(job_id))
    )
    risk_score = result.scalar_one_or_none()
    
    if not risk_score:
        risk_score_response = await get_job_risk_score(job_id, False, db, current_user)
        risk_score_dict = risk_score_response.dict()
    else:
        risk_score_dict = {
            "overall_score": risk_score.overall_score,
            "attack_surface_score": risk_score.attack_surface_score,
            "exploitability_score": risk_score.exploitability_score,
            "impact_score": risk_score.impact_score,
            "severity_breakdown": risk_score.severity_breakdown,
            "risk_level": risk_score.risk_level,
            "total_findings": risk_score.total_findings
        }
    
    # Convert to dict
    job_dict = {
        "id": str(job.id),
        "name": job.name,
        "targets": job.targets,
        "phase": job.phase,
        "intensity": job.intensity,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at
    }
    
    findings_dict = [
        {
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value if hasattr(f.severity, 'value') else f.severity,
            "finding_type": f.finding_type,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "mitre_technique": f.mitre_technique,
            "target": f.target,
            "evidence": f.evidence,
            "remediation": f.remediation
        }
        for f in findings
    ]
    
    # Generate reports
    executive_summary = ReportGenerator.generate_executive_summary(
        job_dict, findings_dict, risk_score_dict
    )
    
    detailed_report = ReportGenerator.generate_detailed_report(
        job_dict, findings_dict, risk_score_dict
    )
    
    # Generate HTML
    html = ReportGenerator.generate_html_report(
        job_dict, findings_dict, risk_score_dict,
        executive_summary, detailed_report
    )
    
    return HTMLResponse(content=html)

@router.get("/jobs/{job_id}/report/pdf")
async def get_pdf_report(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Generate and download a professional PDF pentest report"""

    tenant_id = current_user.tenant_id

    # Get job
    job = await db.get(Job, uuid.UUID(job_id))
    if not job or job.tenant_id != tenant_id:
        raise HTTPException(status_code=404, detail="Job not found")

    # Get findings
    result = await db.execute(
        select(Finding).where(Finding.job_id == uuid.UUID(job_id))
    )
    findings = result.scalars().all()

    # Get risk score
    result = await db.execute(
        select(RiskScore).where(RiskScore.job_id == uuid.UUID(job_id))
    )
    risk_score = result.scalar_one_or_none()

    if not risk_score:
        risk_score_response = await get_job_risk_score(job_id, False, db, current_user)
        risk_score_dict = risk_score_response.dict()
    else:
        risk_score_dict = {
            "overall_score": risk_score.overall_score,
            "attack_surface_score": risk_score.attack_surface_score,
            "exploitability_score": risk_score.exploitability_score,
            "impact_score": risk_score.impact_score,
            "severity_breakdown": risk_score.severity_breakdown,
            "risk_level": risk_score.risk_level,
            "total_findings": risk_score.total_findings,
        }

    # Build data dicts
    job_dict = {
        "id": str(job.id),
        "name": job.name,
        "targets": job.targets,
        "phase": job.phase,
        "status": getattr(job, "status", "completed"),
        "created_at": job.created_at,
        "started_at": job.started_at,
        "completed_at": job.completed_at,
    }

    findings_dict = [
        {
            "title": f.title,
            "description": getattr(f, "description", ""),
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "finding_type": f.finding_type,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "mitre_technique": f.mitre_technique,
            "target": f.target,
            "evidence": f.evidence,
            "remediation": f.remediation,
        }
        for f in findings
    ]

    credentials_dict = []  # Credentials not exposed in this endpoint for security

    # Detect tools from findings
    tools_used = list(set(
        f.finding_type for f in findings if f.finding_type
    )) or ["automated assessment"]

    try:
        from services.pdf_report import generate_pdf_report as gen_pdf

        pdf_bytes = gen_pdf(
            job=job_dict,
            findings=findings_dict,
            credentials=credentials_dict,
            tools_used=tools_used,
            raw_output="",
            mitre_techniques=[
                {"id": f.mitre_technique, "name": f.title}
                for f in findings if f.mitre_technique
            ],
        )
    except ImportError:
        logger.warning("reportlab not installed, falling back to simple PDF")
        raise HTTPException(
            status_code=501,
            detail="PDF generation requires reportlab. Install with: pip install reportlab"
        )
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {str(e)}")

    # Optionally upload to MinIO for persistence
    try:
        from services.evidence_storage import upload_to_minio
        minio_key = f"reports/{tenant_id}/{job_id}/report.pdf"
        upload_to_minio(minio_key, pdf_bytes, content_type="application/pdf")
        logger.info(f"PDF report uploaded to MinIO: {minio_key}")
    except Exception:
        pass  # MinIO upload is best-effort; report still returned

    filename = f"TazoSploit_Report_{job_dict.get('name', job_id)[:30]}_{job_dict.get('created_at', 'report')}.pdf"
    # Sanitize filename
    filename = "".join(c for c in filename if c.isalnum() or c in "._- ").strip()
    if not filename.endswith(".pdf"):
        filename += ".pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/tenants/me/trends")
async def get_risk_trends(
    days: int = 30,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get risk trend analysis for tenant"""
    
    tenant_id = current_user.tenant_id
    
    # Get all risk scores for tenant
    result = await db.execute(
        select(RiskScore).where(RiskScore.tenant_id == tenant_id)
        .order_by(RiskScore.calculated_at)
    )
    risk_scores = result.scalars().all()
    
    # Convert to trend data
    historical_scores = [
        {
            "date": score.calculated_at,
            "score": score.overall_score,
            "risk_level": score.risk_level
        }
        for score in risk_scores
    ]
    
    # Calculate trends
    trend_data = RiskScoringService.calculate_trend_data(
        historical_scores, days
    )
    
    return trend_data
