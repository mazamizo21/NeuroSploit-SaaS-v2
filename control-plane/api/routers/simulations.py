"""
NeuroSploit SaaS v2 - Simulations Router
API endpoints for attack simulation and ML predictions
"""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from ..database import get_db
from ..models import Job, Finding
from ..auth import get_current_user
from services.simulation_service import SimulationService, ControlType
from services.ml_prediction_service import MLPredictionService
from services.attack_graph_service import AttackGraphService

router = APIRouter()

# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class SimulationResponse(BaseModel):
    simulation_type: str
    target_node_id: Optional[str]
    original_risk: int
    simulated_risk: int
    risk_change: int
    paths_affected: int
    paths_eliminated: int
    new_nodes: List[dict]
    new_edges: List[dict]
    recommendations: List[str]
    details: dict

class ControlSimulationRequest(BaseModel):
    control_type: str = Field(..., pattern="^(firewall|waf|ids|segmentation|mfa|patch_management)$")
    target_node_id: Optional[str] = None

class PredictionResponse(BaseModel):
    item_id: str
    item_name: str
    likelihood: float
    confidence: float
    factors: List[str]
    priority: str

class ThreatSummaryResponse(BaseModel):
    summary: dict
    top_exploit_targets: List[dict]
    top_attack_paths: List[dict]
    recommendations: List[str]

# =============================================================================
# SIMULATION ENDPOINTS
# =============================================================================

@router.post("/jobs/{job_id}/simulate/exploit", response_model=SimulationResponse)
async def simulate_exploit(
    job_id: UUID,
    vulnerability_id: str = Query(..., description="Node ID of vulnerability to exploit"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Simulate exploiting a vulnerability
    
    Shows what happens if an attacker successfully exploits this vulnerability:
    - New nodes created (exploit, access gained)
    - Risk score increase
    - New attack paths enabled
    """
    # Get attack graph
    from ..routers.attack_graphs import get_attack_graph
    graph_response = await get_attack_graph(job_id, db, current_user)
    
    graph = {
        "nodes": [n.dict() for n in graph_response.nodes],
        "edges": [e.dict() for e in graph_response.edges]
    }
    
    result = SimulationService.simulate_exploit(graph, vulnerability_id)
    
    return SimulationResponse(
        simulation_type=result.simulation_type.value,
        target_node_id=result.target_node_id,
        original_risk=result.original_risk,
        simulated_risk=result.simulated_risk,
        risk_change=result.risk_change,
        paths_affected=result.paths_affected,
        paths_eliminated=result.paths_eliminated,
        new_nodes=result.new_nodes,
        new_edges=result.new_edges,
        recommendations=result.recommendations,
        details=result.details
    )

@router.post("/jobs/{job_id}/simulate/patch", response_model=SimulationResponse)
async def simulate_patch(
    job_id: UUID,
    vulnerability_id: str = Query(..., description="Node ID of vulnerability to patch"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Simulate patching a vulnerability
    
    Shows the impact of remediating this vulnerability:
    - Risk score reduction
    - Attack paths eliminated
    - Remediation priority recommendation
    """
    from ..routers.attack_graphs import get_attack_graph
    graph_response = await get_attack_graph(job_id, db, current_user)
    
    graph = {
        "nodes": [n.dict() for n in graph_response.nodes],
        "edges": [e.dict() for e in graph_response.edges]
    }
    
    result = SimulationService.simulate_patch(graph, vulnerability_id)
    
    return SimulationResponse(
        simulation_type=result.simulation_type.value,
        target_node_id=result.target_node_id,
        original_risk=result.original_risk,
        simulated_risk=result.simulated_risk,
        risk_change=result.risk_change,
        paths_affected=result.paths_affected,
        paths_eliminated=result.paths_eliminated,
        new_nodes=result.new_nodes,
        new_edges=result.new_edges,
        recommendations=result.recommendations,
        details=result.details
    )

@router.post("/jobs/{job_id}/simulate/control", response_model=SimulationResponse)
async def simulate_control(
    job_id: UUID,
    request: ControlSimulationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Simulate adding a security control
    
    Control types:
    - firewall: Block network paths
    - waf: Block web attacks
    - ids: Increase attack detection
    - segmentation: Eliminate lateral movement
    - mfa: Protect against credential attacks
    - patch_management: Reduce vulnerability risk
    """
    from ..routers.attack_graphs import get_attack_graph
    graph_response = await get_attack_graph(job_id, db, current_user)
    
    graph = {
        "nodes": [n.dict() for n in graph_response.nodes],
        "edges": [e.dict() for e in graph_response.edges]
    }
    
    control_type = ControlType(request.control_type)
    result = SimulationService.simulate_control(graph, control_type, request.target_node_id)
    
    return SimulationResponse(
        simulation_type=result.simulation_type.value,
        target_node_id=result.target_node_id,
        original_risk=result.original_risk,
        simulated_risk=result.simulated_risk,
        risk_change=result.risk_change,
        paths_affected=result.paths_affected,
        paths_eliminated=result.paths_eliminated,
        new_nodes=result.new_nodes,
        new_edges=result.new_edges,
        recommendations=result.recommendations,
        details=result.details
    )

# =============================================================================
# ML PREDICTION ENDPOINTS
# =============================================================================

@router.get("/jobs/{job_id}/predictions/exploits", response_model=List[PredictionResponse])
async def predict_likely_exploits(
    job_id: UUID,
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Predict which vulnerabilities are most likely to be exploited
    
    Uses ML model considering:
    - Severity/CVSS score
    - CVE age
    - Exploit availability
    - Service type
    - MITRE technique
    """
    # Get findings
    result = await db.execute(
        select(Finding).where(
            and_(
                Finding.job_id == job_id,
                Finding.tenant_id == current_user["tenant_id"]
            )
        )
    )
    findings = result.scalars().all()
    
    vulnerabilities = [
        {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity,
            "cve_id": f.cve_id,
            "mitre_technique": f.mitre_technique,
            "target": f.target,
            "metadata": f.metadata or {}
        }
        for f in findings
        if f.finding_type in ["vulnerability", "cve"]
    ]
    
    predictions = MLPredictionService.predict_likely_exploits(vulnerabilities)
    
    return [
        PredictionResponse(
            item_id=p.item_id,
            item_name=p.item_name,
            likelihood=p.likelihood,
            confidence=p.confidence,
            factors=p.factors,
            priority=p.priority
        )
        for p in predictions[:limit]
    ]

@router.get("/jobs/{job_id}/predictions/paths", response_model=List[PredictionResponse])
async def predict_attack_paths(
    job_id: UUID,
    limit: int = Query(10, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Predict most likely attack paths
    
    Uses ML model considering:
    - Path length
    - Node risk scores
    - Edge difficulties
    - Critical techniques
    """
    from ..routers.attack_graphs import get_attack_graph
    graph_response = await get_attack_graph(job_id, db, current_user)
    
    graph = {
        "nodes": [n.dict() for n in graph_response.nodes],
        "edges": [e.dict() for e in graph_response.edges]
    }
    
    predictions = MLPredictionService.predict_attack_paths(graph, limit)
    
    return [
        PredictionResponse(
            item_id=p.item_id,
            item_name=p.item_name,
            likelihood=p.likelihood,
            confidence=p.confidence,
            factors=p.factors,
            priority=p.priority
        )
        for p in predictions
    ]

@router.get("/jobs/{job_id}/predictions/summary", response_model=ThreatSummaryResponse)
async def get_threat_summary(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get comprehensive ML-powered threat summary
    
    Includes:
    - Vulnerability exploit predictions
    - Attack path predictions
    - Overall threat assessment
    - Prioritized recommendations
    """
    from ..routers.attack_graphs import get_attack_graph
    
    # Get graph
    graph_response = await get_attack_graph(job_id, db, current_user)
    graph = {
        "nodes": [n.dict() for n in graph_response.nodes],
        "edges": [e.dict() for e in graph_response.edges]
    }
    
    # Get vulnerabilities
    result = await db.execute(
        select(Finding).where(
            and_(
                Finding.job_id == job_id,
                Finding.tenant_id == current_user["tenant_id"]
            )
        )
    )
    findings = result.scalars().all()
    
    vulnerabilities = [
        {
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity,
            "cve_id": f.cve_id,
            "mitre_technique": f.mitre_technique,
            "target": f.target,
            "metadata": f.metadata or {}
        }
        for f in findings
    ]
    
    summary = MLPredictionService.get_threat_summary(graph, vulnerabilities)
    
    return ThreatSummaryResponse(**summary)
