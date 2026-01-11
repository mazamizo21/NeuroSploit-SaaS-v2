"""
NeuroSploit SaaS v2 - Attack Graphs Router
API endpoints for attack path visualization
"""

from typing import List, Optional
from uuid import UUID
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from ..database import get_db
from ..models import Job, Finding, AttackNode, AttackEdge, AttackPath, CriticalAsset, Tenant
from ..auth import get_current_user
from services.attack_graph_service import AttackGraphService

router = APIRouter()

# =============================================================================
# REQUEST/RESPONSE MODELS
# =============================================================================

class NodeResponse(BaseModel):
    id: str
    type: str
    name: str
    description: Optional[str] = None
    risk_score: int
    mitre_techniques: List[str]
    metadata: dict

class EdgeResponse(BaseModel):
    id: str
    source: str
    target: str
    type: str
    technique_id: Optional[str] = None
    difficulty: str
    impact: str
    metadata: dict

class PathResponse(BaseModel):
    id: Optional[str] = None
    name: str
    path_nodes: List[str]
    risk_score: int
    length: int
    is_critical: bool = False
    start_node: str
    end_node: str

class AttackGraphResponse(BaseModel):
    job_id: str
    nodes: List[NodeResponse]
    edges: List[EdgeResponse]
    paths: List[PathResponse] = []
    node_count: int
    edge_count: int
    recommendations: List[str] = []

class CriticalAssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    asset_type: str = Field(..., min_length=1, max_length=50)
    criticality: str = Field(default="high", pattern="^(low|medium|high|critical)$")
    identifiers: dict = Field(default_factory=dict)
    metadata: dict = Field(default_factory=dict)

class CriticalAssetResponse(BaseModel):
    id: str
    name: str
    asset_type: str
    criticality: str
    identifiers: dict
    metadata: dict
    created_at: str

# =============================================================================
# ATTACK GRAPH ENDPOINTS
# =============================================================================

@router.post("/jobs/{job_id}/build", response_model=AttackGraphResponse)
async def build_attack_graph(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Build attack graph from job findings
    
    Creates nodes and edges representing the attack surface,
    vulnerabilities, and potential attack paths.
    """
    # Get job and verify access
    result = await db.execute(
        select(Job).where(
            and_(
                Job.id == job_id,
                Job.tenant_id == current_user["tenant_id"]
            )
        )
    )
    job = result.scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Get findings for job
    findings_result = await db.execute(
        select(Finding).where(Finding.job_id == job_id)
    )
    findings = findings_result.scalars().all()
    
    # Convert findings to dictionaries
    findings_data = [
        {
            "finding_type": f.finding_type,
            "target": f.target,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "mitre_technique": f.mitre_technique,
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "metadata": f.metadata or {}
        }
        for f in findings
    ]
    
    # Build graph using service
    graph = AttackGraphService.build_graph_from_findings(
        job_id=job_id,
        findings=findings_data,
        targets=job.targets if isinstance(job.targets, list) else [job.targets]
    )
    
    # Save nodes to database
    for node_data in graph["nodes"]:
        node = AttackNode(
            job_id=job_id,
            tenant_id=current_user["tenant_id"],
            node_type=node_data["type"],
            name=node_data["name"],
            description=node_data.get("description"),
            risk_score=node_data.get("risk_score", 0),
            mitre_techniques=node_data.get("mitre_techniques", []),
            node_metadata=node_data.get("metadata", {})
        )
        # Use the ID from graph for consistency
        node.id = UUID(node_data["id"].replace("host-", "").replace("service-", "").replace("vuln-", "").replace("exploit-", "")[:36].ljust(36, '0'))
        db.add(node)
    
    # Save edges to database
    for edge_data in graph["edges"]:
        edge = AttackEdge(
            job_id=job_id,
            tenant_id=current_user["tenant_id"],
            source_node_id=UUID(edge_data["source"].replace("host-", "").replace("service-", "").replace("vuln-", "").replace("exploit-", "")[:36].ljust(36, '0')),
            target_node_id=UUID(edge_data["target"].replace("host-", "").replace("service-", "").replace("vuln-", "").replace("exploit-", "")[:36].ljust(36, '0')),
            edge_type=edge_data["type"],
            technique_id=edge_data.get("technique_id"),
            difficulty=edge_data.get("difficulty", "medium"),
            impact=edge_data.get("impact", "medium"),
            edge_metadata=edge_data.get("metadata", {})
        )
        db.add(edge)
    
    await db.commit()
    
    return AttackGraphResponse(
        job_id=str(job_id),
        nodes=[NodeResponse(**n) for n in graph["nodes"]],
        edges=[EdgeResponse(**e) for e in graph["edges"]],
        node_count=graph["node_count"],
        edge_count=graph["edge_count"]
    )

@router.get("/jobs/{job_id}", response_model=AttackGraphResponse)
async def get_attack_graph(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get existing attack graph for a job"""
    # Verify job access
    result = await db.execute(
        select(Job).where(
            and_(
                Job.id == job_id,
                Job.tenant_id == current_user["tenant_id"]
            )
        )
    )
    job = result.scalar_one_or_none()
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Get nodes
    nodes_result = await db.execute(
        select(AttackNode).where(AttackNode.job_id == job_id)
    )
    nodes = nodes_result.scalars().all()
    
    # Get edges
    edges_result = await db.execute(
        select(AttackEdge).where(AttackEdge.job_id == job_id)
    )
    edges = edges_result.scalars().all()
    
    # Get paths
    paths_result = await db.execute(
        select(AttackPath).where(AttackPath.job_id == job_id)
    )
    paths = paths_result.scalars().all()
    
    return AttackGraphResponse(
        job_id=str(job_id),
        nodes=[
            NodeResponse(
                id=str(n.id),
                type=n.node_type,
                name=n.name,
                description=n.description,
                risk_score=n.risk_score,
                mitre_techniques=n.mitre_techniques or [],
                metadata=n.node_metadata or {}
            )
            for n in nodes
        ],
        edges=[
            EdgeResponse(
                id=str(e.id),
                source=str(e.source_node_id),
                target=str(e.target_node_id),
                type=e.edge_type,
                technique_id=e.technique_id,
                difficulty=e.difficulty,
                impact=e.impact,
                metadata=e.edge_metadata or {}
            )
            for e in edges
        ],
        paths=[
            PathResponse(
                id=str(p.id),
                name=p.name,
                path_nodes=p.path_nodes or [],
                risk_score=p.total_risk_score,
                length=p.length,
                is_critical=p.is_critical,
                start_node=str(p.start_node_id) if p.start_node_id else "",
                end_node=str(p.end_node_id) if p.end_node_id else ""
            )
            for p in paths
        ],
        node_count=len(nodes),
        edge_count=len(edges)
    )

@router.get("/jobs/{job_id}/paths", response_model=List[PathResponse])
async def find_attack_paths(
    job_id: UUID,
    start_node: Optional[str] = Query(None),
    end_node: Optional[str] = Query(None),
    min_risk: Optional[int] = Query(None, ge=0, le=100),
    max_hops: int = Query(10, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Find attack paths in graph
    
    Query parameters:
    - start_node: Starting node ID (optional)
    - end_node: Ending node ID (optional)
    - min_risk: Minimum risk score filter
    - max_hops: Maximum path length
    """
    # Get graph
    graph_response = await get_attack_graph(job_id, db, current_user)
    
    # Convert to service format
    graph = {
        "nodes": [n.dict() for n in graph_response.nodes],
        "edges": [e.dict() for e in graph_response.edges]
    }
    
    # Find all paths or specific path
    if start_node and end_node:
        paths = AttackGraphService.find_all_paths(
            graph, start_node, end_node, max_hops
        )
    else:
        # Find all possible paths (entry points to any node)
        paths = []
        # This would be expensive, so limit it
        raise HTTPException(
            status_code=400,
            detail="Please specify start_node and end_node for path finding"
        )
    
    # Calculate risk for each path and filter
    path_responses = []
    for path_nodes in paths:
        risk_score = AttackGraphService.calculate_path_risk(graph, path_nodes)
        
        if min_risk is None or risk_score >= min_risk:
            path_responses.append(PathResponse(
                name=f"Path: {path_nodes[0]} → {path_nodes[-1]}",
                path_nodes=path_nodes,
                risk_score=risk_score,
                length=len(path_nodes),
                is_critical=risk_score >= 75,
                start_node=path_nodes[0],
                end_node=path_nodes[-1]
            ))
    
    # Sort by risk score
    path_responses.sort(key=lambda p: p.risk_score, reverse=True)
    
    return path_responses

@router.get("/jobs/{job_id}/paths/critical", response_model=List[PathResponse])
async def get_critical_paths(
    job_id: UUID,
    max_paths: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get critical attack paths leading to critical assets
    
    Returns paths sorted by risk score that lead to
    tenant's defined critical assets.
    """
    # Get graph
    graph_response = await get_attack_graph(job_id, db, current_user)
    
    # Get critical assets for tenant
    assets_result = await db.execute(
        select(CriticalAsset).where(
            CriticalAsset.tenant_id == current_user["tenant_id"]
        )
    )
    critical_assets = assets_result.scalars().all()
    
    if not critical_assets:
        return []
    
    # Convert to service format
    graph = {
        "nodes": [n.dict() for n in graph_response.nodes],
        "edges": [e.dict() for e in graph_response.edges]
    }
    
    assets_data = [
        {
            "name": a.name,
            "asset_type": a.asset_type,
            "criticality": a.criticality,
            "identifiers": a.identifiers or {}
        }
        for a in critical_assets
    ]
    
    # Find critical paths
    critical_paths = AttackGraphService.identify_critical_paths(
        graph, assets_data, max_paths
    )
    
    # Save paths to database
    for path_data in critical_paths:
        path = AttackPath(
            job_id=job_id,
            tenant_id=current_user["tenant_id"],
            name=f"Critical Path: {path_data['start_node']} → {path_data['end_node']}",
            path_nodes=path_data["path_nodes"],
            total_risk_score=path_data["risk_score"],
            length=path_data["length"],
            is_critical=True,
            leads_to_critical_asset=True
        )
        db.add(path)
    
    await db.commit()
    
    return [PathResponse(**p) for p in critical_paths]

@router.get("/jobs/{job_id}/recommendations")
async def get_attack_graph_recommendations(
    job_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get remediation recommendations based on attack paths"""
    # Get critical paths
    critical_paths = await get_critical_paths(job_id, 10, db, current_user)
    
    if not critical_paths:
        return {"recommendations": ["✅ No critical attack paths identified"]}
    
    # Get graph for analysis
    graph_response = await get_attack_graph(job_id, db, current_user)
    graph = {
        "nodes": [n.dict() for n in graph_response.nodes],
        "edges": [e.dict() for e in graph_response.edges]
    }
    
    # Generate recommendations
    paths_data = [p.dict() for p in critical_paths]
    recommendations = AttackGraphService.generate_recommendations(paths_data, graph)
    
    return {"recommendations": recommendations}

@router.get("/jobs/{job_id}/export")
async def export_attack_graph(
    job_id: UUID,
    format: str = Query("json", pattern="^(json|graphml|cytoscape)$"),
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Export attack graph in various formats
    
    Supported formats:
    - json: Standard JSON format
    - graphml: GraphML XML format
    - cytoscape: Cytoscape.js JSON format
    """
    # Get graph
    graph_response = await get_attack_graph(job_id, db, current_user)
    
    if format == "json":
        return graph_response.dict()
    
    elif format == "cytoscape":
        # Cytoscape.js format
        elements = []
        
        # Add nodes
        for node in graph_response.nodes:
            elements.append({
                "data": {
                    "id": node.id,
                    "label": node.name,
                    "type": node.type,
                    "risk_score": node.risk_score,
                    "description": node.description
                },
                "classes": node.type
            })
        
        # Add edges
        for edge in graph_response.edges:
            elements.append({
                "data": {
                    "id": edge.id,
                    "source": edge.source,
                    "target": edge.target,
                    "label": edge.type,
                    "technique": edge.technique_id,
                    "impact": edge.impact
                },
                "classes": edge.type
            })
        
        return {"elements": elements}
    
    elif format == "graphml":
        # GraphML XML format (simplified)
        nodes_xml = "\n".join([
            f'  <node id="{n.id}"><data key="name">{n.name}</data><data key="type">{n.type}</data></node>'
            for n in graph_response.nodes
        ])
        
        edges_xml = "\n".join([
            f'  <edge source="{e.source}" target="{e.target}"><data key="type">{e.type}</data></edge>'
            for e in graph_response.edges
        ])
        
        graphml = f"""<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
  <key id="name" for="node" attr.name="name" attr.type="string"/>
  <key id="type" for="node" attr.name="type" attr.type="string"/>
  <key id="type" for="edge" attr.name="type" attr.type="string"/>
  <graph id="attack_graph" edgedefault="directed">
{nodes_xml}
{edges_xml}
  </graph>
</graphml>"""
        
        return {"graphml": graphml}
    
    return graph_response.dict()

# =============================================================================
# CRITICAL ASSET ENDPOINTS
# =============================================================================

@router.post("/critical-assets", response_model=CriticalAssetResponse)
async def create_critical_asset(
    asset: CriticalAssetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Define a critical asset (crown jewel) for the tenant"""
    critical_asset = CriticalAsset(
        tenant_id=current_user["tenant_id"],
        created_by=current_user["user_id"],
        name=asset.name,
        asset_type=asset.asset_type,
        criticality=asset.criticality,
        identifiers=asset.identifiers,
        asset_metadata=asset.metadata
    )
    
    db.add(critical_asset)
    await db.commit()
    await db.refresh(critical_asset)
    
    return CriticalAssetResponse(
        id=str(critical_asset.id),
        name=critical_asset.name,
        asset_type=critical_asset.asset_type,
        criticality=critical_asset.criticality,
        identifiers=critical_asset.identifiers or {},
        metadata=critical_asset.asset_metadata or {},
        created_at=critical_asset.created_at.isoformat()
    )

@router.get("/critical-assets", response_model=List[CriticalAssetResponse])
async def list_critical_assets(
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """List all critical assets for the tenant"""
    result = await db.execute(
        select(CriticalAsset).where(
            CriticalAsset.tenant_id == current_user["tenant_id"]
        )
    )
    assets = result.scalars().all()
    
    return [
        CriticalAssetResponse(
            id=str(a.id),
            name=a.name,
            asset_type=a.asset_type,
            criticality=a.criticality,
            identifiers=a.identifiers or {},
            metadata=a.asset_metadata or {},
            created_at=a.created_at.isoformat()
        )
        for a in assets
    ]

@router.delete("/critical-assets/{asset_id}")
async def delete_critical_asset(
    asset_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete a critical asset"""
    result = await db.execute(
        select(CriticalAsset).where(
            and_(
                CriticalAsset.id == asset_id,
                CriticalAsset.tenant_id == current_user["tenant_id"]
            )
        )
    )
    asset = result.scalar_one_or_none()
    
    if not asset:
        raise HTTPException(status_code=404, detail="Critical asset not found")
    
    await db.delete(asset)
    await db.commit()
    
    return {"message": "Critical asset deleted"}
