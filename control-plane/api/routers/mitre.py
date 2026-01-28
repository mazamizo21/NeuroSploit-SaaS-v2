"""
TazoSploit SaaS v2 - MITRE ATT&CK Router
API endpoints for MITRE ATT&CK framework integration
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from services.mitre_service import get_mitre_service

router = APIRouter()

# =============================================================================
# RESPONSE MODELS
# =============================================================================

class TechniqueResponse(BaseModel):
    id: str
    name: str
    description: str
    tactics: List[str]
    platforms: List[str]
    data_sources: List[str]
    detection: str
    is_subtechnique: bool
    url: str

class TacticResponse(BaseModel):
    id: str
    name: str
    description: str

class CoverageStatsResponse(BaseModel):
    total_techniques: int
    total_tactics: int
    total_tools: int
    mapped_tools: int
    techniques_by_tactic: dict

# =============================================================================
# ENDPOINTS
# =============================================================================

@router.get("/techniques", response_model=List[TechniqueResponse])
async def list_techniques(
    tactic: Optional[str] = Query(None, description="Filter by tactic"),
    search: Optional[str] = Query(None, description="Search in name/description"),
    limit: int = Query(100, ge=1, le=1000)
):
    """List MITRE ATT&CK techniques"""
    mitre = get_mitre_service()
    
    if tactic:
        techniques = mitre.get_techniques_by_tactic(tactic)
    elif search:
        techniques = mitre.search_techniques(search)
    else:
        techniques = list(mitre.techniques.values())
    
    return techniques[:limit]

@router.get("/techniques/{technique_id}", response_model=TechniqueResponse)
async def get_technique(technique_id: str):
    """Get details of a specific technique"""
    mitre = get_mitre_service()
    technique = mitre.get_technique(technique_id)
    
    if not technique:
        raise HTTPException(status_code=404, detail="Technique not found")
    
    return technique

@router.get("/tactics", response_model=List[TacticResponse])
async def list_tactics():
    """List all MITRE ATT&CK tactics"""
    mitre = get_mitre_service()
    return list(mitre.tactics.values())

@router.get("/tools/{tool_name}/techniques", response_model=List[TechniqueResponse])
async def get_tool_techniques(tool_name: str):
    """Get techniques associated with a tool"""
    mitre = get_mitre_service()
    techniques = mitre.get_techniques_for_tool(tool_name)
    
    if not techniques:
        raise HTTPException(
            status_code=404, 
            detail=f"No techniques found for tool '{tool_name}'"
        )
    
    return techniques

@router.get("/coverage", response_model=CoverageStatsResponse)
async def get_coverage():
    """Get MITRE ATT&CK coverage statistics"""
    mitre = get_mitre_service()
    return mitre.get_coverage_stats()

@router.get("/context")
async def get_ai_context(tool_name: Optional[str] = Query(None)):
    """Get MITRE ATT&CK context for AI system prompt"""
    mitre = get_mitre_service()
    context = mitre.get_ai_context(tool_name)
    return {"context": context}
