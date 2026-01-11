"""
NeuroSploit SaaS v2 - MITRE ATT&CK Service
Loads, parses, and provides access to MITRE ATT&CK framework data
"""

import json
import os
import logging
from typing import List, Dict, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class MITREService:
    """Service for MITRE ATT&CK framework integration"""
    
    def __init__(self, data_path: str = None, mapping_path: str = None):
        self.data_path = data_path or os.path.join(
            Path(__file__).parent.parent.parent, 
            "data/mitre/enterprise-attack.json"
        )
        self.mapping_path = mapping_path or os.path.join(
            Path(__file__).parent,
            "tool_technique_mapping.json"
        )
        self.techniques: Dict[str, Dict] = {}
        self.tactics: Dict[str, Dict] = {}
        self.tools: Dict[str, Dict] = {}
        self.tool_technique_map: Dict[str, List[str]] = {}
        self._loaded = False
    
    def load(self):
        """Load and parse MITRE ATT&CK STIX data"""
        if self._loaded:
            return
        
        logger.info("Loading MITRE ATT&CK data", path=self.data_path)
        
        try:
            with open(self.data_path, 'r') as f:
                data = json.load(f)
            
            objects = data.get('objects', [])
            logger.info(f"Loaded {len(objects)} MITRE objects")
            
            # Parse techniques (attack-pattern)
            for obj in objects:
                if obj['type'] == 'attack-pattern':
                    technique_id = self._extract_technique_id(obj)
                    if technique_id:
                        self.techniques[technique_id] = {
                            'id': technique_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'tactics': self._extract_tactics(obj),
                            'platforms': obj.get('x_mitre_platforms', []),
                            'data_sources': obj.get('x_mitre_data_sources', []),
                            'detection': obj.get('x_mitre_detection', ''),
                            'is_subtechnique': '.' in technique_id,
                            'url': f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
                        }
            
            # Parse tactics (x-mitre-tactic)
            for obj in objects:
                if obj['type'] == 'x-mitre-tactic':
                    tactic_id = obj.get('x_mitre_shortname', '')
                    if tactic_id:
                        self.tactics[tactic_id] = {
                            'id': tactic_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', '')
                        }
            
            # Parse tools (tool type)
            for obj in objects:
                if obj['type'] == 'tool':
                    tool_name = obj.get('name', '').lower()
                    if tool_name:
                        self.tools[tool_name] = {
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'aliases': obj.get('x_mitre_aliases', [])
                        }
            
            # Parse relationships (tool -> technique)
            for obj in objects:
                if obj['type'] == 'relationship' and obj.get('relationship_type') == 'uses':
                    source_ref = obj.get('source_ref', '')
                    target_ref = obj.get('target_ref', '')
                    
                    # Find tool name from source
                    tool_name = None
                    for tool_obj in objects:
                        if tool_obj.get('id') == source_ref and tool_obj['type'] == 'tool':
                            tool_name = tool_obj.get('name', '').lower()
                            break
                    
                    # Find technique ID from target
                    technique_id = None
                    for tech_obj in objects:
                        if tech_obj.get('id') == target_ref and tech_obj['type'] == 'attack-pattern':
                            technique_id = self._extract_technique_id(tech_obj)
                            break
                    
                    if tool_name and technique_id:
                        if tool_name not in self.tool_technique_map:
                            self.tool_technique_map[tool_name] = []
                        self.tool_technique_map[tool_name].append(technique_id)
            
            # Load custom tool mappings (Kali tools)
            if os.path.exists(self.mapping_path):
                try:
                    with open(self.mapping_path, 'r') as f:
                        custom_mappings = json.load(f)
                    
                    for tool, techniques in custom_mappings.items():
                        if tool not in self.tool_technique_map:
                            self.tool_technique_map[tool] = []
                        self.tool_technique_map[tool].extend(techniques)
                    
                    logger.info(f"Loaded {len(custom_mappings)} custom tool mappings")
                except Exception as e:
                    logger.warning(f"Failed to load custom mappings: {e}")
            
            self._loaded = True
            logger.info(
                "MITRE ATT&CK data loaded",
                techniques=len(self.techniques),
                tactics=len(self.tactics),
                tools=len(self.tools),
                mappings=len(self.tool_technique_map)
            )
            
        except Exception as e:
            logger.error("Failed to load MITRE data", error=str(e))
            raise
    
    def _extract_technique_id(self, obj: Dict) -> Optional[str]:
        """Extract technique ID (T1234 or T1234.001) from object"""
        external_refs = obj.get('external_references', [])
        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id')
        return None
    
    def _extract_tactics(self, obj: Dict) -> List[str]:
        """Extract tactic names from technique object"""
        kill_chain_phases = obj.get('kill_chain_phases', [])
        tactics = []
        for phase in kill_chain_phases:
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactics.append(phase.get('phase_name', ''))
        return tactics
    
    def get_technique(self, technique_id: str) -> Optional[Dict]:
        """Get technique details by ID"""
        if not self._loaded:
            self.load()
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: str) -> List[Dict]:
        """Get all techniques for a tactic"""
        if not self._loaded:
            self.load()
        return [
            tech for tech in self.techniques.values()
            if tactic in tech['tactics']
        ]
    
    def get_techniques_for_tool(self, tool_name: str) -> List[Dict]:
        """Get techniques associated with a tool"""
        if not self._loaded:
            self.load()
        
        tool_name_lower = tool_name.lower()
        technique_ids = self.tool_technique_map.get(tool_name_lower, [])
        return [self.techniques[tid] for tid in technique_ids if tid in self.techniques]
    
    def search_techniques(self, query: str) -> List[Dict]:
        """Search techniques by name or description"""
        if not self._loaded:
            self.load()
        
        query_lower = query.lower()
        results = []
        for tech in self.techniques.values():
            if (query_lower in tech['name'].lower() or 
                query_lower in tech['description'].lower()):
                results.append(tech)
        return results
    
    def get_coverage_stats(self) -> Dict:
        """Get statistics on MITRE ATT&CK coverage"""
        if not self._loaded:
            self.load()
        
        return {
            'total_techniques': len(self.techniques),
            'total_tactics': len(self.tactics),
            'total_tools': len(self.tools),
            'mapped_tools': len(self.tool_technique_map),
            'techniques_by_tactic': {
                tactic: len(self.get_techniques_by_tactic(tactic))
                for tactic in self.tactics.keys()
            }
        }
    
    def get_ai_context(self, tool_name: Optional[str] = None) -> str:
        """
        Generate MITRE ATT&CK context for AI system prompt
        If tool_name provided, include specific techniques for that tool
        """
        if not self._loaded:
            self.load()
        
        context = """
# MITRE ATT&CK Framework Context

You have access to the MITRE ATT&CK framework for understanding adversary tactics and techniques.

## Tactics (High-Level Objectives):
"""
        for tactic_id, tactic in sorted(self.tactics.items()):
            context += f"- **{tactic['name']}** ({tactic_id}): {tactic['description'][:100]}...\n"
        
        if tool_name:
            techniques = self.get_techniques_for_tool(tool_name)
            if techniques:
                context += f"\n## Techniques for {tool_name}:\n"
                for tech in techniques[:10]:  # Limit to 10 to avoid token bloat
                    context += f"- **{tech['id']}**: {tech['name']} - {tech['description'][:150]}...\n"
        
        context += """
## Your Responsibilities:
1. When executing commands, identify which MITRE ATT&CK technique(s) you are using
2. Tag your findings with the appropriate technique ID (e.g., T1595 for Active Scanning)
3. Explain which tactic you are pursuing (e.g., Reconnaissance, Initial Access)
4. Consider the full attack chain and which techniques to use next

## Technique ID Format:
- Main techniques: T1234
- Sub-techniques: T1234.001

Always reference techniques by their ID when documenting findings.
"""
        return context

# Global instance
_mitre_service = None

def get_mitre_service() -> MITREService:
    """Get or create global MITRE service instance"""
    global _mitre_service
    if _mitre_service is None:
        _mitre_service = MITREService()
        _mitre_service.load()
    return _mitre_service
