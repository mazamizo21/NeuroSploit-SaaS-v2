#!/usr/bin/env python3
"""
TazoSploit Skills System
Loads and manages pentest capabilities (skills) for the DynamicAgent.

Skills are self-contained modules that define:
- Methodology and approach
- Available tools
- MITRE ATT&CK mappings
- Evidence collection requirements
"""

import os
import re
import yaml
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Tool:
    """Represents a tool available for a skill"""
    name: str
    description: str
    category: str
    install_cmd: Optional[str] = None
    verify_cmd: Optional[str] = None
    examples: List[str] = field(default_factory=list)


@dataclass
class Skill:
    """Represents a pentest capability/skill"""
    id: str
    name: str
    description: str
    methodology: str
    mitre_techniques: List[str]
    tools: List[Tool] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    evidence_collection: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    category: str = "custom"
    phase: str = ""
    target_types: List[str] = field(default_factory=list)
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    priority: int = 50
    safety_notes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    @classmethod
    def from_directory(cls, skill_dir: str) -> 'Skill':
        """Load skill from directory containing SKILL.md and tools.yaml"""
        skill_path = Path(skill_dir)
        skill_id = skill_path.name

        # Read SKILL.md (required)
        skill_md = skill_path / "SKILL.md"
        with open(skill_md, 'r') as f:
            md_content = f.read()

        # Read skill.yaml if present
        meta = {}
        meta_file = skill_path / "skill.yaml"
        if meta_file.exists():
            with open(meta_file, 'r') as f:
                meta = yaml.safe_load(f) or {}

        def _extract_overview(text: str) -> str:
            match = re.search(r"##\\s+Overview\\s*\\n(.+?)(\\n##|$)", text, re.S | re.I)
            if match:
                return match.group(1).strip()
            return ""

        name = meta.get("name") or skill_id.replace('_', ' ').title()
        description = meta.get("description") or _extract_overview(md_content)
        methodology = meta.get("methodology") or md_content
        mitre_techniques = meta.get("mitre_techniques") or []
        prerequisites = meta.get("prerequisites") or []
        evidence_collection = meta.get("evidence_collection") or []
        success_criteria = meta.get("success_criteria") or []
        category = meta.get("category", "custom")
        phase = meta.get("phase", "")
        target_types = meta.get("target_types") or []
        inputs = meta.get("inputs") or []
        outputs = meta.get("outputs") or []
        priority = int(meta.get("priority", 50))
        safety_notes = meta.get("safety_notes") or []
        tags = meta.get("tags") or []
        
        # Parse YAML tools.yaml if exists
        tools_file = skill_path / "tools.yaml"
        tools = []
        if tools_file.exists():
            with open(tools_file, 'r') as f:
                tools_data = yaml.safe_load(f)
                for tool_name, tool_info in tools_data.items():
                    tools.append(Tool(
                        name=tool_name,
                        description=tool_info.get('description', ''),
                        category=tool_info.get('category', 'general'),
                        install_cmd=tool_info.get('install_cmd'),
                        verify_cmd=tool_info.get('verify_cmd'),
                        examples=tool_info.get('examples', [])
                    ))
        
        return cls(
            id=meta.get("id", skill_id),
            name=name,
            description=description,
            methodology=methodology,
            mitre_techniques=mitre_techniques,
            tools=tools,
            prerequisites=prerequisites,
            evidence_collection=evidence_collection,
            success_criteria=success_criteria,
            category=category,
            phase=phase,
            target_types=target_types,
            inputs=inputs,
            outputs=outputs,
            priority=priority,
            safety_notes=safety_notes,
            tags=tags
        )
    
    def get_tools_by_category(self, category: str) -> List[Tool]:
        """Get tools filtered by category"""
        return [t for t in self.tools if t.category == category]
    
    def format_for_prompt(self) -> str:
        """Format skill for inclusion in AI prompt"""
        def _truncate(text: str, max_len: int = 900) -> str:
            if len(text) <= max_len:
                return text
            return text[:max_len].rstrip() + "..."

        lines = [
            f"## Skill: {self.name} ({self.id})",
            f"**Phase**: {self.phase or 'N/A'}",
            f"**Category**: {self.category}",
            f"**Targets**: {', '.join(self.target_types) if self.target_types else 'any'}",
            f"**Description**: {self.description or 'N/A'}",
            f"**MITRE ATT&CK**: {', '.join(self.mitre_techniques) if self.mitre_techniques else 'N/A'}",
        ]

        if self.inputs:
            lines.append(f"**Inputs**: {', '.join(self.inputs)}")
        if self.outputs:
            lines.append(f"**Outputs**: {', '.join(self.outputs)}")
        if self.prerequisites:
            lines.append(f"**Prereqs**: {', '.join(self.prerequisites)}")
        if self.safety_notes:
            lines.append(f"**Safety**: {', '.join(self.safety_notes)}")

        lines.extend([
            "",
            "### Methodology",
            _truncate(self.methodology),
            "",
            "### Available Tools"
        ])
        
        for tool in self.tools:
            lines.append(f"- **{tool.name}**: {tool.description}")
            if tool.examples:
                for example in tool.examples:
                    lines.append(f"  Example: `{example}`")
        
        if self.success_criteria:
            lines.append("")
            lines.append("### Success Criteria")
            for criteria in self.success_criteria:
                lines.append(f"- {criteria}")
        
        return "\n".join(lines)


class SkillLoader:
    """
    Loads and manages all available skills.
    Provides methods to query and retrieve relevant skills.
    """
    
    def __init__(self, skills_dir: str = None):
        self.skills_dir = skills_dir or os.path.join(os.path.dirname(__file__), "skills")
        self.skills: Dict[str, Skill] = {}
        self._load_all_skills()
    
    def _load_all_skills(self):
        """Load all skills from the skills directory"""
        skills_path = Path(self.skills_dir)
        if not skills_path.exists():
            return
        
        for skill_dir in skills_path.iterdir():
            if skill_dir.is_dir():
                # Skip folders that aren't skills (no SKILL.md)
                skill_md = skill_dir / "SKILL.md"
                if not skill_md.exists():
                    continue
                try:
                    skill = Skill.from_directory(str(skill_dir))
                    self.skills[skill.id] = skill
                except Exception as e:
                    print(f"Warning: Failed to load skill {skill_dir.name}: {e}")
    
    def get_skill(self, skill_id: str) -> Optional[Skill]:
        """Get a specific skill by ID"""
        return self.skills.get(skill_id)
    
    def get_all_skills(self) -> List[Skill]:
        """Get all available skills"""
        return list(self.skills.values())
    
    def get_skills_by_mitre(self, technique_id: str) -> List[Skill]:
        """Get skills that map to a specific MITRE technique"""
        return [s for s in self.skills.values() if technique_id in s.mitre_techniques]
    
    def get_skills_for_category(self, category: str) -> List[Skill]:
        """Get skills that have tools in a specific category"""
        return [s for s in self.skills.values() if any(t.category == category for t in s.tools)]
    
    def get_relevant_skills(self, context: Dict[str, Any] = None) -> List[Skill]:
        """
        Get skills relevant to a specific context.
        Context can include:
        - target_type: web, network, etc.
        - objective: reconnaissance, exploitation, etc.
        - technique: specific MITRE technique
        - vulnerability: specific vulnerability type
        """
        if not context:
            return list(self.skills.values())
        
        relevant = []
        
        # Match by objective
        objective = context.get('objective', '').lower()
        for skill in self.skills.values():
            if objective in skill.description.lower() or objective in skill.id.lower():
                relevant.append(skill)
                continue
        
        # Match by technique
        technique = context.get('technique', '')
        if technique:
            for skill in self.skills.values():
                if technique in skill.mitre_techniques:
                    relevant.append(skill)
        
        # If no matches, return all
        if not relevant:
            relevant = list(self.skills.values())
        
        return relevant
    
    def format_skills_for_prompt(self, skills: List[Skill] = None, max_chars: int = 5000) -> str:
        """Format skills for inclusion in AI prompt"""
        if skills is None:
            skills = list(self.skills.values())
        
        if not skills:
            return ""
        
        lines = ["# Available Pentest Skills\n"]
        char_count = len(lines[0])
        
        for skill in skills:
            skill_text = skill.format_for_prompt()
            if char_count + len(skill_text) > max_chars:
                lines.append(f"\n... and {len(skills) - skills.index(skill)} more skills")
                break
            lines.append(skill_text)
            char_count += len(skill_text)
        
        return "\n".join(lines)
    
    def get_tool_install_commands(self, skill_id: str) -> List[str]:
        """Get install commands for all tools in a skill"""
        skill = self.get_skill(skill_id)
        if not skill:
            return []
        
        commands = []
        for tool in skill.tools:
            if tool.install_cmd:
                commands.append(tool.install_cmd)
        
        return commands
    
    def get_verification_commands(self, skill_id: str) -> List[str]:
        """Get verification commands for all tools in a skill"""
        skill = self.get_skill(skill_id)
        if not skill:
            return []
        
        commands = []
        for tool in skill.tools:
            if tool.verify_cmd:
                commands.append(tool.verify_cmd)
        
        return commands


# Global skill loader instance
_global_loader: Optional[SkillLoader] = None


def get_skill_loader(skills_dir: str = None) -> SkillLoader:
    """Get or create the global skill loader instance"""
    global _global_loader
    if _global_loader is None:
        _global_loader = SkillLoader(skills_dir)
    return _global_loader


def reload_skills(skills_dir: str = None):
    """Reload all skills from disk"""
    global _global_loader
    _global_loader = SkillLoader(skills_dir)


if __name__ == "__main__":
    # Test skill loader
    loader = SkillLoader()
    print(f"Loaded {len(loader.skills)} skills:")
    for skill_id, skill in loader.skills.items():
        print(f"  - {skill_id}: {skill.name} ({len(skill.tools)} tools)")
