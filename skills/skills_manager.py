"""
TazoSploit Skills Manager
Professional skills marketplace and management system
"""

import os
import json
import shutil
import logging
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
import yaml


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SkillMetadata:
    """Metadata for a skill in the marketplace"""
    id: str
    name: str
    description: str
    category: str
    version: str
    author: str
    installed: bool = False
    enabled: bool = True
    rating: float = 0.0
    downloads: int = 0
    tags: List[str] = None
    requirements: List[str] = None
    tools: List[str] = None
    mitre_techniques: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.requirements is None:
            self.requirements = []
        if self.tools is None:
            self.tools = []
        if self.mitre_techniques is None:
            self.mitre_techniques = []
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'SkillMetadata':
        return cls(**data)


@dataclass
class SkillInstallationResult:
    """Result of a skill installation operation"""
    success: bool
    skill_id: str
    message: str
    warnings: List[str] = None
    installed_tools: List[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
        if self.installed_tools is None:
            self.installed_tools = []


class SkillsManager:
    """
    Professional skills marketplace manager for TazoSploit
    
    Features:
        - List available skills
        - Install/uninstall skills
        - Create custom skills
        - Search skills by category/tag
        - Get skill information
        - Manage skill dependencies
    """
    
    CATEGORIES = [
        "reconnaissance",
        "scanning",
        "exploitation",
        "post_exploitation",
        "privilege_escalation",
        "lateral_movement",
        "credential_access",
        "persistence",
        "defense_evasion",
        "exfiltration",
        "command_control",
        "impact",
        "reporting",
        "monitoring",
        "custom"
    ]
    
    def __init__(self, skills_dir: str = "skills", marketplace_file: str = "skills/SKILL_CATALOG.json"):
        """
        Initialize skills manager
        
        Args:
            skills_dir: Directory containing installed skills
            marketplace_file: Path to marketplace catalog file
        """
        self.skills_dir = Path(skills_dir)
        self.marketplace_file = Path(marketplace_file)
        self.installed_file = self.skills_dir / ".installed_skills.json"
        
        # Ensure directories exist
        self.skills_dir.mkdir(parents=True, exist_ok=True)
        
        # Load marketplace catalog
        self.marketplace: Dict[str, SkillMetadata] = {}
        self._load_marketplace()
        
        # Load installed skills
        self.installed_skills: Dict[str, SkillMetadata] = {}
        self._load_installed_skills()
    
    def _load_marketplace(self):
        """Load skills marketplace catalog"""
        if self.marketplace_file.exists():
            try:
                with open(self.marketplace_file, 'r') as f:
                    catalog_data = json.load(f)
                    for skill_id, skill_data in catalog_data.items():
                        self.marketplace[skill_id] = SkillMetadata.from_dict(skill_data)
                logger.info(f"Loaded {len(self.marketplace)} skills from marketplace")
            except Exception as e:
                logger.error(f"Failed to load marketplace catalog: {e}")
                self._generate_default_marketplace()
        else:
            self._generate_default_marketplace()
    
    def _generate_default_marketplace(self):
        """Generate default marketplace with core skills"""
        default_skills = {
            "nmap_skill": SkillMetadata(
                id="nmap_skill",
                name="Nmap Scanner",
                description="Advanced network scanning and service detection",
                category="scanning",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["network", "port-scanning", "discovery"],
                requirements=["nmap"],
                tools=["nmap"],
                mitre_techniques=["T1046"],
                rating=5.0,
                downloads=1000
            ),
            "nuclei_skill": SkillMetadata(
                id="nuclei_skill",
                name="Nuclei Vulnerability Scanner",
                description="Fast vulnerability scanner with customizable templates",
                category="scanning",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["vulnerability", "web", "templates"],
                requirements=["nuclei"],
                tools=["nuclei"],
                mitre_techniques=["T1190", "T1195"],
                rating=4.8,
                downloads=850
            ),
            "metasploit_skill": SkillMetadata(
                id="metasploit_skill",
                name="Metasploit Framework",
                description="Advanced exploitation framework with hundreds of exploits",
                category="exploitation",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["exploitation", "framework", "post-exploitation"],
                requirements=["metasploit-framework"],
                tools=["msfconsole", "msfvenom"],
                mitre_techniques=["T1210", "T1068"],
                rating=4.9,
                downloads=1200
            ),
            "subdomain_skill": SkillMetadata(
                id="subdomain_skill",
                name="Subdomain Discovery",
                description="Comprehensive subdomain enumeration",
                category="reconnaissance",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["subdomain", "dns", "enumeration"],
                requirements=["subfinder", "amass"],
                tools=["subfinder", "amass", "dnsx"],
                mitre_techniques=["T1018"],
                rating=4.7,
                downloads=700
            ),
            "web_scan_skill": SkillMetadata(
                id="web_scan_skill",
                name="Web Application Scanner",
                description="Web vulnerability scanning and assessment",
                category="scanning",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["web", "vulnerability", "owasp"],
                requirements=["nikto", "wpscan"],
                tools=["nikto", "wpscan", "dirsearch"],
                mitre_techniques=["T1190"],
                rating=4.6,
                downloads=650
            ),
            "burp_skill": SkillMetadata(
                id="burp_skill",
                name="Burp Suite Integration",
                description="Burp Suite automation and API integration",
                category="scanning",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["web", "testing", "proxy"],
                requirements=["burpsuite"],
                tools=["burpsuite"],
                mitre_techniques=["T1190"],
                rating=4.5,
                downloads=500
            ),
            "recon_skill": SkillMetadata(
                id="recon_skill",
                name="General Reconnaissance",
                description="Comprehensive reconnaissance automation",
                category="reconnaissance",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["recon", "osint", "discovery"],
                requirements=["theHarvester", "whois"],
                tools=["theHarvester", "whois", "dnsrecon"],
                mitre_techniques=["T1018", "T1016"],
                rating=4.8,
                downloads=900
            ),
            "privesc_skill": SkillMetadata(
                id="privesc_skill",
                name="Privilege Escalation",
                description="Automated privilege escalation checks",
                category="privilege_escalation",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["privilege-escalation", "linux", "windows"],
                requirements=["linpeas", "winpeas"],
                tools=["linpeas", "winpeas", "linuxprivchecker"],
                mitre_techniques=["T1068", "T1548"],
                rating=4.9,
                downloads=1100
            ),
            "lateral_skill": SkillMetadata(
                id="lateral_skill",
                name="Lateral Movement",
                description="Network lateral movement techniques",
                category="lateral_movement",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["lateral-movement", "network", "psexec"],
                requirements=["crackmapexec", "psexec"],
                tools=["crackmapexec", "psexec", "smbclient"],
                mitre_techniques=["T1021", "T1077"],
                rating=4.6,
                downloads=550
            ),
            "report_skill": SkillMetadata(
                id="report_skill",
                name="Report Generator",
                description="Professional pentest report generation",
                category="reporting",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["reporting", "documentation", "pdf"],
                requirements=["pandoc", "wkhtmltopdf"],
                tools=["pandoc", "wkhtmltopdf"],
                mitre_techniques=[],
                rating=4.7,
                downloads=800
            ),
            "monitor_skill": SkillMetadata(
                id="monitor_skill",
                name="Continuous Monitor",
                description="Continuous security monitoring and alerting",
                category="monitoring",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["monitoring", "alerting", "continuous"],
                requirements=["prometheus", "grafana"],
                tools=["prometheus", "grafana"],
                mitre_techniques=[],
                rating=4.5,
                downloads=400
            ),
            "xss_skill": SkillMetadata(
                id="xss_skill",
                name="XSS Hunter",
                description="Cross-site scripting detection and exploitation",
                category="exploitation",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["xss", "web", "injection"],
                requirements=["xsser"],
                tools=["xsser", "dalfox"],
                mitre_techniques=["T1059"],
                rating=4.4,
                downloads=450
            ),
            "sql_injection_skill": SkillMetadata(
                id="sql_injection_skill",
                name="SQL Injection Tester",
                description="SQL injection vulnerability detection and exploitation",
                category="exploitation",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["sql", "injection", "web"],
                requirements=["sqlmap"],
                tools=["sqlmap", "bbqsql"],
                mitre_techniques=["T1190"],
                rating=4.8,
                downloads=950
            ),
            "credential_access_skill": SkillMetadata(
                id="credential_access_skill",
                name="Credential Harvester",
                description="Credential extraction and dumping",
                category="credential_access",
                version="1.0.0",
                author="TazoSploit Core",
                tags=["credentials", "dumping", "hashes"],
                requirements=["mimikatz", "hashcat"],
                tools=["mimikatz", "hashcat", "john"],
                mitre_techniques=["T1003", "T1555"],
                rating=4.7,
                downloads=750
            )
        }
        
        self.marketplace = default_skills
        self._save_marketplace()
        logger.info(f"Generated default marketplace with {len(default_skills)} skills")
    
    def _save_marketplace(self):
        """Save marketplace catalog to file"""
        try:
            marketplace_data = {skill_id: skill.to_dict() for skill_id, skill in self.marketplace.items()}
            with open(self.marketplace_file, 'w') as f:
                json.dump(marketplace_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save marketplace catalog: {e}")
    
    def _load_installed_skills(self):
        """Load installed skills from file"""
        if self.installed_file.exists():
            try:
                with open(self.installed_file, 'r') as f:
                    installed_data = json.load(f)
                    for skill_id, skill_data in installed_data.items():
                        self.installed_skills[skill_id] = SkillMetadata.from_dict(skill_data)
                logger.info(f"Loaded {len(self.installed_skills)} installed skills")
            except Exception as e:
                logger.error(f"Failed to load installed skills: {e}")
    
    def _save_installed_skills(self):
        """Save installed skills to file"""
        try:
            installed_data = {skill_id: skill.to_dict() for skill_id, skill in self.installed_skills.items()}
            with open(self.installed_file, 'w') as f:
                json.dump(installed_data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save installed skills: {e}")
    
    def list_skills(self, category: Optional[str] = None, installed_only: bool = False) -> List[SkillMetadata]:
        """
        List available skills
        
        Args:
            category: Filter by category
            installed_only: Only show installed skills
        
        Returns:
            List of skill metadata
        """
        skills = list(self.marketplace.values())
        
        if installed_only:
            skills = [s for s in skills if s.installed]
        
        if category:
            skills = [s for s in skills if s.category == category]
        
        return sorted(skills, key=lambda x: x.name)
    
    def get_skill_info(self, skill_id: str) -> Optional[SkillMetadata]:
        """
        Get detailed information about a skill
        
        Args:
            skill_id: Skill identifier
        
        Returns:
            Skill metadata or None if not found
        """
        # Check marketplace
        if skill_id in self.marketplace:
            return self.marketplace[skill_id]
        
        # Check installed
        if skill_id in self.installed_skills:
            return self.installed_skills[skill_id]
        
        return None
    
    def search_skills(self, query: str) -> List[SkillMetadata]:
        """
        Search skills by name, description, or tags
        
        Args:
            query: Search query
        
        Returns:
            List of matching skills
        """
        query_lower = query.lower()
        results = []
        
        for skill in self.marketplace.values():
            # Search in name
            if query_lower in skill.name.lower():
                results.append(skill)
                continue
            
            # Search in description
            if query_lower in skill.description.lower():
                results.append(skill)
                continue
            
            # Search in tags
            if any(query_lower in tag.lower() for tag in skill.tags):
                results.append(skill)
            
            # Search in category
            if query_lower in skill.category.lower():
                results.append(skill)
        
        return results
    
    def install_skill(self, skill_id: str) -> SkillInstallationResult:
        """
        Install a skill from the marketplace
        
        Args:
            skill_id: Skill identifier
        
        Returns:
            Installation result
        """
        # Check if skill exists in marketplace
        if skill_id not in self.marketplace:
            return SkillInstallationResult(
                success=False,
                skill_id=skill_id,
                message=f"Skill '{skill_id}' not found in marketplace"
            )
        
        skill_metadata = self.marketplace[skill_id]
        
        # Check if already installed
        if skill_id in self.installed_skills:
            return SkillInstallationResult(
                success=False,
                skill_id=skill_id,
                message=f"Skill '{skill_id}' is already installed"
            )
        
        # Create skill directory
        skill_dir = self.skills_dir / skill_id
        try:
            skill_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            return SkillInstallationResult(
                success=False,
                skill_id=skill_id,
                message=f"Failed to create skill directory: {e}"
            )
        
        warnings = []
        installed_tools = []
        
        # Check requirements
        for requirement in skill_metadata.requirements:
            if not self._check_requirement(requirement):
                warnings.append(f"Requirement '{requirement}' may not be installed")
            else:
                installed_tools.append(requirement)
        
        # Create SKILL.md
        skill_md = self._generate_skill_md(skill_metadata)
        try:
            with open(skill_dir / "SKILL.md", 'w') as f:
                f.write(skill_md)
        except Exception as e:
            return SkillInstallationResult(
                success=False,
                skill_id=skill_id,
                message=f"Failed to create SKILL.md: {e}"
            )
        
        # Create tools.yaml
        tools_yaml = self._generate_tools_yaml(skill_metadata)
        try:
            with open(skill_dir / "tools.yaml", 'w') as f:
                yaml.dump(tools_yaml, f, default_flow_style=False)
        except Exception as e:
            warnings.append(f"Failed to create tools.yaml: {e}")
        
        # Create __init__.py
        init_py = self._generate_init_py(skill_metadata)
        try:
            with open(skill_dir / "__init__.py", 'w') as f:
                f.write(init_py)
        except Exception as e:
            warnings.append(f"Failed to create __init__.py: {e}")
        
        # Create main.py with basic implementation
        main_py = self._generate_main_py(skill_metadata)
        try:
            with open(skill_dir / "main.py", 'w') as f:
                f.write(main_py)
        except Exception as e:
            warnings.append(f"Failed to create main.py: {e}")
        
        # Create requirements.txt
        requirements_txt = "\n".join(skill_metadata.requirements) + "\n"
        try:
            with open(skill_dir / "requirements.txt", 'w') as f:
                f.write(requirements_txt)
        except Exception as e:
            warnings.append(f"Failed to create requirements.txt: {e}")
        
        # Update installed skills
        skill_metadata.installed = True
        self.installed_skills[skill_id] = skill_metadata
        self._save_installed_skills()
        
        # Update marketplace downloads
        self.marketplace[skill_id].downloads += 1
        self._save_marketplace()
        
        return SkillInstallationResult(
            success=True,
            skill_id=skill_id,
            message=f"Successfully installed '{skill_metadata.name}'",
            warnings=warnings,
            installed_tools=installed_tools
        )
    
    def _check_requirement(self, requirement: str) -> bool:
        """Check if a requirement is available"""
        import shutil
        return shutil.which(requirement) is not None
    
    def _generate_skill_md(self, skill: SkillMetadata) -> str:
        """Generate SKILL.md content"""
        mitre_list = ", ".join(skill.mitre_techniques) if skill.mitre_techniques else "None"
        tags_list = ", ".join(skill.tags) if skill.tags else "None"
        
        return f"""# {skill.name}

**Skill ID**: `{skill.id}`
**Version**: {skill.version}
**Author**: {skill.author}
**Category**: {skill.category}

## Description

{skill.description}

## Tags

{tags_list}

## MITRE ATT&CK Techniques

{mitre_list}

## Requirements

"""
    
    def _generate_tools_yaml(self, skill: SkillMetadata) -> Dict:
        """Generate tools.yaml content"""
        tools_dict = {}
        for tool in skill.tools:
            tools_dict[tool] = {
                'description': f'{tool} tool for {skill.name}',
                'category': skill.category,
                'install_cmd': f'sudo apt install {tool}  # Adjust based on your system',
                'examples': [
                    f'{tool} --help',
                    f'# {tool} target.example.com'
                ]
            }
        return tools_dict
    
    def _generate_init_py(self, skill: SkillMetadata) -> str:
        """Generate __init__.py content"""
        return f'''"""
{skill.name} - {skill.description}
TazoSploit Skill
"""

from .main import {skill.id.replace('_skill', '').capitalize()}Skill

__all__ = ['{skill.id.replace('_skill', '').capitalize()}Skill']
__version__ = "{skill.version}"
'''
    
    def _generate_main_py(self, skill: SkillMetadata) -> str:
        """Generate main.py content"""
        class_name = skill.id.replace('_skill', '').capitalize()
        return f'''"""
{skill.name} - Main Implementation
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class {class_name}Result:
    """Result of {skill.name.lower()} operation"""
    success: bool
    target: str
    findings: List[str]
    metadata: Dict[str, Any]
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class {class_name}Skill:
    """
    {skill.name} - {skill.description}
    
    Category: {skill.category}
    MITRE ATT&CK: {', '.join(skill.mitre_techniques)}
    """
    
    def __init__(self):
        self.name = "{skill.name}"
        self.category = "{skill.category}"
        self.tools = {skill.tools}
        self.mitre_techniques = {skill.mitre_techniques}
    
    def execute(self, target: str, **kwargs) -> {class_name}Result:
        """
        Execute {skill.name.lower()} against target
        
        Args:
            target: Target to scan/exploit
            **kwargs: Additional parameters
        
        Returns:
            {class_name}Result with findings
        """
        logger.info(f"Executing {self.name} on {{target}}")
        
        # Placeholder implementation
        # In a real skill, this would:
        # 1. Validate input
        # 2. Run appropriate tools
        # 3. Parse results
        # 4. Return structured findings
        
        return {class_name}Result(
            success=True,
            target=target,
            findings=[f"Placeholder finding from {self.name}"],
            metadata={{'method': 'placeholder', 'timestamp': 'now'}}
        )
    
    def validate_tools(self) -> Dict[str, bool]:
        """
        Validate that required tools are installed
        
        Returns:
            Dict mapping tool names to availability status
        """
        import shutil
        return {{
            tool: shutil.which(tool) is not None
            for tool in self.tools
        }}
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict[str, str]]:
        """
        Get information about a specific tool
        
        Args:
            tool_name: Name of the tool
        
        Returns:
            Tool information or None if not found
        """
        import os
        import yaml
        
        tools_file = os.path.join(os.path.dirname(__file__), "tools.yaml")
        if not os.path.exists(tools_file):
            return None
        
        with open(tools_file, 'r') as f:
            tools_data = yaml.safe_load(f)
        
        return tools_data.get(tool_name)


# Export skill instance
_skill_instance: Optional[{class_name}Skill] = None


def get_skill() -> {class_name}Skill:
    """Get or create skill instance"""
    global _skill_instance
    if _skill_instance is None:
        _skill_instance = {class_name}Skill()
    return _skill_instance
'''
    
    def remove_skill(self, skill_id: str) -> bool:
        """
        Remove an installed skill
        
        Args:
            skill_id: Skill identifier
        
        Returns:
            True if removed, False if not found
        """
        if skill_id not in self.installed_skills:
            logger.warning(f"Skill '{skill_id}' is not installed")
            return False
        
        # Remove skill directory
        skill_dir = self.skills_dir / skill_id
        try:
            if skill_dir.exists():
                shutil.rmtree(skill_dir)
        except Exception as e:
            logger.error(f"Failed to remove skill directory: {e}")
            return False
        
        # Remove from installed skills
        del self.installed_skills[skill_id]
        self._save_installed_skills()
        
        logger.info(f"Removed skill '{skill_id}'")
        return True
    
    def create_skill(
        self,
        name: str,
        description: str,
        category: str,
        author: str = "Custom",
        **kwargs
    ) -> SkillMetadata:
        """
        Create a custom skill
        
        Args:
            name: Skill name
            description: Skill description
            category: Skill category
            author: Skill author
            **kwargs: Additional metadata
        
        Returns:
            Created skill metadata
        """
        skill_id = name.lower().replace(' ', '_') + "_skill"
        
        skill_metadata = SkillMetadata(
            id=skill_id,
            name=name,
            description=description,
            category=category,
            version="1.0.0",
            author=author,
            tags=kwargs.get('tags', []),
            requirements=kwargs.get('requirements', []),
            tools=kwargs.get('tools', []),
            mitre_techniques=kwargs.get('mitre_techniques', [])
        )
        
        # Add to marketplace
        self.marketplace[skill_id] = skill_metadata
        self._save_marketplace()
        
        # Install the skill
        result = self.install_skill(skill_id)
        
        if not result.success:
            logger.error(f"Failed to create skill: {result.message}")
            return skill_metadata
        
        return skill_metadata
    
    def get_categories(self) -> List[str]:
        """Get all available categories"""
        categories = set(skill.category for skill in self.marketplace.values())
        return sorted(list(categories))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get marketplace statistics"""
        return {
            'total_skills': len(self.marketplace),
            'installed_skills': len(self.installed_skills),
            'categories': len(self.get_categories()),
            'downloads': sum(skill.downloads for skill in self.marketplace.values()),
            'average_rating': sum(skill.rating for skill in self.marketplace.values()) / len(self.marketplace) if self.marketplace else 0
        }


# Global skills manager instance
_manager_instance: Optional[SkillsManager] = None


def get_skills_manager(skills_dir: str = None, marketplace_file: str = None) -> SkillsManager:
    """Get or create the global skills manager instance"""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = SkillsManager(
            skills_dir=skills_dir,
            marketplace_file=marketplace_file
        )
    return _manager_instance
