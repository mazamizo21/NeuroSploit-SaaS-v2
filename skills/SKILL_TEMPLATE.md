# TazoSploit Skill Template

Use this template to create custom skills for TazoSploit.

## Quick Start

```bash
# Create a new skill from template
tazos skills create "My Skill" \
  --description "Description of my skill" \
  --category custom \
  --author "Your Name"
```

## Skill Structure

```
my_skill/
├── SKILL.md           # Skill documentation (REQUIRED)
├── tools.yaml         # Tool configurations (OPTIONAL)
├── main.py           # Skill implementation (REQUIRED)
├── __init__.py       # Package initialization (AUTO-GENERATED)
├── requirements.txt  # Python dependencies (OPTIONAL)
└── examples/         # Usage examples (OPTIONAL)
    └── basic_usage.py
```

## File Templates

### SKILL.md Template

```markdown
# Skill Name

**Skill ID**: `skill_id`
**Version**: 1.0.0
**Author**: Author Name
**Category**: category_name

## Description

Detailed description of what this skill does.

## Use Cases

- Use case 1
- Use case 2
- Use case 3

## Tags

tag1, tag2, tag3

## MITRE ATT&CK Techniques

T1234, T5678

## Requirements

List of external tools or dependencies required.

## Installation

```bash
# Tool installation commands
sudo apt install tool-name
pip install python-package
```

## Usage

### Basic Usage

```python
from skills.my_skill.main import MySkillSkill

skill = MySkillSkill()
result = skill.execute(target="example.com")
print(result.findings)
```

### CLI Usage

```bash
tazos run skill my_skill --target example.com
```

## Tools

| Tool | Purpose |
|------|---------|
| tool1 | Description |
| tool2 | Description |

## Examples

See `examples/` directory for detailed examples.

## Methodology

1. Step 1: First step in the methodology
2. Step 2: Second step
3. Step 3: Third step

## Success Criteria

- [ ] Criterion 1
- [ ] Criterion 2
- [ ] Criterion 3

## Limitations

Known limitations of the skill.

## References

- Link to documentation
- Link to tools
- MITRE ATT&CK reference
```

### tools.yaml Template

```yaml
tool1:
  description: Description of tool1
  category: scanning
  install_cmd: sudo apt install tool1
  verify_cmd: tool1 --version
  examples:
    - tool1 --help
    - tool1 target.example.com

tool2:
  description: Description of tool2
  category: exploitation
  install_cmd: pip install tool2
  verify_cmd: tool2 --version
  examples:
    - tool2 -h
    - tool2 --target example.com
```

### main.py Template

```python
"""
Skill Name - Main Implementation
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import subprocess
import json


logger = logging.getLogger(__name__)


@dataclass
class SkillNameResult:
    """Result of Skill Name operation"""
    success: bool
    target: str
    findings: List[str]
    metadata: Dict[str, Any]
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class SkillNameSkill:
    """
    Skill Name - Brief description
    
    Category: category_name
    MITRE ATT&CK: T1234, T5678
    """
    
    def __init__(self):
        self.name = "Skill Name"
        self.category = "category_name"
        self.tools = ["tool1", "tool2"]
        self.mitre_techniques = ["T1234", "T5678"]
        self.description = "Detailed description of the skill"
    
    def execute(
        self,
        target: str,
        scan_type: str = "full",
        output_format: str = "json",
        **kwargs
    ) -> SkillNameResult:
        """
        Execute skill against target
        
        Args:
            target: Target to scan/exploit
            scan_type: Type of scan/operation
            output_format: Output format (json, xml, txt)
            **kwargs: Additional parameters
        
        Returns:
            SkillNameResult with findings
        """
        logger.info(f"Executing {self.name} on {target}")
        
        # Validate tools are available
        available_tools = self.validate_tools()
        missing_tools = [t for t, available in available_tools.items() if not available]
        
        if missing_tools:
            return SkillNameResult(
                success=False,
                target=target,
                findings=[],
                metadata={'error': 'missing_tools'},
                errors=[f"Missing tools: {', '.join(missing_tools)}"]
            )
        
        try:
            # Execute the skill logic
            findings = self._run_scan(target, scan_type, **kwargs)
            
            return SkillNameResult(
                success=True,
                target=target,
                findings=findings,
                metadata={
                    'scan_type': scan_type,
                    'output_format': output_format,
                    'timestamp': self._get_timestamp()
                }
            )
            
        except Exception as e:
            logger.error(f"Error executing skill: {e}")
            return SkillNameResult(
                success=False,
                target=target,
                findings=[],
                metadata={},
                errors=[str(e)]
            )
    
    def _run_scan(self, target: str, scan_type: str, **kwargs) -> List[str]:
        """
        Run the actual scan/operation
        
        Args:
            target: Target to scan
            scan_type: Type of scan
            **kwargs: Additional parameters
        
        Returns:
            List of findings
        """
        findings = []
        
        # Example: Run tool1
        try:
            cmd = ["tool1", target, f"--{scan_type}"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=kwargs.get('timeout', 300)
            )
            
            if result.returncode == 0:
                # Parse output
                findings.extend(self._parse_output(result.stdout))
            else:
                logger.warning(f"Tool1 failed: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.error("Tool1 timed out")
        except Exception as e:
            logger.error(f"Error running tool1: {e}")
        
        # Example: Run tool2
        try:
            cmd = ["tool2", target, "--output", "json"]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=kwargs.get('timeout', 300)
            )
            
            if result.returncode == 0:
                findings.extend(self._parse_output(result.stdout))
                
        except Exception as e:
            logger.error(f"Error running tool2: {e}")
        
        return findings
    
    def _parse_output(self, output: str) -> List[str]:
        """
        Parse tool output into structured findings
        
        Args:
            output: Raw output from tool
        
        Returns:
            List of finding strings
        """
        findings = []
        
        # Example parsing logic
        for line in output.split('\n'):
            if 'vulnerable' in line.lower():
                findings.append(f"Vulnerability found: {line}")
            elif 'open' in line.lower():
                findings.append(f"Open port: {line}")
        
        return findings
    
    def validate_tools(self) -> Dict[str, bool]:
        """
        Validate that required tools are installed
        
        Returns:
            Dict mapping tool names to availability status
        """
        import shutil
        return {
            tool: shutil.which(tool) is not None
            for tool in self.tools
        }
    
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
    
    def get_install_commands(self) -> List[str]:
        """
        Get installation commands for required tools
        
        Returns:
            List of installation commands
        """
        import os
        import yaml
        
        tools_file = os.path.join(os.path.dirname(__file__), "tools.yaml")
        if not os.path.exists(tools_file):
            return []
        
        with open(tools_file, 'r') as f:
            tools_data = yaml.safe_load(f)
        
        return [
            tool_info.get('install_cmd', '')
            for tool_name, tool_info in tools_data.items()
            if tool_info.get('install_cmd')
        ]
    
    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format"""
        from datetime import datetime
        return datetime.utcnow().isoformat()
    
    def export_report(self, findings: List[str], output_file: str):
        """
        Export findings to a report file
        
        Args:
            findings: List of findings to export
            output_file: Output file path
        """
        with open(output_file, 'w') as f:
            json.dump({
                'skill': self.name,
                'timestamp': self._get_timestamp(),
                'findings': findings
            }, f, indent=2)


# Export skill instance
_skill_instance: Optional[SkillNameSkill] = None


def get_skill() -> SkillNameSkill:
    """Get or create skill instance"""
    global _skill_instance
    if _skill_instance is None:
        _skill_instance = SkillNameSkill()
    return _skill_instance
```

### requirements.txt Template

```txt
# Python dependencies
pyyaml>=6.0
requests>=2.31.0

# Add more dependencies as needed
```

### examples/basic_usage.py Template

```python
"""
Basic usage example for Skill Name
"""

from skills.my_skill.main import SkillNameSkill, get_skill


def main():
    """Basic usage example"""
    
    # Get skill instance
    skill = get_skill()
    
    # Check tools availability
    print("Checking tools availability...")
    tools = skill.validate_tools()
    for tool, available in tools.items():
        print(f"  {tool}: {'✅' if available else '❌'}")
    
    # Execute skill
    print("\nExecuting skill...")
    result = skill.execute(
        target="example.com",
        scan_type="full",
        output_format="json"
    )
    
    # Print results
    print(f"\nSuccess: {result.success}")
    print(f"Target: {result.target}")
    print(f"Findings: {len(result.findings)}")
    
    if result.errors:
        print("\nErrors:")
        for error in result.errors:
            print(f"  - {error}")
    
    if result.findings:
        print("\nFindings:")
        for finding in result.findings[:10]:  # Show first 10
            print(f"  - {finding}")
    
    # Export report
    print("\nExporting report...")
    skill.export_report(result.findings, "report.json")
    print("Report saved to report.json")


if __name__ == "__main__":
    main()
```

## Best Practices

### 1. Documentation
- **Be thorough:** Document all parameters, return values, and behaviors
- **Use examples:** Include real-world usage examples
- **Keep it updated:** Update documentation when the skill changes

### 2. Error Handling
- **Validate input:** Always validate target and parameter inputs
- **Handle timeouts:** Set appropriate timeouts for tool execution
- **Log errors:** Log all errors for debugging

### 3. Tool Execution
- **Use subprocess:** Use subprocess.run() for tool execution
- **Capture output:** Capture both stdout and stderr
- **Parse carefully:** Parse tool output carefully with error handling

### 4. MITRE ATT&CK
- **Map techniques:** Map skill functionality to MITRE ATT&CK techniques
- **Document mappings:** Document which techniques the skill covers

### 5. Testing
- **Test locally:** Test the skill on local targets
- **Edge cases:** Test edge cases and error conditions
- **Examples work:** Ensure all examples work correctly

### 6. Security
- **Sanitize inputs:** Sanitize all user inputs
- **Validate targets:** Validate target addresses
- **Restrict operations:** Implement appropriate restrictions

## Categories

Choose the appropriate category for your skill:

- `reconnaissance` - Discovery and OSINT
- `scanning` - Port, service, vulnerability scanning
- `exploitation` - Exploiting vulnerabilities
- `privilege_escalation` - Escalating privileges
- `lateral_movement` - Moving through networks
- `credential_access` - Accessing credentials
- `persistence` - Maintaining access
- `defense_evasion` - Evading detection
- `exfiltration` - Data exfiltration
- `command_control` - C2 operations
- `impact` - System impact operations
- `reporting` - Report generation
- `monitoring` - Continuous monitoring
- `custom` - Custom skills

## Submitting Your Skill

1. **Test thoroughly:** Ensure your skill works correctly
2. **Document well:** Write comprehensive documentation
3. **Add examples:** Include working examples
4. **Submit:** Create a pull request or contact the maintainers

## Support

For help creating skills:
- Review existing skills in the marketplace
- Check the SKILL_CATALOG.md for examples
- Open an issue on GitHub

---

*TazoSploit Skill Template v1.0.0*
