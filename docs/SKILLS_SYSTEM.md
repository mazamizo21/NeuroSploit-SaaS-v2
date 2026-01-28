# TazoSploit Skills System

Professional pentest capabilities through a modular skills marketplace.

## Overview

The TazoSploit Skills System allows you to:
- **Browse** a catalog of professional pentest skills
- **Install** skills with a single command
- **Create** custom skills for your specific needs
- **Search** skills by category, tool, or technique
- **Manage** skill installations and configurations

Skills are self-contained modules that include:
- Documentation (SKILL.md)
- Tool configurations (tools.yaml)
- Implementation code (main.py)
- Dependencies (requirements.txt)

## Quick Start

### Install a Skill

```bash
# Install by skill ID
tazos skills install nmap_skill

# Install by name (fuzzy matching)
tazos skills install "Nmap Scanner"

# Install Metasploit
tazos skills install metasploit_skill
```

### List Available Skills

```bash
# List all skills
tazos skills list

# Filter by category
tazos skills list --category scanning

# Show only installed skills
tazos skills list --installed-only
```

### Search Skills

```bash
# Search by name
tazos skills search nmap

# Search by category
tazos skills search web

# Search by tag
tazos skills search sql
```

### Get Skill Information

```bash
# Get detailed info
tazos skills info nmap_skill

# Show in JSON format
tazos skills info nmap_skill --json
```

## CLI Commands

### `tazos skills list`

List all available skills in the marketplace.

**Options:**
- `--category CATEGORY` - Filter by category
- `--installed-only` - Show only installed skills
- `--json` - Output in JSON format

**Examples:**
```bash
tazos skills list
tazos skills list --category exploitation
tazos skills list --installed-only --json
```

### `tazos skills install <skill_name>`

Install a skill from the marketplace.

**Arguments:**
- `skill_name` - Skill name or ID (supports fuzzy matching)

**Examples:**
```bash
tazos skills install nmap_skill
tazos skills install "Nmap Scanner"
tazos skills install metasploit_skill
```

### `tazos skills remove <skill_name>`

Remove an installed skill.

**Arguments:**
- `skill_name` - Skill name or ID

**Examples:**
```bash
tazos skills remove nmap_skill
tazos skills remove "Nmap Scanner"
```

### `tazos skills info <skill_name>`

Get detailed information about a skill.

**Arguments:**
- `skill_name` - Skill name or ID

**Options:**
- `--json` - Output in JSON format

**Examples:**
```bash
tazos skills info nmap_skill
tazos skills info "Nmap Scanner" --json
```

### `tazos skills search <query>`

Search skills by name, description, or tags.

**Arguments:**
- `query` - Search query

**Examples:**
```bash
tazos skills search web
tazos skills search sql
tazos skills search privilege
```

### `tazos skills create <name>`

Create a custom skill from template.

**Arguments:**
- `name` - Skill name

**Options:**
- `--description TEXT` (required) - Skill description
- `--category CATEGORY` (required) - Skill category
- `--author AUTHOR` - Skill author

**Categories:**
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

**Examples:**
```bash
tazos skills create "Custom Exploit" \
  --description "My custom exploit framework" \
  --category exploitation \
  --author "John Doe"
```

### `tazos skills categories`

List all available skill categories.

**Examples:**
```bash
tazos skills categories
```

### `tazos skills stats`

Show marketplace statistics.

**Options:**
- `--json` - Output in JSON format

**Examples:**
```bash
tazos skills stats
tazos skills stats --json
```

## Skill Categories

### 🔍 Reconnaissance

Skills for discovery, OSINT, and information gathering.

**Available Skills:**
- `subdomain_skill` - Subdomain enumeration
- `recon_skill` - General reconnaissance

### 📡 Scanning

Skills for port scanning, service detection, and vulnerability scanning.

**Available Skills:**
- `nmap_skill` - Network scanning
- `nuclei_skill` - Template-based vulnerability scanning
- `web_scan_skill` - Web application scanning
- `burp_skill` - Burp Suite integration

### 💥 Exploitation

Skills for exploiting vulnerabilities.

**Available Skills:**
- `metasploit_skill` - Metasploit framework
- `xss_skill` - XSS detection and exploitation
- `sql_injection_skill` - SQL injection testing

### 🚀 Privilege Escalation

Skills for privilege escalation on Linux and Windows.

**Available Skills:**
- `privesc_skill` - Automated privilege escalation checks

### 🔐 Credential Access

Skills for credential extraction and dumping.

**Available Skills:**
- `credential_access_skill` - Credential harvesting

### 🌐 Lateral Movement

Skills for moving through networks.

**Available Skills:**
- `lateral_skill` - Network lateral movement

### 📊 Reporting

Skills for generating professional reports.

**Available Skills:**
- `report_skill` - Report generation

### 👁️ Monitoring

Skills for continuous monitoring and alerting.

**Available Skills:**
- `monitor_skill` - Continuous monitoring

## Creating Custom Skills

### Step 1: Create Skill Template

```bash
tazos skills create "My Skill" \
  --description "Description of my skill" \
  --category custom \
  --author "Your Name"
```

This creates a new skill directory with:
```
my_skill/
├── SKILL.md          # Documentation
├── tools.yaml        # Tool configurations
├── main.py          # Implementation
├── __init__.py      # Package init
└── requirements.txt # Dependencies
```

### Step 2: Edit Skill Files

#### SKILL.md

```markdown
# My Skill

**Skill ID**: `my_skill`
**Version**: 1.0.0
**Author**: Your Name
**Category**: custom

## Description

Detailed description of your skill.

## Usage

### Basic Usage

```python
from skills.my_skill.main import MySkillSkill

skill = MySkillSkill()
result = skill.execute(target="example.com")
print(result.findings)
```
```

#### tools.yaml

```yaml
tool_name:
  description: Description of the tool
  category: custom
  install_cmd: sudo apt install tool_name
  verify_cmd: tool_name --version
  examples:
    - tool_name --help
    - tool_name target.com
```

#### main.py

```python
"""
My Skill - Main Implementation
"""

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MySkillResult:
    """Result of skill operation"""
    success: bool
    target: str
    findings: List[str]
    metadata: Dict[str, Any]
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class MySkillSkill:
    """
    My Skill - Description
    
    Category: custom
    MITRE ATT&CK: T1234
    """
    
    def __init__(self):
        self.name = "My Skill"
        self.category = "custom"
        self.tools = ["tool_name"]
        self.mitre_techniques = ["T1234"]
    
    def execute(self, target: str, **kwargs) -> MySkillResult:
        """
        Execute skill against target
        
        Args:
            target: Target to scan/exploit
            **kwargs: Additional parameters
        
        Returns:
            MySkillResult with findings
        """
        logger.info(f"Executing {self.name} on {target}")
        
        # Your skill logic here
        
        return MySkillResult(
            success=True,
            target=target,
            findings=["Finding 1", "Finding 2"],
            metadata={'timestamp': 'now'}
        )
    
    def validate_tools(self) -> Dict[str, bool]:
        """Validate that required tools are installed"""
        import shutil
        return {
            tool: shutil.which(tool) is not None
            for tool in self.tools
        }


def get_skill() -> MySkillSkill:
    """Get skill instance"""
    return MySkillSkill()
```

### Step 3: Test Your Skill

```bash
# Test the skill
cd skills/my_skill
python3 main.py

# Or use from parent directory
python3 -c "from skills.my_skill.main import get_skill; skill = get_skill(); print(skill.execute('example.com'))"
```

### Step 4: Use Your Skill

```python
from skills.my_skill.main import get_skill

skill = get_skill()
result = skill.execute("example.com")

if result.success:
    print(f"Found {len(result.findings)} findings:")
    for finding in result.findings:
        print(f"  - {finding}")
```

## Skill Development Best Practices

### 1. Documentation

- Write comprehensive documentation in SKILL.md
- Include usage examples
- Document all parameters and return values
- Keep documentation updated with code changes

### 2. Error Handling

- Validate all input parameters
- Handle timeouts gracefully
- Log errors for debugging
- Provide helpful error messages

### 3. Tool Execution

- Use `subprocess.run()` for tool execution
- Capture both stdout and stderr
- Set appropriate timeouts
- Parse output carefully

### 4. MITRE ATT&CK Mapping

- Map skill functionality to MITRE ATT&CK techniques
- Document which techniques your skill covers
- Helps with reporting and methodology

### 5. Testing

- Test on local targets first
- Test edge cases and error conditions
- Ensure examples work correctly
- Document known limitations

### 6. Security

- Sanitize all user inputs
- Validate target addresses
- Implement appropriate restrictions
- Don't expose sensitive data

## Integration with Scheduler

Skills can be scheduled for automatic execution:

```bash
# Schedule a skill to run daily
tazos schedule "run nmap scan on target.com" "daily at 3am"

# Schedule periodic subdomain discovery
tazos schedule "discover subdomains" "every 6 hours"
```

## Integration with AI

Skills can be called by AI agents for autonomous pentesting:

```python
from skills.nmap_skill.main import get_skill

# AI agent calls skill
skill = get_skill()
result = skill.execute(
    target="target.com",
    scan_type="full",
    output_format="json"
)

# AI analyzes results
for finding in result.findings:
    if "vulnerable" in finding:
        print(f"AI detected vulnerability: {finding}")
```

## Troubleshooting

### Skill Not Found

```bash
# Search for the skill
tazos skills search <query>

# List all skills
tazos skills list
```

### Tools Not Available

```bash
# Check skill requirements
tazos skills info <skill_name>

# Install required tools manually
sudo apt install <tool_name>
pip install <package>
```

### Skill Installation Fails

```bash
# Check if already installed
tazos skills list --installed-only

# Remove and reinstall
tazos skills remove <skill_name>
tazos skills install <skill_name>
```

## Contributing Skills

Want to contribute a skill to the marketplace?

1. Create your skill using the template
2. Test thoroughly on various targets
3. Write comprehensive documentation
4. Include working examples
5. Submit a pull request or contact maintainers

## References

- [Skill Catalog](skills/SKILL_CATALOG.md) - All available skills
- [Skill Template](skills/SKILL_TEMPLATE.md) - Development template
- [MITRE ATT&CK](https://attack.mitre.org/) - Framework for techniques

## Support

For help with skills:
- Check the skill's SKILL.md
- Review examples in the skill directory
- Open an issue on GitHub
- Check the documentation

---

*TazoSploit Skills System v1.0.0*
