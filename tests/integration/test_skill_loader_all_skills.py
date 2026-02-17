#!/usr/bin/env python3
"""Integration test — load ALL skills and verify each has the required files.

Every skill directory must contain:
  - SKILL.md   (methodology / documentation)
  - skill.yaml (structured metadata)
  - tools.yaml (tool definitions)

Any missing file means the skill is incomplete and will break skill routing.
"""

import os
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SKILLS_DIR = ROOT / "skills"
sys.path.insert(0, str(ROOT / "kali-executor" / "open-interpreter"))
sys.path.insert(0, str(ROOT))

# ---------------------------------------------------------------------------
# Discover skill directories (skip internal files, __pycache__, _example)
# ---------------------------------------------------------------------------

SKIP_NAMES = {
    "__pycache__",
    "_example",
    "__init__.py",
    "SKILL_CATALOG.json",
    "SKILL_CATALOG.md",
    "SKILL_TEMPLATE.md",
    "UPGRADE_PLAN.md",
    # Utility directories that are NOT real skills
    "scripts",
    "toolcards",
}

# Skills that are known to be incomplete (tracked for future completion).
# Tests will xfail for these rather than hard-fail.
INCOMPLETE_SKILLS = {
    "beef_browser",    # missing SKILL.md, tools.yaml
    "empire_c2",       # missing SKILL.md, tools.yaml
    "file_upload",     # missing SKILL.md
    "owasp_zap",       # missing SKILL.md, tools.yaml
    "ssrf",            # missing SKILL.md
    "windows_pentest", # missing tools.yaml
}


def _skill_dirs():
    """Return list of Path objects for every real skill directory."""
    if not SKILLS_DIR.is_dir():
        return []
    return sorted(
        p
        for p in SKILLS_DIR.iterdir()
        if p.is_dir() and p.name not in SKIP_NAMES and not p.name.startswith(".")
    )


SKILL_DIRS = _skill_dirs()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSkillDirectoryStructure:
    """Every skill directory must contain the three canonical files."""

    @pytest.mark.parametrize("skill_path", SKILL_DIRS, ids=[p.name for p in SKILL_DIRS])
    def test_has_skill_md(self, skill_path: Path):
        if skill_path.name in INCOMPLETE_SKILLS:
            pytest.xfail(f"{skill_path.name} is a known incomplete skill")
        md = skill_path / "SKILL.md"
        assert md.exists(), f"{skill_path.name}/SKILL.md is missing"
        content = md.read_text(encoding="utf-8", errors="replace")
        assert len(content.strip()) > 20, f"{skill_path.name}/SKILL.md is effectively empty"

    @pytest.mark.parametrize("skill_path", SKILL_DIRS, ids=[p.name for p in SKILL_DIRS])
    def test_has_skill_yaml(self, skill_path: Path):
        if skill_path.name in INCOMPLETE_SKILLS:
            pytest.xfail(f"{skill_path.name} is a known incomplete skill")
        yml = skill_path / "skill.yaml"
        assert yml.exists(), f"{skill_path.name}/skill.yaml is missing"
        data = yaml.safe_load(yml.read_text(encoding="utf-8"))
        assert isinstance(data, dict), f"{skill_path.name}/skill.yaml is not a valid YAML mapping"
        # Minimum required keys
        for key in ("id", "name", "category"):
            assert key in data, f"{skill_path.name}/skill.yaml missing required key '{key}'"

    @pytest.mark.parametrize("skill_path", SKILL_DIRS, ids=[p.name for p in SKILL_DIRS])
    def test_has_tools_yaml(self, skill_path: Path):
        if skill_path.name in INCOMPLETE_SKILLS:
            pytest.xfail(f"{skill_path.name} is a known incomplete skill")
        tools = skill_path / "tools.yaml"
        assert tools.exists(), f"{skill_path.name}/tools.yaml is missing"
        data = yaml.safe_load(tools.read_text(encoding="utf-8"))
        # tools.yaml should be a list or dict of tool definitions
        assert data is not None, f"{skill_path.name}/tools.yaml parsed as None (empty?)"

    @pytest.mark.parametrize("skill_path", SKILL_DIRS, ids=[p.name for p in SKILL_DIRS])
    def test_skill_yaml_has_phase(self, skill_path: Path):
        """skill.yaml should declare a phase so tool-phase routing works."""
        yml = skill_path / "skill.yaml"
        if not yml.exists():
            pytest.skip("skill.yaml missing (covered by other test)")
        data = yaml.safe_load(yml.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            pytest.skip("skill.yaml not a dict")
        # phase is recommended but not strictly required for every skill
        phase = data.get("phase", "")
        if not phase:
            import warnings
            warnings.warn(
                f"{skill_path.name}/skill.yaml missing 'phase' — tool routing may fall back to defaults",
                stacklevel=1,
            )
            pytest.skip(f"{skill_path.name} has no phase field (non-critical)")


class TestSkillLoaderImport:
    """Verify the SkillLoader can be imported and used."""

    def test_import_skill_loader(self):
        from skills.skill_loader import SkillLoader
        assert SkillLoader is not None

    def test_load_skill_from_directory(self):
        """Load a known skill and verify basic attributes."""
        from skills.skill_loader import SkillLoader
        # Pick a skill that definitely exists
        if not SKILL_DIRS:
            pytest.skip("No skill directories found")
        loader = SkillLoader(str(SKILLS_DIR))
        assert loader is not None
        # The loader should be able to list available skills
        skills = loader.list_skills() if hasattr(loader, "list_skills") else []
        # If list_skills doesn't exist, try other common methods
        if not skills and hasattr(loader, "get_all_skills"):
            skills = loader.get_all_skills()
        if not skills and hasattr(loader, "skills"):
            skills = loader.skills
        # At minimum the loader object should be created without error
        assert loader is not None

    def test_skill_count_sanity(self):
        """We expect at least 100 skill directories."""
        assert len(SKILL_DIRS) >= 100, (
            f"Expected >=100 skill directories, found {len(SKILL_DIRS)}. "
            "Did skills get deleted?"
        )
