#!/usr/bin/env python3
"""Rebuild SKILL_CATALOG.json and SKILL_CATALOG.md from skill.yaml files."""

import argparse
import json
import os
from collections import OrderedDict
from typing import Dict, List

import yaml


def load_yaml(path: str) -> Dict:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = yaml.safe_load(f)
    return data or {}


def build_catalog(skills_dir: str) -> List[OrderedDict]:
    skills: List[OrderedDict] = []
    for name in os.listdir(skills_dir):
        path = os.path.join(skills_dir, name)
        if not os.path.isdir(path):
            continue
        skill_yaml = os.path.join(path, "skill.yaml")
        if not os.path.exists(skill_yaml):
            continue
        data = load_yaml(skill_yaml)
        skill_id = data.get("id")
        if not skill_id:
            continue
        tools_yaml = os.path.join(path, "tools.yaml")
        tools: List[str] = []
        if os.path.exists(tools_yaml):
            tools_data = load_yaml(tools_yaml)
            tools = [str(key) for key in tools_data.keys()]
        skill = OrderedDict(
            [
                ("id", skill_id),
                ("name", data.get("name", skill_id)),
                ("description", (data.get("description") or "").replace("\n", " ").strip()),
                ("category", data.get("category", "")),
                ("version", "1.0.0"),
                ("author", "TazoSploit Core"),
                ("installed", True),
                ("enabled", True),
                ("rating", 0.0),
                ("downloads", 0),
                ("tags", data.get("tags") or []),
                ("requirements", []),
                ("tools", tools),
                ("mitre_techniques", data.get("mitre_techniques") or []),
            ]
        )
        skills.append(skill)
    return sorted(skills, key=lambda s: s["id"])


def write_catalog_json(skills: List[OrderedDict], path: str) -> None:
    catalog = OrderedDict((skill["id"], skill) for skill in skills)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)


def write_catalog_md(skills: List[OrderedDict], path: str, max_tools: int = 12) -> None:
    lines: List[str] = []
    lines.append("# Skill Catalog")
    lines.append("")
    lines.append("Auto-generated catalog of available skills.")
    for skill in skills:
        lines.append("")
        lines.append(f"## {skill['name']} (`{skill['id']}`)")
        lines.append("")
        lines.append(f"- Category: `{skill['category']}`")
        if skill["description"]:
            lines.append(f"- Description: {skill['description']}")
        mitre = skill.get("mitre_techniques") or []
        if mitre:
            lines.append(f"- MITRE: {', '.join(mitre)}")
        tools = skill.get("tools") or []
        if tools:
            if len(tools) > max_tools:
                display = tools[:max_tools]
                display[-1] = f"{display[-1]}..."
            else:
                display = tools
            lines.append(f"- Tools: {', '.join(display)}")
        tags = skill.get("tags") or []
        if tags:
            lines.append(f"- Tags: {', '.join(tags)}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines).rstrip() + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skills-dir", default="skills", help="Skills directory")
    parser.add_argument("--catalog-json", default="skills/SKILL_CATALOG.json", help="Catalog JSON path")
    parser.add_argument("--catalog-md", default="skills/SKILL_CATALOG.md", help="Catalog MD path")
    parser.add_argument("--max-tools", type=int, default=12, help="Max tools to list per skill")
    args = parser.parse_args()

    skills = build_catalog(args.skills_dir)
    write_catalog_json(skills, args.catalog_json)
    write_catalog_md(skills, args.catalog_md, args.max_tools)
    print(f"Rebuilt catalog with {len(skills)} skills.")


if __name__ == "__main__":
    main()
