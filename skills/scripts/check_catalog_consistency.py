#!/usr/bin/env python3
"""Check that SKILL_CATALOG.json matches tools.yaml for each skill."""

import argparse
import json
import os
from typing import Dict, List, Tuple

import yaml


def load_yaml(path: str) -> Dict:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = yaml.safe_load(f)
    return data or {}


def collect_skills(skills_dir: str) -> Dict[str, Dict[str, List[str]]]:
    skills: Dict[str, Dict[str, List[str]]] = {}
    for entry in os.listdir(skills_dir):
        path = os.path.join(skills_dir, entry)
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
        skills[skill_id] = {
            "path": path,
            "tools": tools,
        }
    return skills


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skills-dir", default="skills", help="Skills directory")
    parser.add_argument("--catalog", default="skills/SKILL_CATALOG.json", help="Catalog JSON path")
    args = parser.parse_args()

    skills = collect_skills(args.skills_dir)

    with open(args.catalog, "r", encoding="utf-8") as f:
        catalog = json.load(f)

    missing_in_catalog = sorted([sid for sid in skills.keys() if sid not in catalog])
    missing_in_skills = sorted([sid for sid in catalog.keys() if sid not in skills])

    mismatches: List[Tuple[str, List[str], List[str]]] = []
    for sid, meta in skills.items():
        if sid not in catalog:
            continue
        tools_yaml = meta["tools"]
        tools_catalog = catalog[sid].get("tools") or []
        if tools_yaml != tools_catalog:
            mismatches.append((sid, tools_yaml, tools_catalog))

    if missing_in_catalog:
        print("Missing in catalog:")
        for sid in missing_in_catalog:
            print(f"- {sid}")

    if missing_in_skills:
        print("Missing skill.yaml for catalog entries:")
        for sid in missing_in_skills:
            print(f"- {sid}")

    if mismatches:
        print("Tool mismatches:")
        for sid, tools_yaml, tools_catalog in mismatches:
            print(f"- {sid}")
            print(f"  tools.yaml: {tools_yaml}")
            print(f"  catalog:   {tools_catalog}")

    if missing_in_catalog or missing_in_skills or mismatches:
        return 1

    print(f"OK: {len(skills)} skills match catalog tool lists.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
