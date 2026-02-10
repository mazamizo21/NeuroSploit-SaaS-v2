#!/usr/bin/env python3
"""Run core skill validation checks in one pass."""

import argparse
import json
import os
from typing import Dict, List, Tuple

import yaml


def load_yaml(path: str) -> Dict:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = yaml.safe_load(f)
    return data or {}


def collect_skills(skills_dir: str) -> Dict[str, Dict[str, object]]:
    skills: Dict[str, Dict[str, object]] = {}
    for entry in os.listdir(skills_dir):
        path = os.path.join(skills_dir, entry)
        if not os.path.isdir(path):
            continue
        skill_yaml = os.path.join(path, "skill.yaml")
        skill_md = os.path.join(path, "SKILL.md")
        if not os.path.exists(skill_yaml) or not os.path.exists(skill_md):
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
        outputs = data.get("outputs") or []
        skills[skill_id] = {
            "path": path,
            "tools": tools,
            "outputs": outputs,
            "skill_md": skill_md,
            "scripts_dir": os.path.join(path, "scripts"),
        }
    return skills


def check_catalog(skills_dir: str, catalog_path: str) -> Tuple[List[str], List[str], List[Tuple[str, List[str], List[str]]]]:
    skills = collect_skills(skills_dir)
    with open(catalog_path, "r", encoding="utf-8") as f:
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

    return missing_in_catalog, missing_in_skills, mismatches


def check_skill_docs(skills_dir: str) -> Tuple[List[str], List[str]]:
    skills = collect_skills(skills_dir)
    missing_evidence_ref: List[str] = []
    missing_consolidation: List[str] = []

    for sid, meta in skills.items():
        skill_md = meta["skill_md"]
        with open(skill_md, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        outputs = meta["outputs"]
        if "evidence.json" in outputs and "evidence.json" not in content:
            missing_evidence_ref.append(sid)

        scripts_dir = meta["scripts_dir"]
        has_scripts = os.path.isdir(scripts_dir) and any(
            name.endswith(".py") for name in os.listdir(scripts_dir)
        )
        if has_scripts and "## Evidence Consolidation" not in content:
            missing_consolidation.append(sid)

    return missing_evidence_ref, missing_consolidation


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skills-dir", default="skills", help="Skills directory")
    parser.add_argument("--catalog", default="skills/SKILL_CATALOG.json", help="Catalog JSON path")
    args = parser.parse_args()

    missing_in_catalog, missing_in_skills, mismatches = check_catalog(args.skills_dir, args.catalog)
    missing_evidence_ref, missing_consolidation = check_skill_docs(args.skills_dir)

    failed = False

    if missing_in_catalog:
        failed = True
        print("Missing in catalog:")
        for sid in missing_in_catalog:
            print(f"- {sid}")

    if missing_in_skills:
        failed = True
        print("Missing skill.yaml for catalog entries:")
        for sid in missing_in_skills:
            print(f"- {sid}")

    if mismatches:
        failed = True
        print("Tool mismatches:")
        for sid, tools_yaml, tools_catalog in mismatches:
            print(f"- {sid}")
            print(f"  tools.yaml: {tools_yaml}")
            print(f"  catalog:   {tools_catalog}")

    if missing_evidence_ref:
        failed = True
        print("Missing evidence.json reference in SKILL.md:")
        for sid in missing_evidence_ref:
            print(f"- {sid}")

    if missing_consolidation:
        failed = True
        print("Missing Evidence Consolidation section in SKILL.md:")
        for sid in missing_consolidation:
            print(f"- {sid}")

    if failed:
        return 1

    print("OK: catalog and skill documentation checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
