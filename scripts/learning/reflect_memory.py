#!/usr/bin/env python3
"""
Reflect on short-term memory and promote durable learnings to long-term memory.
Generates a daily reflection report and respects learning gates.
"""

import argparse
import json
import os
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Tuple


def _repo_root() -> str:
    here = os.path.abspath(os.path.dirname(__file__))
    return os.path.abspath(os.path.join(here, "..", ".."))


def _load_gate(memory_dir: str) -> Dict:
    gate_path = os.path.join(memory_dir, "BENCHMARKS", "learning_gate.json")
    if not os.path.exists(gate_path):
        return {}
    try:
        with open(gate_path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _parse_daily_file(path: str) -> List[Tuple[str, str, str]]:
    """
    Parse daily memory lines:
    - 2026-02-06T01:23:45+00:00 [category] content
    Returns list of (timestamp, category, content)
    """
    entries = []
    if not os.path.exists(path):
        return entries
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("- "):
                    continue
                m = re.match(r"^-\\s+(\\S+)\\s+\\[([^\\]]+)\\]\\s+(.+)$", line)
                if not m:
                    continue
                ts, cat, content = m.group(1), m.group(2), m.group(3)
                entries.append((ts, cat.strip().lower(), content.strip()))
    except Exception:
        return entries
    return entries


def _load_daily_entries(memory_dir: str, tenant_id: str, days: int) -> List[Tuple[str, str, str]]:
    entries: List[Tuple[str, str, str]] = []
    today = datetime.now(timezone.utc).date()
    for offset in range(days):
        day = datetime.combine(today - timedelta(days=offset), datetime.min.time(), tzinfo=timezone.utc)
        day_str = day.strftime("%Y-%m-%d")
        path = os.path.join(memory_dir, "DAILY", f"{tenant_id}_{day_str}.md")
        entries.extend(_parse_daily_file(path))
    return entries


def _load_session_summaries(memory_dir: str, tenant_id: str, limit: int = 5) -> List[Dict]:
    history_dir = os.path.join(memory_dir, "SESSION_HISTORY")
    if not os.path.exists(history_dir):
        return []
    items = []
    for fname in os.listdir(history_dir):
        if not fname.startswith(f"{tenant_id}_") or not fname.endswith(".json"):
            continue
        try:
            path = os.path.join(history_dir, fname)
            with open(path, "r") as f:
                items.append(json.load(f))
        except Exception:
            continue
    items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return items[:limit]


def _load_tool_stats(memory_dir: str, tenant_id: str, limit: int = 5) -> List[Dict]:
    path = os.path.join(memory_dir, f"{tenant_id}_tool_stats.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            data = json.load(f)
        tools = data.get("tools", {})
        items = [{"tool": k, **v} for k, v in tools.items() if isinstance(v, dict)]
        items.sort(key=lambda x: (x.get("success_rate", 0.0), x.get("success", 0)), reverse=True)
        return items[:limit]
    except Exception:
        return []


def _promotable_categories() -> set:
    return {
        "credential_found",
        "vulnerability_found",
        "access_gained",
        "technique_worked",
        "technique_failed",
        "package_name",
        "target_info",
    }


def run_reflection(memory_dir: str, tenant_id: str, days: int, min_occurrences: int, max_promote: int, force: bool):
    os.environ["MEMORY_DIR"] = memory_dir
    # Import MemoryStore from agent code
    import sys
    sys.path.insert(0, os.path.join(_repo_root(), "kali-executor", "open-interpreter"))
    from memory import MemoryStore, Memory  # type: ignore

    store = MemoryStore(tenant_id=tenant_id, target="global")

    gate = _load_gate(memory_dir)
    promote_allowed = gate.get("promote", True)
    if force:
        promote_allowed = True

    entries = _load_daily_entries(memory_dir, tenant_id, days)
    counts: Dict[Tuple[str, str], int] = {}
    last_seen: Dict[Tuple[str, str], str] = {}
    for ts, cat, content in entries:
        key = (cat, content)
        counts[key] = counts.get(key, 0) + 1
        last_seen[key] = ts

    promotable = []
    for (cat, content), count in counts.items():
        if cat in _promotable_categories() or count >= min_occurrences:
            promotable.append((cat, content, count, last_seen.get((cat, content), "")))

    promotable.sort(key=lambda x: (x[2], x[3]), reverse=True)
    promotable = promotable[:max_promote]

    promoted = 0
    promoted_items: List[str] = []
    if promote_allowed and promotable:
        memories = []
        for cat, content, count, ts in promotable:
            mem = Memory(
                id="",
                timestamp=ts or datetime.now(timezone.utc).isoformat(),
                category=cat,
                content=content,
                context={"source": "reflection", "count": count},
                importance="high" if cat in _promotable_categories() else "medium",
            )
            memories.append(mem)
            promoted_items.append(f"- [{cat}] {content}")
        promoted = store.promote_memories(memories)

    # Build reflection report
    report_dir = os.path.join(memory_dir, "REFLECTIONS")
    os.makedirs(report_dir, exist_ok=True)
    report_path = os.path.join(report_dir, f"{tenant_id}_{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.md")

    categories = {}
    for (cat, _), count in counts.items():
        categories[cat] = categories.get(cat, 0) + count
    top_categories = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:8]

    tool_stats = _load_tool_stats(memory_dir, tenant_id, limit=5)
    sessions = _load_session_summaries(memory_dir, tenant_id, limit=5)

    with open(report_path, "w") as f:
        f.write(f"# Daily Reflection — {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        if gate:
            f.write("## Learning Gate\n")
            f.write(f"- Promote allowed: {promote_allowed}\n")
            f.write(f"- Status: {gate.get('status', 'unknown')}\n")
            f.write(f"- Score: {gate.get('score', 'n/a')}\n")
            f.write(f"- Baseline: {gate.get('baseline_score', 'n/a')}\n")
            f.write(f"- Score delta: {gate.get('score_delta', 'n/a')}\n\n")

        f.write("## Summary\n")
        f.write(f"- Daily entries analyzed: {len(entries)}\n")
        f.write(f"- Unique entries: {len(counts)}\n")
        f.write(f"- Promoted to long-term: {promoted}\n\n")

        if top_categories:
            f.write("## Top Categories\n")
            for cat, count in top_categories:
                f.write(f"- {cat}: {count}\n")
            f.write("\n")

        if tool_stats:
            f.write("## Top Tool Performance\n")
            for item in tool_stats:
                f.write(
                    f"- {item.get('tool')}: {item.get('success_rate', 0.0)}% "
                    f"({item.get('success', 0)} success / {item.get('failure', 0)} fail)\n"
                )
            f.write("\n")

        if sessions:
            f.write("## Recent Sessions\n")
            for s in sessions:
                summary = s.get("summary", {})
                f.write(
                    f"- {s.get('session_id')} | target={summary.get('target', s.get('target', 'n/a'))} "
                    f"| findings={summary.get('findings_count', 'n/a')} "
                    f"| success={summary.get('successful_executions', 'n/a')}/{summary.get('total_executions', 'n/a')}\n"
                )
            f.write("\n")

        if promoted_items:
            f.write("## Promoted Notes\n")
            for item in promoted_items:
                f.write(f"{item}\n")
            f.write("\n")

    return {"report_path": report_path, "promoted": promoted, "promote_allowed": promote_allowed}


def main():
    parser = argparse.ArgumentParser(description="Reflect on short-term memory and update long-term memory.")
    parser.add_argument("--memory-dir", default=os.environ.get("MEMORY_DIR", "./memory"))
    parser.add_argument("--tenant-id", default=os.environ.get("TENANT_ID", "default"))
    parser.add_argument("--days", type=int, default=int(os.environ.get("REFLECT_DAYS", "2")))
    parser.add_argument("--min-occurrences", type=int, default=int(os.environ.get("REFLECT_MIN_OCCURRENCES", "2")))
    parser.add_argument("--max-promote", type=int, default=int(os.environ.get("REFLECT_MAX_PROMOTE", "50")))
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    result = run_reflection(
        memory_dir=args.memory_dir,
        tenant_id=args.tenant_id,
        days=args.days,
        min_occurrences=args.min_occurrences,
        max_promote=args.max_promote,
        force=args.force,
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
