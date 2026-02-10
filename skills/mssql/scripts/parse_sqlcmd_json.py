#!/usr/bin/env python3
"""Extract JSON output from sqlcmd results and summarize records."""

import argparse
import json
from typing import Any, Dict, List


def extract_json(text: str) -> Any:
    candidates = [text.find("{"), text.find("[")]
    candidates = [c for c in candidates if c >= 0]
    if not candidates:
        raise ValueError("No JSON object or array found in input")
    start = min(candidates)
    end_obj = text.rfind("}")
    end_arr = text.rfind("]")
    end = max(end_obj, end_arr)
    if end < start:
        raise ValueError("Malformed JSON boundaries")
    snippet = text[start : end + 1]
    return json.loads(snippet)


def summarize(data: Any) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    if isinstance(data, list):
        summary["count"] = len(data)
        names: List[str] = []
        if data and isinstance(data[0], dict):
            for row in data:
                if isinstance(row, dict) and "name" in row and isinstance(row["name"], str):
                    names.append(row["name"])
        if names:
            summary["sample_names"] = names[:20]
        summary["keys"] = sorted({k for row in data if isinstance(row, dict) for k in row.keys()})
    elif isinstance(data, dict):
        summary["keys"] = sorted(list(data.keys()))
    else:
        summary["type"] = type(data).__name__
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="Path to sqlcmd output file")
    parser.add_argument("--out", required=True, help="Output JSON file")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    data = extract_json(raw)
    output = {
        "summary": summarize(data),
        "data": data,
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()

