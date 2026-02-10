#!/usr/bin/env python3
"""Summarize Elasticsearch cluster and index metadata from JSON inputs."""

import argparse
import json
from typing import Any, Dict, List


def _load_json(path: str) -> Any:
    if not path:
        return None
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return json.load(f)


def summarize_cluster(cluster: Any) -> Dict[str, Any]:
    if not isinstance(cluster, dict):
        return {}
    version = cluster.get("version", {})
    return {
        "cluster_name": cluster.get("cluster_name", ""),
        "status": cluster.get("status", ""),
        "number_of_nodes": cluster.get("number_of_nodes"),
        "number_of_data_nodes": cluster.get("number_of_data_nodes"),
        "version": version.get("number") if isinstance(version, dict) else "",
    }


def _to_int(value: Any) -> int:
    try:
        return int(str(value).replace(",", ""))
    except Exception:
        return 0


def summarize_indices(indices: Any) -> Dict[str, Any]:
    if not isinstance(indices, list):
        return {}
    total_docs = 0
    names: List[str] = []
    for row in indices:
        if not isinstance(row, dict):
            continue
        name = row.get("index") or row.get("i")
        if name:
            names.append(str(name))
        docs = row.get("docs.count") or row.get("docsCount") or row.get("docs")
        total_docs += _to_int(docs)
    return {
        "count": len(names),
        "total_docs": total_docs,
        "sample_indices": names[:20],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cluster", help="Path to cluster health JSON", default="")
    parser.add_argument("--indices", help="Path to _cat/indices JSON", default="")
    parser.add_argument("--out", required=True, help="Output JSON summary file")
    args = parser.parse_args()

    cluster = _load_json(args.cluster)
    indices = _load_json(args.indices)

    output = {
        "cluster": summarize_cluster(cluster),
        "indices": summarize_indices(indices),
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()

