# elasticsearch Toolcard

## Overview
- Summary: Elasticsearch exposes a REST API for cluster and index metadata, including human-readable `_cat` endpoints.

## Advanced Techniques
- Use the root endpoint to capture version and build metadata.
- Use `_cluster/health` for status and `_cat/indices` for visibility.
- Prefer JSON APIs for automation; `_cat` is primarily for human use.

## Safe Defaults
- Rate limits: avoid repeated bulk queries on external targets.
- Scope rules: explicit target only.

## Evidence Outputs
- outputs: es_cluster.json, es_indices.json

## References
- https://www.elastic.co/guide/en/elasticsearch/reference/current/cat.html
- https://www.elastic.co/guide/en/elasticsearch/reference/current/cat-indices.html
- https://www.elastic.co/guide/en/elasticsearch/reference/current/api-conventions.html
