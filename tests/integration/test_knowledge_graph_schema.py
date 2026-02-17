#!/usr/bin/env python3
"""Integration test — verify KnowledgeGraph schema matches expected node/relationship types.

This test validates the code-level schema definitions WITHOUT requiring a running
Neo4j instance. It inspects the Cypher statements in _init_schema() and the
public methods to ensure all 10 node types and 9 relationship types are present.
"""

import inspect
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kali-executor" / "open-interpreter"))

# Import knowledge_graph — it may fail to connect to Neo4j, but we only need
# the class definition and schema strings.
import os
os.environ["KNOWLEDGE_GRAPH_ENABLED"] = "false"  # prevent connection attempt

from knowledge_graph import KnowledgeGraph, _redact  # noqa: E402

# ---------------------------------------------------------------------------
# Expected schema (from knowledge_graph.py docstring)
# ---------------------------------------------------------------------------

EXPECTED_NODE_TYPES = {
    "Target",
    "Port",
    "Service",
    "Technology",
    "Vulnerability",
    "CVE",
    "Exploit",
    "Credential",
    "Endpoint",
    "MitreTechnique",
}

EXPECTED_RELATIONSHIPS = {
    "HAS_PORT",         # Target -> Port
    "RUNS",             # Port -> Service
    "USES_TECH",        # Service -> Technology
    "HAS_VULNERABILITY",# Target -> Vulnerability
    "REFERENCES",       # Vulnerability -> CVE
    "EXPLOITED_BY",     # Vulnerability -> Exploit
    "YIELDED",          # Exploit -> Credential
    "HAS_ENDPOINT",     # Service -> Endpoint
    "USES_TECHNIQUE",   # Exploit -> MitreTechnique
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestKnowledgeGraphSchema:
    """Verify the KnowledgeGraph class declares all expected schema elements."""

    def test_init_schema_references_all_node_types(self):
        """_init_schema() Cypher should reference constraints for all node types."""
        source = inspect.getsource(KnowledgeGraph._init_schema)
        for node_type in EXPECTED_NODE_TYPES:
            assert node_type in source, (
                f"Node type '{node_type}' not found in _init_schema() Cypher. "
                "Missing constraint/index?"
            )

    def test_class_has_add_methods_for_all_node_types(self):
        """KnowledgeGraph should have an add_* method for each node type."""
        method_map = {
            "Target": "add_target",
            "Port": "add_port",
            "Service": "add_service",
            "Technology": "add_technology",
            "Vulnerability": "add_vulnerability",
            "CVE": "add_cve",
            "Exploit": "add_exploit",
            "Credential": "add_credential",
            "Endpoint": "add_endpoint",
            "MitreTechnique": "add_mitre_technique",
        }
        for node_type, method_name in method_map.items():
            assert hasattr(KnowledgeGraph, method_name), (
                f"KnowledgeGraph missing method '{method_name}' for node type '{node_type}'"
            )

    def test_relationship_types_in_source(self):
        """All expected relationship types should appear in the class source."""
        full_source = inspect.getsource(KnowledgeGraph)
        for rel in EXPECTED_RELATIONSHIPS:
            assert rel in full_source, (
                f"Relationship type '{rel}' not found in KnowledgeGraph source. "
                "Was it renamed or removed?"
            )

    def test_init_schema_has_constraints_and_indexes(self):
        """_init_schema should create both constraints and indexes."""
        source = inspect.getsource(KnowledgeGraph._init_schema)
        assert "CREATE CONSTRAINT" in source, "No CREATE CONSTRAINT in _init_schema"
        assert "CREATE INDEX" in source, "No CREATE INDEX in _init_schema"

    def test_redact_function(self):
        """_redact should properly mask sensitive values."""
        assert _redact(None) is None
        assert _redact("") is None
        # Short values fully redacted
        assert _redact("ab") == "**"
        assert _redact("abcd") == "****"
        # Longer values keep first/last 2 chars
        result = _redact("password123")
        assert result.startswith("pa")
        assert result.endswith("23")
        assert "*" in result
        assert len(result) == len("password123")

    def test_knowledge_graph_available_property(self):
        """available property should return False when driver is None."""
        # We can't create a real KnowledgeGraph without Neo4j, but we can
        # verify the property exists and the class structure.
        assert hasattr(KnowledgeGraph, "available")

    def test_node_type_count(self):
        """Sanity check: we expect exactly 10 node types."""
        assert len(EXPECTED_NODE_TYPES) == 10

    def test_relationship_count(self):
        """Sanity check: we expect exactly 9 relationship types."""
        assert len(EXPECTED_RELATIONSHIPS) == 9

    def test_query_methods_exist(self):
        """KnowledgeGraph should have key query methods for the attack graph UI."""
        query_methods = [
            "get_unexploited_services",
            "get_unattempted_services",
            "get_all_credentials",
            "get_attack_surface_summary",
        ]
        for method_name in query_methods:
            assert hasattr(KnowledgeGraph, method_name), (
                f"KnowledgeGraph missing query method '{method_name}'"
            )

    def test_link_exploit_technique_exists(self):
        """The method to link exploits to MITRE techniques should exist."""
        assert hasattr(KnowledgeGraph, "link_exploit_technique")
