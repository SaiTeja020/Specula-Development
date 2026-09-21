"""
Tests for the real Threat Attribution Agent.

3 test scenarios per the approved implementation plan:
  1. Happy path    — FAISS returns techniques+groups, Neo4j returns entities
  2. FAISS not ready  — index not built; agent degrades to LLM-only
  3. Neo4j down    — graph query fails; agent runs with FAISS results only

All external I/O (FAISS, Neo4j, LLM) is mocked — no infrastructure required.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.agents.threat_attribution_agent import (
    run_threat_attribution,
    _query_threat_intel,
    _query_graph_entities,
    _parse_llm_response,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

FAKE_TECHNIQUES = [
    {
        "record_id": "T1059.001",
        "record_type": "attack_technique",
        "title": "PowerShell",
        "score": 0.91,
        "metadata": {"tags": ["execution"]},
    },
    {
        "record_id": "T1021.002",
        "record_type": "attack_technique",
        "title": "SMB/Windows Admin Shares",
        "score": 0.74,
        "metadata": {"tags": ["lateral-movement"]},
    },
]

FAKE_GROUPS = [
    {
        "record_id": "G0016",
        "record_type": "attack_group",
        "title": "APT29",
        "score": 0.81,
        "metadata": {},
    },
]

FAKE_ENTITIES = [
    {"uid": "entity:abc123", "type": "Process", "value": "powershell.exe"},
    {"uid": "entity:def456", "type": "NetworkConnection", "value": "10.0.0.5:445"},
]

FAKE_LLM_JSON = """{
  "techniques": [
    {"id": "T1059.001", "name": "PowerShell", "confidence": 0.87, "tactic": "execution", "reasoning": "PowerShell observed in timeline"},
    {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "confidence": 0.74, "tactic": "lateral-movement", "reasoning": "SMB traffic to internal host"}
  ],
  "groups": [
    {"id": "G0016", "name": "APT29", "confidence": 0.72, "reasoning": "TTP overlap with known APT29 campaigns"}
  ],
  "overall_confidence": 0.80,
  "low_confidence_flags": [],
  "narrative": "Attribution points to APT29 with moderate confidence based on PowerShell and SMB lateral movement techniques."
}"""

FAKE_STATE = {
    "case_id": "case-test-001",
    "trace_id": "trace-abc",
    "timeline": {
        "summary": "PowerShell executed on host-A at 14:02; SMB lateral movement to host-B at 14:07.",
        "dfkg_refs": [],
    },
    "findings": [],
}


# ---------------------------------------------------------------------------
# Test 1: Happy path — FAISS ready, Neo4j available, LLM returns valid JSON
# ---------------------------------------------------------------------------

class TestHappyPath:
    """FAISS returns techniques+groups, Neo4j returns entities, LLM returns valid JSON."""

    def test_attribution_contains_real_technique_ids(self):
        """attribution["techniques"] must contain IDs from FAISS results, not hallucinated."""
        fake_mcp = MagicMock()
        fake_mcp.query_attack_techniques.return_value = {"status": "ok", "results": FAKE_TECHNIQUES}
        fake_mcp.query_attack_groups.return_value = {"status": "ok", "results": FAKE_GROUPS}

        fake_neo4j_driver = MagicMock()
        fake_tool_result = MagicMock(ok=True, data=FAKE_ENTITIES, observation="ok")

        with patch(
            "src.mcp.threat_intel_mcp.ThreatIntelMCPServer",
            return_value=fake_mcp,
        ), patch(
            "src.agents.react_tools.DFKGQueryTool"
        ) as MockTool, patch(
            "src.agents.threat_attribution_agent._call_llm",
            return_value=FAKE_LLM_JSON,
        ):
            MockTool.return_value.run.return_value = fake_tool_result

            attribution, finding, trace = run_threat_attribution(
                FAKE_STATE, neo4j_driver=fake_neo4j_driver
            )

        # Technique IDs must match what FAISS + LLM agreed on
        tech_ids = [t["id"] for t in attribution["techniques"]]
        assert "T1059.001" in tech_ids
        assert "T1021.002" in tech_ids

    def test_attribution_contains_group(self):
        """attribution["groups"] must contain the APT29 group returned by FAISS."""
        fake_mcp = MagicMock()
        fake_mcp.query_attack_techniques.return_value = {"status": "ok", "results": FAKE_TECHNIQUES}
        fake_mcp.query_attack_groups.return_value = {"status": "ok", "results": FAKE_GROUPS}

        fake_tool_result = MagicMock(ok=True, data=FAKE_ENTITIES, observation="ok")

        with patch(
            "src.mcp.threat_intel_mcp.ThreatIntelMCPServer",
            return_value=fake_mcp,
        ), patch(
            "src.agents.react_tools.DFKGQueryTool"
        ) as MockTool, patch(
            "src.agents.threat_attribution_agent._call_llm",
            return_value=FAKE_LLM_JSON,
        ):
            MockTool.return_value.run.return_value = fake_tool_result

            attribution, finding, trace = run_threat_attribution(
                FAKE_STATE, neo4j_driver=MagicMock()
            )

        group_ids = [g["id"] for g in attribution["groups"]]
        assert "G0016" in group_ids

    def test_dfkg_refs_populated_from_entities(self):
        """dfkg_refs in the finding must be the UIDs of Neo4j entities, not []."""
        fake_mcp = MagicMock()
        fake_mcp.query_attack_techniques.return_value = {"status": "ok", "results": FAKE_TECHNIQUES}
        fake_mcp.query_attack_groups.return_value = {"status": "ok", "results": FAKE_GROUPS}

        fake_tool_result = MagicMock(ok=True, data=FAKE_ENTITIES, observation="ok")

        with patch(
            "src.mcp.threat_intel_mcp.ThreatIntelMCPServer",
            return_value=fake_mcp,
        ), patch(
            "src.agents.react_tools.DFKGQueryTool"
        ) as MockTool, patch(
            "src.agents.threat_attribution_agent._call_llm",
            return_value=FAKE_LLM_JSON,
        ):
            MockTool.return_value.run.return_value = fake_tool_result

            attribution, finding, trace = run_threat_attribution(
                FAKE_STATE, neo4j_driver=MagicMock()
            )

        assert "entity:abc123" in finding["dfkg_refs"]
        assert "entity:def456" in finding["dfkg_refs"]

    def test_confidence_basis_is_faiss_plus_llm(self):
        """When FAISS succeeds, confidence_basis must be 'faiss+llm'."""
        fake_mcp = MagicMock()
        fake_mcp.query_attack_techniques.return_value = {"status": "ok", "results": FAKE_TECHNIQUES}
        fake_mcp.query_attack_groups.return_value = {"status": "ok", "results": FAKE_GROUPS}

        with patch(
            "src.mcp.threat_intel_mcp.ThreatIntelMCPServer",
            return_value=fake_mcp,
        ), patch(
            "src.agents.react_tools.DFKGQueryTool"
        ) as MockTool, patch(
            "src.agents.threat_attribution_agent._call_llm",
            return_value=FAKE_LLM_JSON,
        ):
            MockTool.return_value.run.return_value = MagicMock(ok=True, data=[], observation="ok")

            attribution, finding, trace = run_threat_attribution(
                FAKE_STATE, neo4j_driver=MagicMock()
            )

        assert attribution["confidence_basis"] == "faiss+llm"


# ---------------------------------------------------------------------------
# Test 2: FAISS not ready — index not built, agent degrades gracefully
# ---------------------------------------------------------------------------

class TestFaissNotReady:
    """ThreatIntelMCPServer raises ThreatIntelIndexNotReadyError — agent must not crash."""

    def test_runs_llm_without_crashing(self):
        """Agent must complete and return valid attribution even when FAISS is unavailable."""
        with patch(
            "src.mcp.threat_intel_mcp.ThreatIntelMCPServer",
            side_effect=Exception("faiss index not ready"),
        ), patch(
            "src.agents.threat_attribution_agent._call_llm",
            return_value=FAKE_LLM_JSON,
        ):
            attribution, finding, trace = run_threat_attribution(
                FAKE_STATE, neo4j_driver=None
            )

        # Must still return a valid structure
        assert "techniques" in attribution
        assert "narrative" in attribution
        assert isinstance(finding["summary"], str)

    def test_confidence_basis_is_llm_only(self):
        """When FAISS fails, confidence_basis must be 'llm_only'."""
        with patch(
            "src.mcp.threat_intel_mcp.ThreatIntelMCPServer",
            side_effect=Exception("index not ready"),
        ), patch(
            "src.agents.threat_attribution_agent._call_llm",
            return_value=FAKE_LLM_JSON,
        ):
            attribution, finding, trace = run_threat_attribution(
                FAKE_STATE, neo4j_driver=None
            )

        assert attribution["confidence_basis"] == "llm_only"

    def test_dfkg_refs_empty_when_no_neo4j(self):
        """With neo4j_driver=None and no FAISS, dfkg_refs must be []."""
        with patch(
            "src.mcp.threat_intel_mcp.ThreatIntelMCPServer",
            side_effect=Exception("index not ready"),
        ), patch(
            "src.agents.threat_attribution_agent._call_llm",
            return_value=FAKE_LLM_JSON,
        ):
            attribution, finding, trace = run_threat_attribution(
                FAKE_STATE, neo4j_driver=None
            )

        assert finding["dfkg_refs"] == []


# ---------------------------------------------------------------------------
# Test 3: Neo4j down — graph query fails, agent runs with FAISS results only
# ---------------------------------------------------------------------------

class TestNeo4jDown:
    """DFKGQueryTool.run() raises — agent must skip graph lookup and not crash."""

    def test_runs_with_faiss_results_when_neo4j_fails(self):
        """Agent must return FAISS-grounded attribution even when Neo4j is unavailable."""
        fake_mcp = MagicMock()
        fake_mcp.query_attack_techniques.return_value = {"status": "ok", "results": FAKE_TECHNIQUES}
        fake_mcp.query_attack_groups.return_value = {"status": "ok", "results": FAKE_GROUPS}

        with patch(
            "src.mcp.threat_intel_mcp.ThreatIntelMCPServer",
            return_value=fake_mcp,
        ), patch(
            "src.agents.react_tools.DFKGQueryTool",
            side_effect=Exception("neo4j connection refused"),
        ), patch(
            "src.agents.threat_attribution_agent._call_llm",
            return_value=FAKE_LLM_JSON,
        ):
            attribution, finding, trace = run_threat_attribution(
                FAKE_STATE, neo4j_driver=MagicMock()
            )

        # FAISS results should still be reflected in the output
        assert attribution["confidence_basis"] == "faiss+llm"
        assert isinstance(finding["summary"], str)

    def test_dfkg_refs_empty_when_neo4j_fails(self):
        """dfkg_refs must be [] when Neo4j is down (no entity UIDs to reference)."""
        fake_mcp = MagicMock()
        fake_mcp.query_attack_techniques.return_value = {"status": "ok", "results": FAKE_TECHNIQUES}
        fake_mcp.query_attack_groups.return_value = {"status": "ok", "results": FAKE_GROUPS}

        with patch(
            "src.mcp.threat_intel_mcp.ThreatIntelMCPServer",
            return_value=fake_mcp,
        ), patch(
            "src.agents.react_tools.DFKGQueryTool",
            side_effect=Exception("neo4j down"),
        ), patch(
            "src.agents.threat_attribution_agent._call_llm",
            return_value=FAKE_LLM_JSON,
        ):
            attribution, finding, trace = run_threat_attribution(
                FAKE_STATE, neo4j_driver=MagicMock()
            )

        assert finding["dfkg_refs"] == []


# ---------------------------------------------------------------------------
# Unit tests: internal helpers
# ---------------------------------------------------------------------------

class TestParseResponse:
    """_parse_llm_response handles both valid JSON and malformed output."""

    def test_parses_valid_json(self):
        result = _parse_llm_response(FAKE_LLM_JSON)
        assert result["techniques"][0]["id"] == "T1059.001"
        assert result["overall_confidence"] == 0.80

    def test_handles_json_in_code_fence(self):
        fenced = f"```json\n{FAKE_LLM_JSON}\n```"
        result = _parse_llm_response(fenced)
        assert result["techniques"][0]["id"] == "T1059.001"

    def test_degrades_on_invalid_json(self):
        """Malformed LLM output must not raise — returns narrative fallback."""
        result = _parse_llm_response("Sorry, I cannot provide attribution for this case.")
        assert result["techniques"] == []
        assert result["overall_confidence"] == 0.0
        assert "low_confidence_flags" in result
        assert "narrative" in result
