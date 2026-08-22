import pytest
from src.agents.supervisor_agent import SkillAccessDenied

def test_supervisor_never_uses_hardcoded_agent_tool_map():
    """Supervisor MUST read tool allowances dynamically from MCP or Neo4j Skill Manifests. There MUST be no hardcoded agent-to-tool maps."""
    # We verify no static map is defined in the module
    import src.agents.supervisor_agent as sa
    assert not hasattr(sa, "AGENT_TOOL_MAPPING")

def test_supervisor_blocks_out_of_scope_skill_access():
    """If an agent attempts to invoke a tool out of scope, the supervisor MUST block it with SkillAccessDenied."""
    from src.agents.supervisor_agent import resolve_skill
    
    skill_manifest = {
        "report_generation": {
            "allowed_skills": ["document_query"]
        }
    }
    
    with pytest.raises(SkillAccessDenied) as exc:
        resolve_skill("report_generation", "mcp-vmi-sandbox", skill_manifest)
        
    assert "SECURITY BLOCK" in str(exc.value)
