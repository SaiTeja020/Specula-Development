import pytest
import os
from src.agents.supervisor_agent import resolve_skill, SkillAccessDenied

def test_fallback_governance_escalates_on_light_tier_with_full_req():
    os.environ["SPECULA_DEPLOYMENT_MODE"] = "light"
    skill_manifest = {
        "report_agent": {
            "allowed_skills": ["generate_report"],
            "min_capability_tier": "full"
        }
    }
    state = {}
    resolve_skill("report_agent", "generate_report", skill_manifest, state)
    assert state.get("degraded_capability_mode") is True

def test_fallback_governance_ignores_if_full_tier_deployed():
    os.environ["SPECULA_DEPLOYMENT_MODE"] = "full"
    skill_manifest = {
        "report_agent": {
            "allowed_skills": ["generate_report"],
            "min_capability_tier": "full"
        }
    }
    state = {}
    resolve_skill("report_agent", "generate_report", skill_manifest, state)
    assert state.get("degraded_capability_mode") is None
