"""Load complete ATT&CK group profiles for deterministic case scoring."""

from typing import Any


def retrieve_group_profiles(server: Any, query_text: str, top_k: int = 20) -> tuple[list[dict], list[str]]:
    if not hasattr(server, "list_attack_group_profiles"):
        return [], ["group_profiles_unavailable"]
    response = server.list_attack_group_profiles()
    if response.get("status") != "ok":
        return [], ["group_profiles_unavailable"]
    profiles = [profile for profile in response.get("profiles", [])
                if profile.get("record_type") == "attack_group" and profile.get("technique_ids")]
    return profiles, ([] if profiles else ["group_profiles_unavailable"])
