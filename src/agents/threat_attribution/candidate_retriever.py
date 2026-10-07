"""Discover ATT&CK groups with FAISS and load complete stable-ID profiles."""

from typing import Any


def retrieve_group_profiles(server: Any, query_text: str, top_k: int = 20) -> tuple[list[dict], list[str]]:
    response = server.query_attack_groups(query_text=query_text, top_k=top_k)
    if response.get("status") != "ok":
        return [], ["group_search_unavailable"]
    profiles = []
    for candidate in response.get("results", []):
        actor_id = candidate.get("record_id")
        if not actor_id:
            continue
        loaded = server.get_attack_group_profile(actor_id)
        profile = loaded.get("profile") if loaded.get("status") == "ok" else None
        if profile and profile.get("record_type") == "attack_group" and profile.get("technique_ids"):
            profiles.append(profile)
    return profiles, ([] if profiles else ["group_profiles_unavailable"])
