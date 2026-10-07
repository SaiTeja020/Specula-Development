"""Pure deterministic ATT&CK profile comparison."""

from .models import ThreatActorCandidate


def jaccard_similarity(observed: list[str], profile: list[str]) -> float:
    left, right = set(observed), set(profile)
    return len(left & right) / len(left | right) if left or right else 0.0


def smith_waterman_similarity(observed: list[str], profile: list[str]) -> float:
    """Local alignment divided by 2 * shorter length; match=2, mismatch/gap=-1."""
    if not observed or not profile:
        return 0.0
    previous = [0] * (len(profile) + 1)
    best = 0
    for left in observed:
        current = [0]
        for index, right in enumerate(profile, 1):
            value = max(0, previous[index - 1] + (2 if left == right else -1),
                        previous[index] - 1, current[-1] - 1)
            current.append(value)
            best = max(best, value)
        previous = current
    return min(1.0, best / (2 * min(len(observed), len(profile))))


def rank_candidates(observed: list[str], profiles: list[dict]) -> list[ThreatActorCandidate]:
    candidates = []
    for profile in profiles:
        ids = profile.get("technique_ids") or []
        sequence = profile.get("technique_sequence") or []
        jaccard = jaccard_similarity(observed, ids)
        alignment = smith_waterman_similarity(observed, sequence) if sequence else 0.0
        candidates.append(ThreatActorCandidate(
            actor_id=profile["record_id"], name=profile.get("title", profile["record_id"]),
            jaccard=jaccard, smith_waterman=alignment,
            combined_score=0.4 * jaccard + 0.6 * alignment,
            matched_techniques=sorted(set(observed) & set(ids)),
            profile_techniques=list(ids), sequence_available=bool(sequence),
            sequence_basis=profile.get("sequence_basis"),
            source_hash=profile.get("source_hash"), source_version=profile.get("source_version"),
        ))
    return sorted(candidates, key=lambda item: (-item.combined_score, item.actor_id))[:3]


def confidence_bounds(candidates: list[ThreatActorCandidate], observed_count: int,
                      stale: bool, citation_complete: bool) -> tuple[float, float, float]:
    """Heuristic evidence confidence interval, never a probability of authorship."""
    if not candidates or not observed_count:
        return 0.0, 0.0, 0.0
    top = candidates[0]
    runner_up = candidates[1].combined_score if len(candidates) > 1 else 0.0
    coverage = len(top.matched_techniques) / observed_count
    quantity = min(1.0, observed_count / 4)
    margin = max(0.0, top.combined_score - runner_up)
    freshness = 0.6 if stale else 1.0
    citation = 1.0 if citation_complete else 0.5
    sequence_quality = 0.75 if top.sequence_basis == "attack_tactic_order" else 1.0
    point = top.combined_score * coverage * quantity * (0.5 + 0.5 * margin) * freshness * citation * sequence_quality
    uncertainty = 0.1 + 0.1 * (1 - coverage) + (0.1 if stale else 0.0) + (0.1 if sequence_quality < 1 else 0.0)
    return round(max(0.0, point - uncertainty), 4), round(point, 4), round(min(1.0, point + uncertainty), 4)
