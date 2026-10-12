"""Ingest a bounded Windows log interval into a new local case and investigate it."""

import json
from pathlib import Path

import requests


ROOT = Path(__file__).resolve().parents[1]
CHANNELS = (
    "System", "Security", "Application", "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Windows Defender/Operational", "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-Sysmon/Operational",
)


def ingest_case(case_id, start_date, end_date, max_events, exclude_ports):
    from src.ingestion.run_pipeline import extract_windows_events
    batches = (("evtx", extract_windows_events(channel, start_date, end_date, max_events))
               for channel in CHANNELS)
    return _ingest_batches(case_id, batches, exclude_ports)


def ingest_uploaded_case(case_id, archive_path, provenance, start_date, end_date, max_events, exclude_ports):
    from datetime import datetime
    from src.ingestion.upload_archive import archive_batches
    lower = datetime.fromisoformat(start_date).astimezone() if start_date else None
    upper = datetime.fromisoformat(end_date).astimezone() if end_date else None

    def selected():
        for source, records in archive_batches(archive_path, provenance):
            filtered = []
            for raw in records:
                if lower:
                    stamp = (raw.get("TimeCreated") or raw.get("eventTime") or raw.get("LastRecordChange") or
                             (raw.get("System") or {}).get("TimeCreated", {}).get("SystemTime"))
                    try:
                        moment = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
                    except ValueError:
                        raise ValueError("Date filtering requires explicit ISO 8601 timestamps on every uploaded record") from None
                    if moment.tzinfo is None:
                        raise ValueError("Uploaded timestamps must include a UTC offset when filtering by date")
                    if not lower <= moment <= upper:
                        continue
                filtered.append(raw)
            yield source, filtered[:max_events]

    provenance["selection"] = {"start_date": start_date, "end_date": end_date,
                               "max_events_per_file": max_events, "excluded_ports": exclude_ports}
    return _ingest_batches(case_id, selected(), exclude_ports, provenance)


def _ingest_batches(case_id, batches, exclude_ports, provenance=None):
    from src.ingestion.run_pipeline import run_pipeline_on_event
    from src.ingestion.preservation.quickwit_client import QuickwitClient
    from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain
    from src.schemas.entity_resolver import CanonicalEntityResolver
    from src.ingestion.normalization.time_normalizer import TimeNormalizer
    from src.graph.neo4j_client import Neo4jClient

    quickwit = QuickwitClient()
    quickwit.ensure_index()
    graph = Neo4jClient()
    accepted = 0
    extracted = 0
    case_created = False
    rejected = []
    ordinal = 0
    records_without_events = 0
    try:
        vct = VCTAtomicChain()
        resolver = CanonicalEntityResolver()
        normalizer = TimeNormalizer(dc_anchor_skew_ms=0)
        for source_type, records in batches:
            extracted += len(records)
            for raw in records:
                ordinal += 1
                try:
                    results = run_pipeline_on_event(
                        raw, vct, resolver, normalizer, qw_client=quickwit,
                        source_type=source_type, neo4j_client=graph,
                        exclude_ports=set(exclude_ports), case_id=case_id,
                    )
                except (ValueError, TypeError, KeyError) as error:
                    if provenance is None:
                        raise
                    if len(rejected) < 20:
                        rejected.append({"record": ordinal, "reason": type(error).__name__})
                    records_without_events += 1
                    continue
                valid_count = 0
                for event, _, write_result in results:
                    if not event.valid or event.event is None:
                        continue
                    if write_result is None:
                        raise RuntimeError("Evidence graph write failed after preservation")
                    if not case_created:
                        graph.execute(
                            "MERGE (c:Case {uid: $case_id}) "
                            "SET c.owner_user_id = $owner, c.member_user_ids = []",
                            {"case_id": case_id, "owner": "local-validation"},
                        )
                        case_created = True
                    properties = event.event.model_dump(mode="json")
                    properties = {key: value if isinstance(value, (str, int, float, bool, type(None)))
                                  else json.dumps(value, sort_keys=True)
                                  for key, value in properties.items()}
                    graph.execute(
                        "MATCH (c:Case {uid: $case_id}) "
                        "MERGE (e:Event {uid: $event_uid}) "
                        "ON CREATE SET e += $properties "
                        "MERGE (c)-[:HAS_EVENT]->(e)",
                        {"case_id": case_id, "event_uid": event.event.uid,
                         "properties": properties},
                    )
                    accepted += 1
                    valid_count += 1
                records_without_events += valid_count == 0
        if provenance is not None and case_created:
            provenance["processing"] = {"selected_records": extracted, "normalized_events": accepted,
                                        "record_errors_sample": rejected,
                                        "selected_records_without_normalized_events": records_without_events,
                                        "coverage": "Only supported valid records are normalized; unsupported and filtered records may be excluded"}
            graph.execute("MATCH (c:Case {uid: $case_id}) SET c.ingestion_provenance_json = $provenance",
                          {"case_id": case_id, "provenance": json.dumps(provenance, sort_keys=True)})
    finally:
        graph.close()
    if not accepted:
        raise RuntimeError("No supported log events were found in the selected interval")
    return {"case_id": case_id, "extracted": extracted, "accepted": accepted}


def investigate_case(case_id):
    token = (ROOT / "data" / "private" / "verification_token").read_text(encoding="utf-8").strip()
    with requests.Session() as session:
        session.trust_env = False
        response = session.post("http://127.0.0.1:8300/api/investigations",
                                headers={"Authorization": f"Bearer {token}"},
                                json={"case_id": case_id}, timeout=900)
    payload = response.json()
    if not response.ok:
        raise RuntimeError(payload.get("detail", "Investigation request failed"))
    return payload
