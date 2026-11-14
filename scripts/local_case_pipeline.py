"""Ingest a bounded Windows log interval into a new local case and investigate it."""

import json
from subprocess import TimeoutExpired
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
    provenance = {'source': 'local_windows', 'channel_receipts': [],
        'selection': {'start_date': start_date, 'end_date': end_date, 'max_events_per_channel': max_events,
                      'excluded_ports': sorted(exclude_ports)}}
    def batches():
        for channel in CHANNELS:
            try:
                rows = extract_windows_events(channel, start_date, end_date, max_events)
                provenance['channel_receipts'].append({'channel': channel, 'status': 'complete', 'records': len(rows)})
            except (RuntimeError, OSError, TimeoutError, TimeoutExpired) as error:
                rows = []
                provenance['channel_receipts'].append({'channel': channel, 'status': 'unavailable',
                    'records': 0, 'error_type': type(error).__name__,
                    'limitation': 'Channel acquisition unavailable; not evidence of no activity.'})
            yield 'evtx', rows
    return _ingest_batches(case_id, batches(), exclude_ports, provenance)


def ingest_uploaded_case(case_id, archive_path, provenance, start_date, end_date, max_events, exclude_ports):
    from datetime import datetime
    from src.ingestion.upload_archive import archive_batches
    lower = datetime.fromisoformat(start_date).astimezone() if start_date else None
    upper = datetime.fromisoformat(end_date).astimezone() if end_date else None

    def selected():
        from src.ingestion.export_aliases import record_timestamp
        for source, records, filename in archive_batches(archive_path, provenance, include_path=True):
            filtered = []
            for record_number, raw in enumerate(records, 1):
                if lower:
                    try:
                        stamp = record_timestamp(raw, source)
                        moment = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
                    except ValueError as error:
                        raise ValueError(f"{filename} record {record_number}: {error}") from None
                    if moment.tzinfo is None:
                        raise ValueError("Uploaded timestamps must include a UTC offset when filtering by date")
                    if not lower <= moment <= upper:
                        continue
                filtered.append(raw)
            yield source, filtered[:max_events], filename

    provenance["selection"] = {"start_date": start_date, "end_date": end_date,
                               "max_events_per_file": max_events, "excluded_ports": exclude_ports}
    return _ingest_batches(case_id, selected(), exclude_ports, provenance)


def _ingest_batches(case_id, batches, exclude_ports, provenance=None, append_only=False):
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
    records_without_events = 0
    try:
        if append_only:
            owners=graph.execute('MATCH (c:Case {uid:$case_id}) RETURN c.owner_user_id AS owner',{'case_id':case_id})
            if len(owners)!=1 or owners[0]['owner']!='local-validation':
                raise ValueError('Follow-up acquisition requires an existing authorized local case')
        vct = VCTAtomicChain()
        resolver = CanonicalEntityResolver()
        normalizer = TimeNormalizer(dc_anchor_skew_ms=0)
        for batch in batches:
            source_type, records = batch[:2]
            filename = batch[2] if len(batch) > 2 else None
            extracted += len(records)
            for record_number, raw in enumerate(records, 1):
                try:
                    results = run_pipeline_on_event(
                        raw, vct, resolver, normalizer, qw_client=quickwit,
                        source_type=source_type, neo4j_client=graph,
                        exclude_ports=set(exclude_ports), case_id=case_id,
                        exported_log_path=filename,
                    )
                except (ValueError, TypeError, KeyError) as error:
                    if provenance is None:
                        raise
                    if len(rejected) < 20:
                        rejected.append({"file": filename, "record": record_number,
                                         "reason": str(error)[:300], "error_type": type(error).__name__})
                    records_without_events += 1
                    continue
                valid_count = 0
                for event, _, write_result in results:
                    if not event.valid or event.event is None:
                        continue
                    if write_result is None:
                        raise RuntimeError("Evidence graph write failed after preservation")
                    if not case_created:
                        if not append_only:graph.execute(
                            "MERGE (c:Case {uid: $case_id}) "
                            "SET c.owner_user_id = $owner, c.member_user_ids = []",
                            {"case_id": case_id, "owner": "local-validation"},
                        )
                        case_created = True
                    properties = event.event.model_dump(mode="json")
                    system = raw.get("System") if isinstance(raw.get("System"), dict) else {}
                    source_event_id = raw.get("event_id") or raw.get("Id") or system.get("EventID")
                    if isinstance(source_event_id, str) and source_event_id.isdigit():
                        source_event_id = int(source_event_id)
                    properties.update({"source_type": source_type,
                        "source_event_id": source_event_id,
                        "source_event_type": raw.get("event_type") or raw.get("event"),
                        "source_outcome": raw.get("status"), "source_user_name": raw.get("user") if isinstance(raw.get("user"), str) else None,
                        "source_finding": raw.get("finding") or raw.get("detection"),
                        "source_baseline_status": raw.get("baseline_status"),
                        "source_volume_creation_time": raw.get("volume_creation_time")})
                    properties = {key: value if isinstance(value, (str, int, float, bool, type(None)))
                                  else json.dumps(value, sort_keys=True)
                                  for key, value in properties.items()}
                    graph.execute(
                        "MATCH (c:Case {uid: $case_id}) "
                        "MERGE (e:Event {uid: $event_uid}) "
                        "ON CREATE SET e += $properties "
                        "FOREACH (key IN [key IN keys($properties) WHERE e[key] IS NULL] | SET e[key] = $properties[key]) "
                        "SET e.source_event_id = coalesce(e.source_event_id, $properties.source_event_id), "
                        "e.source_event_type = coalesce(e.source_event_type, $properties.source_event_type), "
                        "e.source_type = coalesce(e.source_type, $properties.source_type), "
                        "e.source_finding = coalesce(e.source_finding, $properties.source_finding), "
                        "e.source_baseline_status = coalesce(e.source_baseline_status, $properties.source_baseline_status), "
                        "e.source_outcome = coalesce(e.source_outcome, $properties.source_outcome), "
                        "e.source_user_name = coalesce(e.source_user_name, $properties.source_user_name), "
                        "e.source_volume_creation_time = coalesce(e.source_volume_creation_time, $properties.source_volume_creation_time) "
                        "MERGE (c)-[:HAS_EVENT]->(e)",
                        {"case_id": case_id, "event_uid": event.event.uid,
                         "properties": properties},
                    )
                    accepted += 1
                    valid_count += 1
                records_without_events += valid_count == 0
                if valid_count == 0 and provenance is not None and len(rejected) < 20:
                    rejected.append({"file": filename, "record": record_number,
                                     "reason": "Unsupported event type, security rejection, validation failure or excluded port"})
        if case_created:
            from src.graph.process_lineage import persist_lineage
            lineage_receipt = persist_lineage(graph, case_id)
            if provenance is not None:
                provenance["process_lineage"] = lineage_receipt
            from src.agents.case_analysis import decode_record
            from src.ingestion.indexing.case_evidence import CaseEvidenceIndex
            evidence = [decode_record(row["e"]) for row in graph.execute(
                "MATCH (:Case {uid:$case_id})-[:HAS_EVENT]->(e:Event) RETURN e", {"case_id": case_id})]
            vector_receipt = CaseEvidenceIndex().index(case_id, evidence)
            from src.agents.case_analytics import write_case_analytics
            analytics_receipt = write_case_analytics(case_id, evidence)
            from src.ingestion.broker.case_stream import publish_normalized_case
            stream_receipt=publish_normalized_case(case_id,evidence)
            graph.execute("MATCH (c:Case {uid:$case_id}) SET c.vector_receipt_json=$receipt",
                          {"case_id": case_id, "receipt": json.dumps(vector_receipt)})
            if provenance is not None:
                provenance["vector_index"] = vector_receipt
                provenance["analytics"] = analytics_receipt
                provenance['normalized_stream']=stream_receipt
        if provenance is not None and case_created:
            provenance["processing"] = {"selected_records": extracted, "normalized_events": accepted,
                                        "normalization_contract": "local-xml-context-v1" if provenance.get('source')=='local_windows' else "uploaded-context-v2",
                                        "timestamp_policy": "Source times only; MFT modified-time alias uses standard_information_modified when no native event time exists",
                                        "record_errors_sample": rejected,
                                        "selected_records_without_normalized_events": records_without_events,
                                        "coverage": "Only supported valid records are normalized; unsupported and filtered records may be excluded"}
            if not append_only:
                graph.execute("MATCH (c:Case {uid: $case_id}) SET c.ingestion_provenance_json = $provenance",
                              {"case_id": case_id, "provenance": json.dumps(provenance, sort_keys=True)})
            else:
                graph.execute('MATCH (c:Case {uid:$case_id}) MERGE (r:AcquisitionRun {uid:$uid}) '
                    'SET r.provenance_json=$provenance MERGE (c)-[:HAS_ACQUISITION]->(r)',
                    {'case_id':case_id,'uid':provenance['id'],'provenance':json.dumps(provenance,sort_keys=True)})
    finally:
        graph.close()
    if not accepted and not append_only:
        detail = f" First issue: {rejected[0]['file']} record {rejected[0]['record']}: {rejected[0]['reason']}" if rejected else ""
        raise RuntimeError("No supported log events were found in the selected interval." + detail)
    result = {"case_id": case_id, "extracted": extracted, "accepted": accepted}
    if provenance is not None:
        result.update({"excluded_records": records_without_events, "record_errors_sample": rejected})
    return result


def investigate_case(case_id):
    token = (ROOT / "data" / "private" / "verification_token").read_text(encoding="utf-8").strip()
    with requests.Session() as session:
        session.trust_env = False
        response = session.post("http://127.0.0.1:8300/api/investigations",
                                headers={"Authorization": f"Bearer {token}"},
                                # Background job; browser already received HTTP 202.
                                # Large local-model cases must not acquire a false
                                # failure merely because inference exceeds 15 minutes.
                                json={"case_id": case_id}, timeout=(10, None))
    payload = response.json()
    if not response.ok:
        raise RuntimeError(payload.get("detail", "Investigation request failed"))
    return payload
