import json
from src.schemas.ocsf_events import GenericEvent
from src.schemas.uid_generator import generate_deterministic_uid
from src.ingestion.normalization.time_normalizer import TimeNormalizer

def normalize_heuristic(raw_event: dict, time_normalizer: TimeNormalizer, trace_id: str) -> GenericEvent:
    """
    Fallback normalizer that heuristically extracts timestamps and event names
    from unknown log sources. Used when a specific normalizer is unavailable
    or the retrieval of a specific schema mapping is not possible.
    """
    # Heuristically find a timestamp
    time_str = ""
    for field in ["TimeCreated", "eventTime", "timestamp", "date", "time", "log_time", "LastRecordChange"]:
        if field in raw_event and raw_event[field]:
            time_str = str(raw_event[field])
            break
            
    if not time_str:
        from datetime import datetime, timezone
        time_str = datetime.now(timezone.utc).isoformat()
            
    utc_time, skew_offset, skew_unverified = time_normalizer.normalize(time_str)
    
    # Heuristically find an event name
    event_name = "UnknownEvent"
    for field in ["eventName", "Message", "Action", "type", "event_type"]:
        if field in raw_event and raw_event[field]:
            event_name = str(raw_event[field])[:100]
            break
            
    # Heuristically find a host/provider
    provider = "UnknownProvider"
    for field in ["ProviderName", "host", "hostname", "source", "eventSource"]:
        if field in raw_event and raw_event[field]:
            provider = str(raw_event[field])
            break
            
    entity_uid = generate_deterministic_uid("generic", {
        "provider": provider,
        "event_name": event_name,
        "timestamp": utc_time.isoformat()
    })
    
    raw_data_str = json.dumps(raw_event)
    
    return GenericEvent(
        trace_id=trace_id,
        activity_id=99,
        severity_id=1,
        time=utc_time,
        raw_source_timestamp=time_str or utc_time.isoformat(),
        clock_skew_offset_ms=skew_offset,
        clock_skew_unverified=skew_unverified,
        uid=entity_uid,
        event_name=event_name,
        raw_data=raw_data_str
    )
