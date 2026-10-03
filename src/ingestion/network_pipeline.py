"""Network evidence entry points for sensor JSON and preserved PCAP captures."""

from io import BytesIO
import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import uuid

from src.graph.cypher_builder import CypherBuilder
from src.ingestion.normalization.network_normalizer import (
    normalize_pcap_stream, normalize_suricata_event, normalize_zeek_conn,
)
from src.ingestion.normalization.time_normalizer import TimeNormalizer
from src.ingestion.preservation.sha256_hasher import compute_sha256_bytes
from src.ingestion.security_gate.pipeline import run_security_gate
from src.schemas.ocsf_events import GenericEvent, NetworkActivity
from src.schemas.entity_resolver import CanonicalEntityResolver, DHCPLease
from src.schemas.uid_generator import generate_deterministic_uid

log = logging.getLogger(__name__)


def ingest_syslog_message(
    raw_bytes: bytes, *, sender_ip: str, sender_port: int | None,
    case_id: str, resolver: Any, vct_chain: Any, quickwit_client: Any,
    event_producer: Any,
) -> GenericEvent:
    """Preserve a device-forwarded syslog record and publish an OCSF event.

    Vendor-specific message fields remain intact in ``raw_data`` for later
    parsing; the transport sender is recorded separately as collection source.
    """
    trace_id = uuid.uuid4().hex
    _preserve(raw_bytes, "syslog", trace_id, vct_chain, quickwit_client)
    if run_security_gate("text", raw_bytes).injection_blocked:
        raise ValueError("Syslog record blocked by Security Gate after preservation")
    received_at = datetime.now(timezone.utc)
    host_uid = resolver.resolve_ip(sender_ip, received_at) if resolver else None
    message = raw_bytes.decode("utf-8", errors="replace").rstrip("\r\n")
    source = {"sender_ip": sender_ip, "sender_port": sender_port, "transport": "syslog"}
    event = GenericEvent(
        trace_id=trace_id, activity_id=99, severity_id=1,
        time=received_at, raw_source_timestamp=received_at.isoformat(),
        clock_skew_unverified=True, uid=generate_deterministic_uid("syslog", {
            "sender_ip": sender_ip, "raw_sha256": compute_sha256_bytes(raw_bytes),
        }),
        case_id=case_id, canonical_host_id=host_uid,
        event_name="syslog", raw_data=json.dumps({"source": source, "message": message}, sort_keys=True),
    )
    event_producer.produce_event(event)
    return event


async def serve_syslog(
    *, host: str, port: int, protocol: str, case_id: str,
    resolver: Any, vct_chain: Any, quickwit_client: Any,
    event_producer: Any,
) -> None:
    """Listen for endpoint-forwarded UDP or newline-framed TCP syslog records."""
    from src.ingestion.preservation.quickwit_client import QuickwitClientError

    def receive(raw: bytes, address: tuple[str, int]) -> None:
        try:
            ingest_syslog_message(
                raw, sender_ip=address[0], sender_port=address[1], case_id=case_id,
                resolver=resolver, vct_chain=vct_chain,
                quickwit_client=quickwit_client, event_producer=event_producer,
            )
            flush = getattr(event_producer, "flush", None)
            if flush is not None:
                flush()
        except QuickwitClientError:
            log.exception("Syslog preservation failed for sender %s; record not published", address)
        except Exception:
            log.exception("Syslog record from %s was rejected", address)

    if protocol == "udp":
        class DatagramReceiver(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                receive(data, addr)

        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            DatagramReceiver, local_addr=(host, port), family=0,
        )
        log.info("Listening for UDP syslog on %s:%d", host, port)
        try:
            await asyncio.Future()
        finally:
            transport.close()
        return

    if protocol != "tcp":
        raise ValueError("Syslog protocol must be tcp or udp")

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        address = writer.get_extra_info("peername") or ("unknown", 0)
        try:
            while raw := await reader.readline():
                receive(raw, address)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, host, port)
    log.info("Listening for TCP syslog on %s:%d", host, port)
    async with server:
        await server.serve_forever()


def _preserve(raw_bytes: bytes, source_type: str, trace_id: str, vct_chain: Any, quickwit_client: Any) -> None:
    if quickwit_client is None:
        raise ValueError("Network evidence requires a Quickwit preservation client")
    digest = compute_sha256_bytes(raw_bytes)
    quickwit_client.commit_raw_evidence(
        uid=digest, trace_id=trace_id, sha256_digest=digest,
        raw_bytes=raw_bytes, source_type=source_type,
    )
    vct_chain.register(sha256_digest=digest, trace_id=trace_id, uid=digest)


def _publish_and_index(
    event: NetworkActivity, case_id: str, event_producer: Any,
    neo4j_client: Any,
) -> NetworkActivity:
    if not event.canonical_host_id:
        raise ValueError("Network source IP has no time-bounded canonical host mapping")
    event.case_id = case_id
    event_producer.produce_event(event)
    if neo4j_client is not None:
        query, params = CypherBuilder.build_network_activity(event.model_dump(mode="json"))
        neo4j_client.execute(query, params)
    return event


def ingest_network_json(
    raw_bytes: bytes, *, source_type: str, trace_id: str, case_id: str,
    resolver: Any, vct_chain: Any, quickwit_client: Any,
    event_producer: Any, neo4j_client: Any = None,
) -> NetworkActivity:
    """Preserve a Zeek/Suricata record before gate, normalization and Kafka."""
    if source_type not in ("zeek", "suricata"):
        raise ValueError(f"Unsupported network JSON source: {source_type}")
    _preserve(raw_bytes, source_type, trace_id, vct_chain, quickwit_client)
    if run_security_gate("text", raw_bytes).injection_blocked:
        raise ValueError("Network record blocked by Security Gate")
    raw = json.loads(raw_bytes)
    # Sensor clocks have no DC anchor unless independently verified.
    clock = TimeNormalizer(None)
    normalizer = normalize_zeek_conn if source_type == "zeek" else normalize_suricata_event
    event = normalizer(raw, clock, trace_id, resolver)
    return _publish_and_index(event, case_id, event_producer, neo4j_client)


def ingest_pcap_capture(
    raw_bytes: bytes, *, trace_id: str, case_id: str,
    resolver: Any, vct_chain: Any, quickwit_client: Any,
    event_producer: Any, neo4j_client: Any = None,
) -> list[NetworkActivity]:
    """Hash and preserve original capture bytes before packet dissection."""
    _preserve(raw_bytes, "pcap", trace_id, vct_chain, quickwit_client)
    events = []
    for event in normalize_pcap_stream(BytesIO(raw_bytes), TimeNormalizer(None), trace_id, resolver):
        events.append(_publish_and_index(event, case_id, event_producer, neo4j_client))
    return events


def ingest_network_files(
    *, zeek_jsonl: list[str] = (), suricata_eve: list[str] = (),
    pcap_files: list[str] = (), case_id: str = "UNASSIGNED_CONTINUOUS",
    resolver: Any, vct_chain: Any, quickwit_client: Any,
    event_producer: Any, neo4j_client: Any = None,
) -> tuple[list[NetworkActivity], list[str]]:
    """Read completed sensor files and ingest each raw record through one path.

    Zeek and EVE files are JSON Lines. A malformed or blocked line is reported
    and skipped after the original line has been preserved. Quickwit failures
    propagate and stop ingestion so unpreserved records cannot advance.
    """
    from src.ingestion.preservation.quickwit_client import QuickwitClientError

    events: list[NetworkActivity] = []
    errors: list[str] = []
    for source_type, paths in (("zeek", zeek_jsonl), ("suricata", suricata_eve)):
        for path in paths:
            with open(path, "rb") as stream:
                for line_number, raw_line in enumerate(stream, start=1):
                    if not raw_line.strip():
                        continue
                    try:
                        events.append(ingest_network_json(
                            raw_line, source_type=source_type, trace_id=uuid.uuid4().hex,
                            case_id=case_id, resolver=resolver, vct_chain=vct_chain,
                            quickwit_client=quickwit_client, event_producer=event_producer,
                            neo4j_client=neo4j_client,
                        ))
                    except QuickwitClientError:
                        raise
                    except Exception as exc:
                        message = f"{path}:{line_number}: {exc}"
                        errors.append(message)
                        log.warning("Network record skipped: %s", message)

    for path in pcap_files:
        raw_bytes = Path(path).read_bytes()
        try:
            events.extend(ingest_pcap_capture(
                raw_bytes, trace_id=uuid.uuid4().hex, case_id=case_id,
                resolver=resolver, vct_chain=vct_chain,
                quickwit_client=quickwit_client, event_producer=event_producer,
                neo4j_client=neo4j_client,
            ))
        except QuickwitClientError:
            raise
        except Exception as exc:
            message = f"{path}: {exc}"
            errors.append(message)
            log.warning("PCAP capture skipped: %s", message)
    return events, errors


def tail_network_files_once(
    *, zeek_jsonl: list[str] = (), suricata_eve: list[str] = (),
    case_id: str = "UNASSIGNED_CONTINUOUS", resolver: Any, vct_chain: Any,
    quickwit_client: Any, event_producer: Any, neo4j_client: Any = None,
    offset_file: str = "data/ingestion_state/network_offsets.json",
) -> tuple[list[NetworkActivity], list[str]]:
    """Ingest complete appended JSONL records and checkpoint each source offset.

    Incomplete trailing lines remain uncommitted for the next poll. Checkpoints
    are written only after preservation and processing, so a crash may replay a
    record but cannot silently skip one.
    """
    from src.ingestion.preservation.quickwit_client import QuickwitClientError

    checkpoint = Path(offset_file)
    try:
        state = json.loads(checkpoint.read_text(encoding="utf-8")) if checkpoint.exists() else {}
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read network offset checkpoint {checkpoint}: {exc}") from exc
    events: list[NetworkActivity] = []
    errors: list[str] = []

    def save() -> None:
        checkpoint.parent.mkdir(parents=True, exist_ok=True)
        temporary = checkpoint.with_name(checkpoint.name + ".tmp")
        temporary.write_text(json.dumps(state, indent=2), encoding="utf-8")
        os.replace(temporary, checkpoint)

    for source_type, paths in (("zeek", zeek_jsonl), ("suricata", suricata_eve)):
        for raw_path in paths:
            path = Path(raw_path).resolve()
            key = str(path)
            try:
                stat = path.stat()
                identity = f"{stat.st_dev}:{stat.st_ino}"
                entry = state.get(key, {})
                offset = int(entry.get("offset", 0))
                if entry.get("identity") != identity or stat.st_size < offset:
                    offset = 0
                with path.open("rb") as stream:
                    stream.seek(offset)
                    while True:
                        start = stream.tell()
                        raw_line = stream.readline()
                        if not raw_line or not raw_line.endswith(b"\n"):
                            break
                        next_offset = stream.tell()
                        if raw_line.strip():
                            try:
                                events.append(ingest_network_json(
                                    raw_line, source_type=source_type, trace_id=uuid.uuid4().hex,
                                    case_id=case_id, resolver=resolver, vct_chain=vct_chain,
                                    quickwit_client=quickwit_client, event_producer=event_producer,
                                    neo4j_client=neo4j_client,
                                ))
                            except QuickwitClientError:
                                raise
                            except Exception as exc:
                                message = f"{path}:{start}: {exc}"
                                errors.append(message)
                                log.warning("Network record skipped: %s", message)
                        state[key] = {"identity": identity, "offset": next_offset}
                        save()
            except QuickwitClientError:
                raise
            except OSError as exc:
                message = f"{path}: {exc}"
                errors.append(message)
                log.warning("Network file unavailable: %s", message)
    return events, errors


def load_dhcp_leases(path: str | None) -> CanonicalEntityResolver:
    """Load time-bounded IP to host mappings from a JSON array."""
    resolver = CanonicalEntityResolver()
    if not path:
        return resolver
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    leases = payload.get("leases", []) if isinstance(payload, dict) else payload
    if not isinstance(leases, list):
        raise ValueError("DHCP lease file must contain a JSON array or {\"leases\": [...]}")

    def parse_time(value: str | None) -> datetime | None:
        if value is None:
            return None
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

    for item in leases:
        resolver.register_dhcp_lease(DHCPLease(
            ip=item["ip"], canonical_host_uid=item["canonical_host_uid"],
            valid_from=parse_time(item["valid_from"]),
            valid_to=parse_time(item.get("valid_to")),
        ))
    return resolver
