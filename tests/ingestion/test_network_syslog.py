import asyncio
import socket

import pytest

from src.ingestion.network_pipeline import serve_syslog
from src.ingestion.preservation.vct_atomic_chain import VCTAtomicChain


class Quickwit:
    def __init__(self):
        self.records = []

    def commit_raw_evidence(self, **kwargs):
        self.records.append(kwargs)


class Producer:
    def __init__(self):
        self.events = []

    def produce_event(self, event):
        self.events.append(event)


def _free_port(protocol):
    sock_type = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, sock_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_live_syslog_listener_preserves_and_publishes_endpoint_record(protocol):
    async def exercise():
        port = _free_port(protocol)
        quickwit, producer, chain = Quickwit(), Producer(), VCTAtomicChain()
        task = asyncio.create_task(serve_syslog(
            host="127.0.0.1", port=port, protocol=protocol,
            case_id="case-syslog", resolver=None, vct_chain=chain,
            quickwit_client=quickwit, event_producer=producer,
        ))
        try:
            await asyncio.sleep(0.05)
            raw = b"<134>1 2026-10-03T12:00:00Z edge-fw auth - - - blocked outbound connection\n"
            if protocol == "udp":
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                    sender.sendto(raw, ("127.0.0.1", port))
            else:
                _, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.write(raw)
                await writer.drain()
                writer.close()
                await writer.wait_closed()

            for _ in range(30):
                if producer.events:
                    break
                await asyncio.sleep(0.02)
            assert len(quickwit.records) == len(producer.events) == 1
            assert quickwit.records[0]["raw_bytes"] == raw
            event = producer.events[0]
            assert event.case_id == "case-syslog"
            assert event.event_name == "syslog"
            assert '"sender_ip": "127.0.0.1"' in event.raw_data
            assert "blocked outbound connection" in event.raw_data
            assert chain.verify_chain()
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    asyncio.run(exercise())
