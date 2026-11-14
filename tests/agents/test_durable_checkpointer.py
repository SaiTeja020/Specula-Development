"""Executable restart and checkpoint contract checks; no model or cloud calls."""
import asyncio
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from typing import TypedDict

import pytest
from langchain_core.messages import AIMessage
from langgraph.checkpoint.base import empty_checkpoint
from langgraph.checkpoint.serde.types import ERROR, INTERRUPT
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from src.agents.checkpointer import (
    CheckpointBusyError, SQLiteCheckpointSaver, build_persistent_checkpointer,
    durable_case_lock,
)


class State(TypedDict):
    value: str
    decision: str


def approval(state):
    return {"decision": interrupt({"value": state["value"]})}


def graph(saver):
    return (StateGraph(State).add_node("approval", approval)
            .add_edge(START, "approval").add_edge("approval", END)
            .compile(checkpointer=saver))


def config(thread="case-a", namespace=""):
    return {"configurable": {"thread_id": thread, "checkpoint_ns": namespace}}


def save(saver, cfg, value, step):
    checkpoint = empty_checkpoint()
    checkpoint["channel_values"] = {"value": value, "messages": [AIMessage(content="stored")]}
    checkpoint["channel_versions"] = {"value": step + 1, "messages": 1}
    return saver.put(cfg, checkpoint, {"step": step, "source": "loop", "label": "test"},
                     {"value": step + 1})


def test_paused_graph_survives_close_and_reopen(tmp_path):
    path = tmp_path / "checkpoints.sqlite3"
    saver = SQLiteCheckpointSaver(path)
    first = graph(saver)
    first.invoke({"value": "persisted evidence"}, config())
    state = first.get_state(config())
    assert state.next == ("approval",)
    assert state.tasks[0].interrupts[0].value == {"value": "persisted evidence"}
    saver.close()
    reopened = SQLiteCheckpointSaver(path)
    try:
        recovered = graph(reopened)
        assert recovered.get_state(config()).next == ("approval",)
        result = recovered.invoke(Command(resume="approved"), config())
        assert result == {"value": "persisted evidence", "decision": "approved"}
        assert recovered.get_state(config()).next == ()
    finally:
        reopened.close()


def test_full_state_history_filters_namespaces_and_parents(tmp_path):
    saver = SQLiteCheckpointSaver(tmp_path / "state.sqlite3")
    try:
        initial = save(saver, config(), {"nested": [1, 2]}, 0)
        later = save(saver, initial, {"nested": [3]}, 1)
        save(saver, config(namespace="worker"), "other namespace", 0)
        save(saver, config(thread="case-b"), "other thread", 0)
        current = saver.get_tuple(config())
        assert current.config == later
        assert current.parent_config == initial
        assert current.checkpoint["channel_values"]["value"] == {"nested": [3]}
        assert isinstance(current.checkpoint["channel_values"]["messages"][0], AIMessage)
        assert saver.get_tuple(initial).checkpoint["channel_values"]["value"] == {"nested": [1, 2]}
        assert len(list(saver.list(config()))) == 2
        assert len(list(saver.list({"configurable": {"thread_id": "case-a"}}))) == 3
        assert [x.config for x in saver.list(config(), before=later)] == [initial]
        assert [x.config for x in saver.list(config(), filter={"step": 0}, limit=1)] == [initial]
        assert list(saver.list(config(), filter={"label": "absent"})) == []
        assert list(saver.list(None, limit=0)) == []
        assert len(list(saver.list(None))) == 4
    finally:
        saver.close()


def test_retry_writes_preserve_success_and_update_special_channels(tmp_path):
    path = tmp_path / "writes.sqlite3"
    saver = SQLiteCheckpointSaver(path)
    cfg = save(saver, config(), "state", 0)
    saver.put_writes(cfg, [("value", "original"), (ERROR, "old"), (INTERRUPT, "pause-1")], "task")
    saver.put_writes(cfg, [("value", "replacement"), (ERROR, "new"), (INTERRUPT, "pause-2")], "task")
    saver.put_writes(cfg, [("value", "independent")], "other-task")
    saver.close()
    reopened = SQLiteCheckpointSaver(path)
    try:
        writes = {(task, channel): value for task, channel, value in reopened.get_tuple(cfg).pending_writes}
        assert writes == {("task", "value"): "original", ("task", ERROR): "new",
                          ("task", INTERRUPT): "pause-2", ("other-task", "value"): "independent"}
    finally:
        reopened.close()


def test_multiple_connections_and_threads_do_not_lose_independent_cases(tmp_path):
    path = tmp_path / "concurrent.sqlite3"
    left, right = SQLiteCheckpointSaver(path), SQLiteCheckpointSaver(path)
    try:
        def write(index):
            saver = left if index % 2 else right
            return save(saver, config(thread=f"case-{index}"), index, 0)
        with ThreadPoolExecutor(max_workers=4) as pool:
            saved = list(pool.map(write, range(20)))
        assert len(list(left.list(None))) == 20
        assert [right.get_tuple(cfg).checkpoint["channel_values"]["value"] for cfg in saved] == list(range(20))
    finally:
        left.close()
        right.close()


def test_async_graph_recovers_interrupt(tmp_path):
    async def run():
        path = tmp_path / "async.sqlite3"
        first = SQLiteCheckpointSaver(path)
        await graph(first).ainvoke({"value": "async evidence"}, config())
        first.close()
        second = SQLiteCheckpointSaver(path)
        try:
            result = await graph(second).ainvoke(Command(resume="approved"), config())
            assert result["decision"] == "approved"
            assert len([item async for item in second.alist(config())]) >= 3
        finally:
            second.close()
    asyncio.run(run())


def test_factory_fails_closed_and_memory_requires_explicit_selection(tmp_path, monkeypatch):
    monkeypatch.delenv("SPECULA_CHECKPOINT_BACKEND", raising=False)
    monkeypatch.setenv("SPECULA_CHECKPOINT_PATH", str(tmp_path / "default.sqlite3"))
    saver = build_persistent_checkpointer()
    assert isinstance(saver, SQLiteCheckpointSaver)
    saver.close()
    with pytest.raises(sqlite3.OperationalError):
        build_persistent_checkpointer(tmp_path)
    monkeypatch.setenv("SPECULA_CHECKPOINT_BACKEND", "unsupported")
    with pytest.raises(ValueError):
        build_persistent_checkpointer()
    monkeypatch.setenv("SPECULA_CHECKPOINT_BACKEND", "memory")
    from langgraph.checkpoint.memory import InMemorySaver
    assert isinstance(build_persistent_checkpointer(), InMemorySaver)


def test_case_execution_lease_contends_across_connections_and_releases(tmp_path):
    path = tmp_path / "leases.sqlite3"
    first, second = SQLiteCheckpointSaver(path), SQLiteCheckpointSaver(path)
    try:
        with durable_case_lock(first, "case-a"):
            with pytest.raises(CheckpointBusyError):
                with durable_case_lock(second, "case-a"):
                    pytest.fail("A second executor must not enter")
            with durable_case_lock(second, "case-b"):
                assert second.get_tuple(config()) is None
        with durable_case_lock(second, "case-a"):
            with pytest.raises(CheckpointBusyError):
                with durable_case_lock(first, "case-a"):
                    pytest.fail("A second executor must not enter")
        with pytest.raises(ValueError):
            with durable_case_lock(first, "case-a"):
                raise ValueError("worker failed")
        with durable_case_lock(second, "case-a"):
            pass
    finally:
        first.close()
        second.close()


def test_expired_lease_takeover_and_release_preserves_new_owner(tmp_path):
    path = tmp_path / "expiry.sqlite3"
    first, second = SQLiteCheckpointSaver(path), SQLiteCheckpointSaver(path)
    try:
        with first._transaction(write=True) as conn:
            conn.execute("INSERT INTO case_execution_leases VALUES(?,?,?)", ("case-a", "dead", 0))
        with durable_case_lock(first, "case-a"):
            with first._transaction(write=True) as conn:
                conn.execute("UPDATE case_execution_leases SET expires_at=0 WHERE case_id=?", ("case-a",))
            # Simulate an expired crashed holder. Its finalizer must not clear takeover.
            replacement = durable_case_lock(second, "case-a")
            replacement.__enter__()
        with pytest.raises(CheckpointBusyError):
            with durable_case_lock(first, "case-a"):
                pytest.fail("Old owner release removed the replacement lease")
        replacement.__exit__(None, None, None)
        with durable_case_lock(first, "case-a"):
            pass
    finally:
        first.close()
        second.close()


def test_expired_executor_checkpoint_and_writes_are_fenced_after_takeover(tmp_path):
    path = tmp_path / "fenced.sqlite3"
    old, new = SQLiteCheckpointSaver(path), SQLiteCheckpointSaver(path)
    try:
        with durable_case_lock(old, "case-a"):
            initial = save(old, config(), "initial", 0)
            with old._transaction(write=True) as conn:
                conn.execute("UPDATE case_execution_leases SET expires_at=0 WHERE case_id=?", ("case-a",))
            # Expiry alone fences an old worker, even before a replacement acquires.
            with pytest.raises(CheckpointBusyError):
                save(old, initial, "expired writer", 1)
            with durable_case_lock(new, "case-a"):
                winner = save(new, initial, "replacement evidence", 1)
                new.put_writes(winner, [("value", "replacement pending")], "winner")
                with pytest.raises(CheckpointBusyError):
                    save(old, winner, "stale checkpoint", 2)
                with pytest.raises(CheckpointBusyError):
                    old.put_writes(winner, [("value", "stale pending")], "stale")
                restored = new.get_tuple(config())
                assert restored.config == winner
                assert restored.checkpoint["channel_values"]["value"] == "replacement evidence"
                assert restored.pending_writes == [("winner", "value", "replacement pending")]
        assert len(list(new.list(config()))) == 2
    finally:
        old.close()
        new.close()
