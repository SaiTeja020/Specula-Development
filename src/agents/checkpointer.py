"""Durable LangGraph checkpoints for a single host using standard-library SQLite.

The database and its WAL must live on persistent local storage. This is not a
multi-host database or a substitute for coordinating concurrent runs of a case.
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
from threading import Event, RLock, Thread
import time
from uuid import uuid4

from langgraph.checkpoint.base import (
    BaseCheckpointSaver, CheckpointTuple, WRITES_IDX_MAP,
    get_checkpoint_id, get_checkpoint_metadata,
)


class CheckpointBusyError(RuntimeError):
    """Another API process currently owns this case execution lease."""


class SQLiteCheckpointSaver(BaseCheckpointSaver):
    """Store full typed snapshots and task writes transactionally, without pickle."""

    def __init__(self, path):
        super().__init__()
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = RLock()
        self._active_leases = {}
        self._conn = sqlite3.connect(
            str(self.path), timeout=30, check_same_thread=False, isolation_level=None,
        )
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    thread_id TEXT NOT NULL, namespace TEXT NOT NULL,
                    checkpoint_id TEXT NOT NULL, parent_id TEXT,
                    checkpoint_type TEXT NOT NULL, checkpoint BLOB NOT NULL,
                    metadata_type TEXT NOT NULL, metadata BLOB NOT NULL,
                    PRIMARY KEY(thread_id, namespace, checkpoint_id)
                );
                CREATE TABLE IF NOT EXISTS checkpoint_writes (
                    thread_id TEXT NOT NULL, namespace TEXT NOT NULL,
                    checkpoint_id TEXT NOT NULL, task_id TEXT NOT NULL,
                    write_index INTEGER NOT NULL, channel TEXT NOT NULL,
                    value_type TEXT NOT NULL, value BLOB NOT NULL,
                    task_path TEXT NOT NULL,
                    PRIMARY KEY(thread_id, namespace, checkpoint_id, task_id, write_index)
                );
                CREATE TABLE IF NOT EXISTS case_execution_leases (
                    case_id TEXT PRIMARY KEY, owner TEXT NOT NULL,
                    expires_at REAL NOT NULL
                );
            """)
        except BaseException:
            self._conn.close()
            raise

    @contextmanager
    def _transaction(self, *, write=False):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield self._conn
                self._conn.commit()
            except BaseException:
                self._conn.rollback()
                raise

    @staticmethod
    def _config(thread, namespace, checkpoint_id):
        return {"configurable": {"thread_id": thread, "checkpoint_ns": namespace,
                                 "checkpoint_id": checkpoint_id}}

    def _tuple(self, conn, row):
        thread, namespace, checkpoint_id, parent, kind, checkpoint, mkind, metadata = row
        writes = conn.execute(
            "SELECT task_id, channel, value_type, value FROM checkpoint_writes "
            "WHERE thread_id=? AND namespace=? AND checkpoint_id=? "
            "ORDER BY task_path, task_id, write_index",
            (thread, namespace, checkpoint_id),
        ).fetchall()
        return CheckpointTuple(
            config=self._config(thread, namespace, checkpoint_id),
            checkpoint=self.serde.loads_typed((kind, checkpoint)),
            metadata=self.serde.loads_typed((mkind, metadata)),
            parent_config=self._config(thread, namespace, parent) if parent else None,
            pending_writes=[(task, channel, self.serde.loads_typed((typ, value)))
                            for task, channel, typ, value in writes],
        )

    def get_tuple(self, config):
        cfg = config["configurable"]
        args = [cfg["thread_id"], cfg.get("checkpoint_ns", "")]
        query = "SELECT * FROM checkpoints WHERE thread_id=? AND namespace=?"
        if checkpoint_id := get_checkpoint_id(config):
            query += " AND checkpoint_id=?"
            args.append(checkpoint_id)
        query += " ORDER BY checkpoint_id DESC LIMIT 1"
        with self._transaction() as conn:
            row = conn.execute(query, args).fetchone()
            return self._tuple(conn, row) if row else None

    def list(self, config, *, filter=None, before=None, limit=None):
        conditions, args = [], []
        if config:
            cfg = config["configurable"]
            conditions.append("thread_id=?")
            args.append(cfg["thread_id"])
            if "checkpoint_ns" in cfg:
                conditions.append("namespace=?")
                args.append(cfg["checkpoint_ns"])
            if checkpoint_id := get_checkpoint_id(config):
                conditions.append("checkpoint_id=?")
                args.append(checkpoint_id)
        if before and (checkpoint_id := get_checkpoint_id(before)):
            conditions.append("checkpoint_id<?")
            args.append(checkpoint_id)
        query = "SELECT * FROM checkpoints"
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY checkpoint_id DESC, thread_id, namespace"
        found = []
        with self._transaction() as conn:
            for row in conn.execute(query, args).fetchall():
                if limit is not None and len(found) >= limit:
                    break
                metadata = self.serde.loads_typed((row[6], row[7]))
                if filter and not all(metadata.get(k) == v for k, v in filter.items()):
                    continue
                found.append(self._tuple(conn, row))
        yield from found

    def put(self, config, checkpoint, metadata, new_versions):
        cfg = config["configurable"]
        thread, namespace = cfg["thread_id"], cfg.get("checkpoint_ns", "")
        kind, data = self.serde.dumps_typed(checkpoint)
        mkind, mdata = self.serde.dumps_typed(get_checkpoint_metadata(config, metadata))
        with self._transaction(write=True) as conn:
            self._assert_execution_owner(conn, thread)
            conn.execute(
                "INSERT INTO checkpoints VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(thread_id,namespace,checkpoint_id) DO UPDATE SET "
                "parent_id=excluded.parent_id,checkpoint_type=excluded.checkpoint_type,"
                "checkpoint=excluded.checkpoint,metadata_type=excluded.metadata_type,"
                "metadata=excluded.metadata",
                (thread, namespace, checkpoint["id"], get_checkpoint_id(config),
                 kind, data, mkind, mdata),
            )
        return self._config(thread, namespace, checkpoint["id"])

    def put_writes(self, config, writes, task_id, task_path=""):
        cfg = config["configurable"]
        rows = []
        for idx, (channel, value) in enumerate(writes):
            kind, data = self.serde.dumps_typed(value)
            rows.append((cfg["thread_id"], cfg.get("checkpoint_ns", ""),
                         cfg["checkpoint_id"], task_id, WRITES_IDX_MAP.get(channel, idx),
                         channel, kind, data, task_path))
        with self._transaction(write=True) as conn:
            self._assert_execution_owner(conn, cfg["thread_id"])
            for row in rows:
                conn.execute(
                    "INSERT INTO checkpoint_writes VALUES(?,?,?,?,?,?,?,?,?) "
                    "ON CONFLICT(thread_id,namespace,checkpoint_id,task_id,write_index) "
                    "DO UPDATE SET channel=excluded.channel,value_type=excluded.value_type,"
                    "value=excluded.value,task_path=excluded.task_path "
                    "WHERE excluded.write_index<0", row,
                )

    async def aget_tuple(self, config):
        return await asyncio.to_thread(self.get_tuple, config)

    async def alist(self, config, *, filter=None, before=None, limit=None):
        values = await asyncio.to_thread(
            lambda: list(self.list(config, filter=filter, before=before, limit=limit)))
        for value in values:
            yield value

    async def aput(self, config, checkpoint, metadata, new_versions):
        return await asyncio.to_thread(self.put, config, checkpoint, metadata, new_versions)

    async def aput_writes(self, config, writes, task_id, task_path=""):
        await asyncio.to_thread(self.put_writes, config, writes, task_id, task_path)

    def close(self):
        with self._lock:
            self._conn.close()

    def _assert_execution_owner(self, conn, case_id):
        """Fence an expired executor within the same transaction as its writes."""
        owner = self._active_leases.get(case_id)
        if owner is None:
            return  # Direct saver contract operations are allowed in isolated tests.
        row = conn.execute(
            "SELECT owner, expires_at FROM case_execution_leases WHERE case_id=?",
            (case_id,),
        ).fetchone()
        if row is None or row[0] != owner or row[1] <= time.time():
            raise CheckpointBusyError("Investigation execution lease was lost")

    @contextmanager
    def case_execution_lock(self, case_id):
        """Acquire a shared single-host case lease; renew during long model calls.

        A crashed process releases ownership after 60 seconds. Clock agreement
        and timely SQLite access on this single host are required for leases.
        """
        owner = uuid4().hex
        now = time.time()
        with self._transaction(write=True) as conn:
            if case_id in self._active_leases:
                raise CheckpointBusyError("Investigation is already executing in this process")
            cursor = conn.execute(
                "INSERT INTO case_execution_leases VALUES(?,?,?) "
                "ON CONFLICT(case_id) DO UPDATE SET owner=excluded.owner,"
                "expires_at=excluded.expires_at WHERE case_execution_leases.expires_at<=?",
                (case_id, owner, now + 60, now),
            )
            if cursor.rowcount != 1:
                raise CheckpointBusyError("Investigation is already executing")
            self._active_leases[case_id] = owner
        stop, lost = Event(), Event()

        def heartbeat():
            # Independent connection avoids holding the saver lock during busy waits.
            try:
                conn = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
            except sqlite3.Error:
                lost.set()
                return
            last_renewed = now
            delay = 10
            try:
                while not stop.wait(delay):
                    try:
                        renewed_at = time.time()
                        cursor = conn.execute(
                            "UPDATE case_execution_leases SET expires_at=? "
                            "WHERE case_id=? AND owner=? AND expires_at>?",
                            (renewed_at + 60, case_id, owner, renewed_at),
                        )
                        if cursor.rowcount != 1:
                            lost.set()
                            return
                        last_renewed, delay = renewed_at, 10
                    except sqlite3.Error:
                        if time.time() - last_renewed >= 50:
                            lost.set()
                            return
                        delay = 1
            finally:
                conn.close()

        worker = Thread(target=heartbeat, name="specula-case-lease", daemon=True)
        worker.start()
        completed = False
        try:
            yield
            completed = True
        finally:
            stop.set()
            worker.join(timeout=6)
            with self._transaction(write=True) as conn:
                conn.execute("DELETE FROM case_execution_leases WHERE case_id=? AND owner=?",
                             (case_id, owner))
                if self._active_leases.get(case_id) == owner:
                    del self._active_leases[case_id]
            if completed and (lost.is_set() or worker.is_alive()):
                raise CheckpointBusyError("Investigation execution lease was lost")


@contextmanager
def durable_case_lock(saver, case_id):
    """Shared lock for SQLite; memory is allowed only for isolated test runtimes."""
    if isinstance(saver, SQLiteCheckpointSaver):
        with saver.case_execution_lock(case_id):
            yield
    else:
        from langgraph.checkpoint.memory import InMemorySaver
        if not isinstance(saver, InMemorySaver):
            raise TypeError("Unsupported saver for case execution locking")
        yield


def build_persistent_checkpointer(path=None):
    """Default to durable SQLite; permit memory only by explicit test configuration."""
    backend = os.environ.get("SPECULA_CHECKPOINT_BACKEND", "sqlite").strip().lower()
    if backend == "memory":
        from langgraph.checkpoint.memory import InMemorySaver
        return InMemorySaver()
    if backend != "sqlite":
        raise ValueError("SPECULA_CHECKPOINT_BACKEND must be sqlite or memory")
    return SQLiteCheckpointSaver(
        path or os.environ.get("SPECULA_CHECKPOINT_PATH", "data/checkpoints/specula.sqlite3"))
