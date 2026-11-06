"""Local development fallback: one SQLite table holding JSON documents."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from app.storage.base import check_collection
from app.timeutil import now_iso


class SQLiteStore:
    backend = "sqlite"

    def __init__(self, path: str, workspace: str = "default"):
        self.workspace = workspace
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        with self._lock:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS docs (
                    workspace TEXT NOT NULL,
                    collection TEXT NOT NULL,
                    doc_id TEXT NOT NULL,
                    run_id TEXT,
                    updated_at TEXT NOT NULL,
                    data TEXT NOT NULL,
                    PRIMARY KEY (workspace, collection, doc_id)
                )"""
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS docs_run ON docs (workspace, collection, run_id)")
            self._conn.commit()

    def put(self, collection: str, doc_id: str, data: dict[str, Any]) -> None:
        self.put_many(collection, [(doc_id, data)])

    def put_many(self, collection: str, docs: list[tuple[str, dict[str, Any]]]) -> None:
        check_collection(collection)
        ts = now_iso()
        rows = [(self.workspace, collection, doc_id, data.get("run_id"), ts, json.dumps(data)) for doc_id, data in docs]
        with self._lock:
            self._conn.executemany(
                """INSERT INTO docs (workspace, collection, doc_id, run_id, updated_at, data)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT (workspace, collection, doc_id)
                   DO UPDATE SET run_id = excluded.run_id, updated_at = excluded.updated_at, data = excluded.data""",
                rows,
            )
            self._conn.commit()

    def get(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        check_collection(collection)
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM docs WHERE workspace = ? AND collection = ? AND doc_id = ?",
                (self.workspace, collection, doc_id),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, collection: str, run_id: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        check_collection(collection)
        sql = "SELECT data FROM docs WHERE workspace = ? AND collection = ?"
        params: list[Any] = [self.workspace, collection]
        if run_id is not None:
            sql += " AND run_id = ?"
            params.append(run_id)
        sql += " ORDER BY rowid"
        if limit:
            sql += " LIMIT ?"
            params.append(int(limit))
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [json.loads(r[0]) for r in rows]

    def delete_run_docs(self, collection: str, run_id: str) -> int:
        check_collection(collection)
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM docs WHERE workspace = ? AND collection = ? AND run_id = ?",
                (self.workspace, collection, run_id),
            )
            self._conn.commit()
        return cur.rowcount
