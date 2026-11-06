"""Shared persistence. Firestore when credentials are configured, SQLite otherwise."""
from __future__ import annotations

import logging
from functools import lru_cache

from app.config import get_settings
from app.storage.base import COLLECTIONS, Store
from app.storage.sqlite_store import SQLiteStore

log = logging.getLogger(__name__)

__all__ = ["COLLECTIONS", "Store", "SQLiteStore", "build_store", "get_store"]


def build_store() -> Store:
    s = get_settings()
    choice = s.storage
    if choice == "auto":
        choice = "firestore" if s.firebase_credentials else "sqlite"
    if choice == "firestore":
        from app.storage.firestore_store import FirestoreStore

        return FirestoreStore(workspace=s.workspace, credentials_path=s.firebase_credentials, project_id=s.firebase_project_id)
    if choice == "memory":
        return SQLiteStore(":memory:", workspace=s.workspace)
    return SQLiteStore(s.sqlite_path, workspace=s.workspace)


@lru_cache(maxsize=1)
def get_store() -> Store:
    store = build_store()
    log.info("SwarmGuard storage backend: %s (workspace=%s)", store.backend, store.workspace)
    return store
