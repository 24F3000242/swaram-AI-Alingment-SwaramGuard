"""Firestore backend (server-side only, via the Firebase Admin SDK).

Credentials never reach the browser; clients talk to FastAPI, and `firestore.rules`
denies all direct client reads/writes.
"""
from __future__ import annotations

from typing import Any

from app.storage.base import check_collection

_BATCH = 400  # Firestore allows 500 writes per batch


class FirestoreStore:
    backend = "firestore"

    def __init__(self, workspace: str, credentials_path: str | None, project_id: str | None):
        try:
            import firebase_admin
            from firebase_admin import credentials, firestore
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError("Install backend/requirements-firestore.txt to use Firestore") from exc

        if not firebase_admin._apps:
            cred = credentials.Certificate(credentials_path) if credentials_path else credentials.ApplicationDefault()
            options = {"projectId": project_id} if project_id else None
            firebase_admin.initialize_app(cred, options)
        self.workspace = workspace
        self.db = firestore.client()

    def _col(self, collection: str):
        check_collection(collection)
        return self.db.collection("workspaces").document(self.workspace).collection(collection)

    def put(self, collection: str, doc_id: str, data: dict[str, Any]) -> None:
        self._col(collection).document(doc_id).set(data)

    def put_many(self, collection: str, docs: list[tuple[str, dict[str, Any]]]) -> None:
        col = self._col(collection)
        for start in range(0, len(docs), _BATCH):
            batch = self.db.batch()
            for doc_id, data in docs[start : start + _BATCH]:
                batch.set(col.document(doc_id), data)
            batch.commit()

    def get(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        snap = self._col(collection).document(doc_id).get()
        return snap.to_dict() if snap.exists else None

    def list(self, collection: str, run_id: str | None = None, limit: int | None = None) -> list[dict[str, Any]]:
        from google.cloud.firestore_v1.base_query import FieldFilter

        query = self._col(collection)
        if run_id is not None:
            query = query.where(filter=FieldFilter("run_id", "==", run_id))
        if limit:
            query = query.limit(int(limit))
        return [snap.to_dict() for snap in query.stream()]

    def delete_run_docs(self, collection: str, run_id: str) -> int:
        from google.cloud.firestore_v1.base_query import FieldFilter

        snaps = list(self._col(collection).where(filter=FieldFilter("run_id", "==", run_id)).stream())
        for start in range(0, len(snaps), _BATCH):
            batch = self.db.batch()
            for snap in snaps[start : start + _BATCH]:
                batch.delete(snap.reference)
            batch.commit()
        return len(snaps)
