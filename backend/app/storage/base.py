from __future__ import annotations

from typing import Any, Protocol

# Collections live under a shared workspace (Firestore: workspaces/{workspace}/{collection}).
COLLECTIONS = (
    "scenarios",
    "runs",
    "agents",
    "raw_events",
    "normalized_events",
    "alerts",
    "response_actions",
    "detection_rules",
    "response_policies",
    "evaluations",
    "reviews",
)


class Store(Protocol):
    backend: str
    workspace: str

    def put(self, collection: str, doc_id: str, data: dict[str, Any]) -> None: ...

    def put_many(self, collection: str, docs: list[tuple[str, dict[str, Any]]]) -> None: ...

    def get(self, collection: str, doc_id: str) -> dict[str, Any] | None: ...

    def list(self, collection: str, run_id: str | None = None, limit: int | None = None) -> list[dict[str, Any]]: ...

    def delete_run_docs(self, collection: str, run_id: str) -> int: ...


def check_collection(collection: str) -> None:
    if collection not in COLLECTIONS:
        raise ValueError(f"Unknown collection: {collection}")
