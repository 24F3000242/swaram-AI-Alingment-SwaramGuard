"""Local HTTP servers shared only by the optional framework integration tests."""
from contextlib import contextmanager
import socket
import threading
import time

import httpx
import pytest


@contextmanager
def serve(application, *, lifespan="on"):
    import uvicorn

    # Keep the free port reserved until uvicorn takes ownership: no bind race.
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(
        application, host="127.0.0.1", port=sock.getsockname()[1],
        lifespan=lifespan, log_level="critical", timeout_graceful_shutdown=3,
        ws="none",
    ))
    errors = []

    def run():
        try:
            server.run(sockets=[sock])
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if errors or not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError(f"Local server failed to start: {errors}")
            time.sleep(0.01)
        yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        assert not thread.is_alive(), "Local server failed to shut down"
        assert not errors, errors


@pytest.fixture
def real_backend(tmp_path, monkeypatch):
    from app import config

    # Do not load developer .env files or call optional remote services.
    monkeypatch.setattr(config, "_load_dotenv", lambda: None)
    for key, value in {
        "GEMINI_QUOTA_FILE": "off", "SWARMGUARD_API_KEYS": "",
        "SWARMGUARD_LLM_PROVIDER": "deterministic",
        "SWARMGUARD_INJECTION_SCORER_URL": "",
        "LANGSMITH_TRACING": "false", "LANGCHAIN_TRACING_V2": "false",
        "LANGCHAIN_TRACING": "false", "LANGSMITH_API_KEY": "", "LANGCHAIN_API_KEY": "",
    }.items():
        monkeypatch.setenv(key, value)

    from app.main import app, get_pipeline
    from app.services import ingest
    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    store = SQLiteStore(str(tmp_path / "integration.sqlite"))
    pipeline = Pipeline(store)
    pipeline.seed_defaults()
    overrides = dict(app.dependency_overrides)
    existing_sessions = set(ingest.SESSIONS)
    app.dependency_overrides[get_pipeline] = lambda: pipeline
    try:
        # The production lifespan directly opens the configured store and starts
        # deployment services. Exercise real routes/HTTP with our temporary store,
        # without that unrelated startup machinery (same isolation as fake tests).
        with serve(app, lifespan="off") as url:
            with httpx.Client(base_url=url, timeout=10, trust_env=False) as client:
                yield url, client
    finally:
        for run_id in set(ingest.SESSIONS) - existing_sessions:
            ingest.SESSIONS.pop(run_id).stream.close()
        app.dependency_overrides.clear()
        app.dependency_overrides.update(overrides)
        store._conn.close()


def api(client, method, path, **kwargs):
    response = client.request(method, path, **kwargs)
    response.raise_for_status()
    return response.json()


def events(client, run_id):
    return api(client, "GET", f"/api/runs/{run_id}/raw-events")


def pause(client, run_id):
    api(client, "POST", f"/api/live/{run_id}/agents/a1", json={"action": "pause", "note": "integration test"})
    assert "a1" in api(client, "GET", f"/api/ingest/{run_id}/control")["paused"]
