"""Unit tests for Member 1: Google Gemini API Adapter.

All tests are 100% mocked — zero external API calls are made and zero credits consumed.
Verifies:
1. Missing GEMINI_API_KEY handling and configuration defaults.
2. Configurable model selection via environment and arguments.
3. Successful message composition and general response generation.
4. Graceful fallbacks on rate limits (429), server errors (500), timeouts, and empty responses.
5. Spending cap (max_calls) enforcement.
6. Safe connection verification without leaking secrets.
7. Adapter factory integration and full simulation compatibility.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from google.genai import errors

from app.adapters import available_adapters, get_adapter
from app.adapters.base import TEMPLATES, DeterministicAdapter
from app.adapters.gemini_adapter import GeminiAdapter, mask_secret, reset_quota_tracker
from app.modules.simulator.engine import run_simulation
from app.schemas import ScenarioConfig


@pytest.fixture(autouse=True)
def clean_quota():
    reset_quota_tracker()
    yield
    reset_quota_tracker()



def test_mask_secret():
    """Verify secret masking never exposes full keys."""
    assert mask_secret(None) == "<unset>"
    assert mask_secret("") == "<unset>"
    assert mask_secret("short") == "***"
    assert mask_secret("12345678") == "***"
    assert mask_secret("AIzaSyD1234567890abcdef") == "AIza...cdef"


def test_gemini_adapter_missing_api_key(monkeypatch):
    """Instantiating without key or environment variable raises clear ValueError."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY is not set"):
        GeminiAdapter()


def test_gemini_adapter_model_configuration(monkeypatch):
    """Model selection respects explicit argument, then environment, then default."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-123456789")

    # 1. Default model
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    adapter1 = GeminiAdapter()
    assert adapter1.model == "gemini-3.5-flash-lite"

    # 2. Configured via environment
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")
    adapter2 = GeminiAdapter()
    assert adapter2.model == "gemini-3.8-flash"

    # 3. Explicit argument overrides environment
    adapter3 = GeminiAdapter(model="gemini-4-argon")
    assert adapter3.model == "gemini-4-argon"
    assert adapter3.calls_left == 20
    assert adapter3.timeout == 15.0


def test_gemini_compose_message_success_mocked():
    """compose_message generates text using client.models.generate_content."""
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "Sprint item SG-101 is ready for coding."
    mock_client.models.generate_content.return_value = mock_resp

    adapter = GeminiAdapter(
        api_key="test-key-mock",
        model="gemini-2.5-flash",
        max_calls=10,
        client=mock_client,
    )

    result = adapter.compose_message("planner", "coder", "assign_task", "SG-101")
    assert result == "Sprint item SG-101 is ready for coding."
    assert adapter.calls_left == 9

    # Verify generate_content parameters
    mock_client.models.generate_content.assert_called_once()
    call_kwargs = mock_client.models.generate_content.call_args.kwargs
    assert call_kwargs["model"] == "gemini-2.5-flash"
    assert "SG-101" in call_kwargs["contents"]
    assert "planner" in call_kwargs["contents"]
    assert "coder" in call_kwargs["contents"]


def test_gemini_generate_response_interface_mocked():
    """generate_response passes system instruction, temperature, and tokens."""
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "DECISION: tool/sql_query on data/customer_pii"
    mock_client.models.generate_content.return_value = mock_resp

    adapter = GeminiAdapter(api_key="test-key-mock", model="gemini-2.5-flash", client=mock_client)  # 3.x keeps default temperature

    resp = adapter.generate_response(
        prompt="Select the next tool to run given state.",
        system_instruction="You are an autonomous analyst agent.",
        temperature=0.3,
        max_tokens=60,
    )

    assert resp == "DECISION: tool/sql_query on data/customer_pii"
    config = mock_client.models.generate_content.call_args.kwargs["config"]
    assert config.system_instruction == "You are an autonomous analyst agent."
    assert config.temperature == 0.3
    # The adapter deliberately floors output tokens at 8192: thinking models share this budget and truncate below it.
    assert config.max_output_tokens == 8192


def test_gemini_fallback_on_rate_limit_429():
    """API rate limits (429) gracefully fall back to deterministic templates."""
    mock_client = MagicMock()
    api_err = errors.APIError(429, {"error": {"message": "Resource has been exhausted (quota exceeded)"}})
    mock_client.models.generate_content.side_effect = api_err

    adapter = GeminiAdapter(api_key="test-key-mock", client=mock_client)
    res = adapter.compose_message("planner", "coder", "assign_task", "SG-102")

    expected = TEMPLATES["assign_task"].format(role="coder", topic="SG-102")
    assert res == expected


def test_gemini_fallback_on_server_error_500():
    """API server errors (500) gracefully fall back to deterministic templates."""
    mock_client = MagicMock()
    api_err = errors.APIError(500, {"error": {"message": "Internal server error"}})
    mock_client.models.generate_content.side_effect = api_err

    adapter = GeminiAdapter(api_key="test-key-mock", client=mock_client)
    res = adapter.compose_message("analyst", "coder", "handoff", "extract-01")

    expected = TEMPLATES["handoff"].format(role="coder", topic="extract-01")
    assert res == expected


def test_gemini_fallback_on_timeout():
    """Network/client timeouts gracefully fall back to deterministic templates."""
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = TimeoutError("Request timed out after 15s")

    adapter = GeminiAdapter(api_key="test-key-mock", client=mock_client)
    res = adapter.compose_message("coder", "planner", "report", "SG-103")

    expected = TEMPLATES["report"].format(role="planner", topic="SG-103")
    assert res == expected


def test_gemini_fallback_on_empty_or_none_text():
    """Empty or None text response falls back to deterministic template."""
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = None  # E.g., safety filter / empty payload
    mock_client.models.generate_content.return_value = mock_resp

    adapter = GeminiAdapter(api_key="test-key-mock", client=mock_client)
    res = adapter.compose_message("researcher", "coder", "share_notes", "SG-104")

    expected = TEMPLATES["share_notes"].format(role="coder", topic="SG-104")
    assert res == expected


def test_gemini_spending_cap_enforced():
    """Once max_calls is exhausted, adapter falls back without calling API."""
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "LLM generated response"
    mock_client.models.generate_content.return_value = mock_resp

    adapter = GeminiAdapter(api_key="test-key-mock", max_calls=2, client=mock_client)

    # 1st call: uses LLM
    r1 = adapter.compose_message("planner", "coder", "assign_task", "SG-101")
    assert r1 == "LLM generated response"
    assert adapter.calls_left == 1

    # 2nd call: uses LLM
    r2 = adapter.compose_message("planner", "coder", "assign_task", "SG-102")
    assert r2 == "LLM generated response"
    assert adapter.calls_left == 0

    # 3rd call: spending cap hit -> deterministic fallback, API not called
    r3 = adapter.compose_message("planner", "coder", "assign_task", "SG-103")
    assert r3 == TEMPLATES["assign_task"].format(role="coder", topic="SG-103")
    assert mock_client.models.generate_content.call_count == 2


def test_gemini_check_connection_success_mocked():
    """check_connection reports connected status and safely masks key."""
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "PONG"
    mock_client.models.generate_content.return_value = mock_resp

    result = GeminiAdapter.check_connection(
        api_key="AIzaSyD9876543210zyxwvuts",
        model="gemini-2.5-flash",
        client=mock_client,
    )

    assert result["status"] == "connected"
    assert result["connected"] is True
    assert result["model"] == "gemini-2.5-flash"
    assert result["api_key_configured"] is True
    assert result["masked_key"] == "AIza...vuts"
    assert "9876543210" not in str(result)
    assert result["response"] == "PONG"


def test_gemini_check_connection_missing_key(monkeypatch):
    """check_connection cleanly reports missing key without crashing."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    result = GeminiAdapter.check_connection(api_key=None)

    assert result["status"] == "error"
    assert result["connected"] is False
    assert result["api_key_configured"] is False
    assert "GEMINI_API_KEY is not set" in result["error"]


def test_gemini_check_connection_failure_mocked():
    """check_connection masks key even in error strings."""
    mock_client = MagicMock()
    secret = "AIzaSyD_SUPER_SECRET_KEY"
    mock_client.models.generate_content.side_effect = errors.APIError(
        403, {"error": {"message": f"Invalid API key provided: {secret}"}}
    )

    result = GeminiAdapter.check_connection(
        api_key=secret,
        model="gemini-2.5-flash",
        client=mock_client,
    )

    assert result["status"] == "error"
    assert result["connected"] is False
    # Verify the secret was sanitized and masked in the error output
    assert secret not in result["error"]
    assert mask_secret(secret) in result["error"]


def test_adapters_registry_integration(monkeypatch):
    """available_adapters and get_adapter seamlessly support Gemini."""
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-valid")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.8-flash")

    adapters = available_adapters()
    gemini_entry = next((a for a in adapters if a["id"] == "gemini"), None)
    assert gemini_entry is not None
    assert gemini_entry["available"] is True
    assert "gemini-3.8-flash" in str(gemini_entry["label"])

    adapter = get_adapter("gemini")
    assert isinstance(adapter, GeminiAdapter)
    assert adapter.name == "gemini"
    assert adapter.model == "gemini-3.8-flash"


def test_simulation_with_mocked_gemini_adapter():
    """Full simulation execution succeeds with Gemini adapter injected."""
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "Agent message generated by Gemini LLM."
    mock_client.models.generate_content.return_value = mock_resp

    adapter = GeminiAdapter(
        api_key="test-key-mock",
        model="gemini-2.5-flash",
        max_calls=50,
        client=mock_client,
    )

    cfg = ScenarioConfig(scenario_id="normal_collaboration", agent_count=3, seed=42)
    sim = run_simulation(cfg, adapter=adapter)

    # Check that events have been emitted and messages delivered
    send_events = [e for e in sim.events if e.event_type == "message" and e.action == "send"]
    recv_events = [e for e in sim.events if e.event_type == "message" and e.action == "receive"]

    assert len(send_events) > 0
    assert len(recv_events) == len(send_events)
    assert all("Gemini LLM" in e.payload["content"] for e in send_events)
    assert all("Gemini LLM" in e.payload["content"] for e in recv_events)


def test_quota_tracker_paces_instead_of_falling_back(monkeypatch):
    """Hitting the per-minute limit waits for the next free slot, so a run stays on Gemini end to end."""
    from app.adapters.gemini_adapter import GeminiQuotaTracker

    tracker = GeminiQuotaTracker(daily_budget=10, rpm_limit=2)
    tracker.record_call()
    tracker.record_call()
    wait = tracker.seconds_until_slot()
    assert 59 < wait <= 60
    slept = []
    monkeypatch.setattr("app.adapters.gemini_adapter.time.sleep", slept.append)
    tracker.wait_for_slot(max_wait=65)
    assert slept and slept[0] >= 59
    tracker.wait_for_slot(max_wait=5)  # too long to wait: leave it to can_call()
    assert len(slept) == 1
    tracker.daily_calls_used = 10
    assert tracker.seconds_until_slot() is None  # daily budget spent: never wait



@pytest.mark.parametrize("msg,seconds", [
    ("Please retry in 8h3m22.389s.", 8 * 3600 + 3 * 60 + 22.389),
    ("Please retry in 13.827405338s.", 13.827405338),
    ("Please retry in 5m.", 300.0),
    ("no hint here", None),
])
def test_retry_hint_is_read_from_429(msg, seconds):
    from app.adapters.gemini_adapter import retry_after_seconds

    got = retry_after_seconds(msg)
    assert got == pytest.approx(seconds) if seconds is not None else got is None
