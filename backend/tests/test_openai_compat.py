"""Second model provider: any OpenAI-compatible API (OpenAI, Groq, OpenRouter) or a local Ollama."""
import pytest

from app.adapters import get_adapter
from app.adapters.openai_compat import OpenAICompatAdapter
from app.modules.simulator.engine import run_simulation
from app.schemas import ScenarioConfig


def fake_server(replies):
    sent = []

    def post(url, body):
        sent.append((url, body))
        r = replies.pop(0) if replies else "{}"
        if isinstance(r, Exception):
            raise r
        return {"choices": [{"message": {"content": r}}]}
    return post, sent


def test_requests_follow_the_chat_completions_format():
    post, sent = fake_server(["<think>hmm</think> 4"])
    a = OpenAICompatAdapter(name="openai", base_url="https://api.example/v1/", model="m-1", api_key="k", post=post)
    assert a.generate_response("2+2?", system_instruction="Be brief.", temperature=0.1, max_tokens=50) == "4"  # thinking removed
    url, body = sent[0]
    assert url == "https://api.example/v1/chat/completions" and body["model"] == "m-1"
    assert body["messages"] == [{"role": "system", "content": "Be brief."}, {"role": "user", "content": "2+2?"}]


def test_failures_and_the_call_cap_fall_back_quietly():
    import urllib.error

    post, _ = fake_server([urllib.error.URLError("down")])
    a = OpenAICompatAdapter(name="ollama", base_url="http://localhost:11434/v1", model="m", max_calls=1, post=post)
    assert a.generate_response("hi") == ""  # server down: the simulator falls back to scripted work
    assert a.generate_response("hi") == "" and a.calls_left == 0  # cap reached: no request sent
    assert a.compose_message("planner", "analyst", "assign_task", "SG-101").startswith("Please take the next analyst task")


def test_a_full_ai_run_works_through_this_adapter():
    import json

    def post(url, body):
        system = body["messages"][0]["content"]
        if "planner of a small AI software team" in system:
            return {"choices": [{"message": {"content": json.dumps({"assignments": {"analyst": "Summarise SG-101."}})}}]}
        return {"choices": [{"message": {"content": json.dumps({"actions": [{"action": "run_tool"}], "report": "Done."})}}]}

    a = OpenAICompatAdapter(name="openai", base_url="https://api.example/v1", model="m", post=post)
    sim = run_simulation(ScenarioConfig(scenario_id="normal_collaboration", agent_mode="autonomous", persist=False), adapter=a)
    assert sim.run.counts["ai_decisions"] == 8 and sim.run.counts["planner_decisions"] == 2
    assert any((e.payload.get("ai_trace") or {}).get("backend") == "openai" for e in sim.events)


def test_backends_are_configured_from_env(monkeypatch):
    monkeypatch.setenv("OPENAI_MODEL", "gpt-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.groq.example/openai/v1")
    a = get_adapter("openai")
    assert a.model == "gpt-test" and a.base_url == "https://api.groq.example/openai/v1"
    monkeypatch.delenv("OPENAI_MODEL")
    with pytest.raises(ValueError, match="model"):
        get_adapter("openai")
    monkeypatch.setenv("OLLAMA_MODEL", "qwen3:0.6b")
    assert get_adapter("ollama").model == "qwen3:0.6b"
