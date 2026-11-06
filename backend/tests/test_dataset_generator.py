"""Dataset generator: export contract for the Data Optimizer, scoring, resume and quota stop."""
import json
import sys
from pathlib import Path

import pytest

from app.modules.simulator.export import parse_canonical_jsonl
from app.services.dataset import BatchConfig, generate, planned_runs

sys.path.insert(0, str(Path(__file__).parent))
from test_autonomous_agents import FakeLLM  # noqa: E402


@pytest.fixture()
def rules():
    from app.services.pipeline import Pipeline
    from app.storage.sqlite_store import SQLiteStore

    return Pipeline(SQLiteStore(":memory:")).rules()


def _cfg(tmp_path, **kw):
    return BatchConfig(out_dir=str(tmp_path / "batch"), scenarios=["normal_collaboration", "inj_spoofed_planner"],
                       runs_per_scenario=2, learn_runs=2, backend="fake", **kw)


def _lines(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_batch_exports_canonical_events_labels_and_summary(tmp_path, rules):
    cfg = _cfg(tmp_path)
    summary = generate(cfg, rules, adapter_factory=lambda: FakeLLM(gullible=True), log=lambda m: None)
    out = tmp_path / "batch"
    labels = _lines(out / "labels.jsonl")
    assert len(labels) == len(planned_runs(cfg)) == 6
    assert sum(r["learned_into_baseline"] for r in labels) == 2
    for lab in labels:  # the 12-field contract member 2 already parses, one file per run, no labels inside
        records = parse_canonical_jsonl(out / "events" / f"{lab['run_id']}.jsonl")
        assert records and all(len(r) == 12 for r in records)
        assert not any("malicious" in json.dumps(r["details"]) for r in records)
    traced = [r for lab in labels for r in parse_canonical_jsonl(out / "events" / f"{lab['run_id']}.jsonl")
              if "ai_trace" in r["details"]]
    assert traced  # why each agent acted travels with the events
    spoof = summary["scenarios"]["inj_spoofed_planner"]
    assert spoof["runs"] == 2 and spoof["hijacked"] == 2 and spoof["caught"] == 2 and spoof["missed"] == 0
    assert summary["total"]["precision"] == 1.0 and summary["total"]["recall"] == 1.0
    assert "inj_spoofed_planner" in (out / "summary.md").read_text(encoding="utf-8")
    assert json.loads((out / "baseline_profile.json").read_text())["runs_learned"] > 0


def test_rerun_resumes_instead_of_repeating(tmp_path, rules):
    cfg = _cfg(tmp_path)
    llm = FakeLLM()
    generate(cfg, rules, adapter_factory=lambda: llm, log=lambda m: None)
    first = llm.calls
    generate(cfg, rules, adapter_factory=lambda: llm, log=lambda m: None)
    assert llm.calls == first  # nothing re-run
    assert len(_lines(tmp_path / "batch" / "labels.jsonl")) == 6


def test_stops_cleanly_when_the_daily_budget_is_spent(tmp_path, rules):
    class Tracker:
        def __init__(self):
            self.left = 3  # enough for three runs

        def seconds_until_slot(self):
            self.left -= 1
            return 0 if self.left >= 0 else None

    llm = FakeLLM()
    llm.quota_tracker = Tracker()
    summary = generate(_cfg(tmp_path), rules, adapter_factory=lambda: llm, log=lambda m: None)
    assert summary["stopped_early"] and len(_lines(tmp_path / "batch" / "labels.jsonl")) == 3


def test_degraded_run_stops_the_batch_and_is_redone_on_resume(tmp_path, rules):
    class Flaky(FakeLLM):
        down = True

        def generate_response(self, prompt, **kw):
            return "" if self.down else super().generate_response(prompt, **kw)

    llm = Flaky()
    s = generate(_cfg(tmp_path), rules, adapter_factory=lambda: llm, log=lambda m: None, retries=0)
    assert s["stopped_early"] and len(_lines(tmp_path / "batch" / "labels.jsonl")) == 1
    llm.down = False
    s = generate(_cfg(tmp_path), rules, adapter_factory=lambda: llm, log=lambda m: None)
    assert not s["stopped_early"] and s["degraded_runs"] == 1 and s["learned_runs"] == 2


def test_batch_with_live_guard_reports_leaks_stopped(tmp_path, rules):
    cfg = _cfg(tmp_path, live_guard="contain")
    cfg.scenarios = ["inj_phishing_email"]
    s = generate(cfg, rules, adapter_factory=lambda: FakeLLM(gullible=True), log=lambda m: None)
    phish = s["scenarios"]["inj_phishing_email"]
    assert phish["live_runs"] == 2 and phish["stopped_before_harm"] == 2 and phish["leaked"] == 0
    assert s["total"]["innocent_paused"] == 0
    assert "Live guard (contain)" in (tmp_path / "batch" / "summary.md").read_text(encoding="utf-8")



def test_a_passing_outage_is_retried_instead_of_stopping(tmp_path, rules):
    class Blip(FakeLLM):
        failures = 2  # the first two model calls fail (HTTP 503), then it recovers

        def generate_response(self, prompt, **kw):
            if self.failures:
                self.failures -= 1
                return ""
            return super().generate_response(prompt, **kw)

    waits, blip = [], Blip()
    s = generate(_cfg(tmp_path), rules, adapter_factory=lambda: blip, log=lambda m: None, pause=waits.append)
    assert not s["stopped_early"] and waits == [60.0] and s["degraded_runs"] == 1 and s["learned_runs"] == 2



def test_each_run_gets_a_fresh_adapter_so_the_per_run_cap_never_starves_a_batch(tmp_path, rules):
    class Capped(FakeLLM):
        def __init__(self):
            super().__init__()
            self.calls_left = 10  # like SWARMGUARD_LLM_MAX_CALLS: enough for one run (8 decisions), not a batch

        def generate_response(self, prompt, **kw):
            if self.calls_left <= 0:
                return ""
            self.calls_left -= 1
            return super().generate_response(prompt, **kw)

    s = generate(_cfg(tmp_path), rules, adapter_factory=Capped, log=lambda m: None, retries=0)
    assert not s["stopped_early"] and s["degraded_runs"] == 0 and s["learned_runs"] == 2
