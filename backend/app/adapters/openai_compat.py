"""OpenAI-compatible chat adapter: OpenAI, Groq, OpenRouter, a local Ollama, or anything speaking /chat/completions.

A second model provider next to Gemini: compare how different models handle the same injections, and keep working
when Gemini's free daily quota is spent (a local Ollama model has no quota at all).

    backend "openai":  OPENAI_API_KEY, OPENAI_MODEL (required), OPENAI_BASE_URL (default https://api.openai.com/v1)
    backend "ollama":  OLLAMA_MODEL (default ministral-3:3b-instruct-2512-q4_K_M), OLLAMA_BASE_URL
                       (default http://localhost:11434/v1); no key

Keys stay in backend/.env. Each adapter has a per-run call cap like the Gemini one (SWARMGUARD_LLM_MAX_CALLS).
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request

from app.adapters.base import TEMPLATES

log = logging.getLogger(__name__)
THINK = re.compile(r"<think>.*?</think>", re.S)  # reasoning models (e.g. qwen3) wrap their thoughts in these
_REACHABLE: dict[str, tuple[float, bool]] = {}


def reachable(base_url: str, ttl: float = 30.0) -> bool:
    """Is a local server answering? Cached briefly so /api/meta stays fast."""
    hit = _REACHABLE.get(base_url)
    if hit and time.time() - hit[0] < ttl:
        return hit[1]
    try:
        urllib.request.urlopen(f"{base_url.rstrip('/')}/models", timeout=0.4).read()
        ok = True
    except Exception:
        ok = False
    _REACHABLE[base_url] = (time.time(), ok)
    return ok


class OpenAICompatAdapter:
    def __init__(self, *, name: str, base_url: str, model: str, api_key: str | None = None, max_calls: int = 80,
                 timeout: float = 60.0, post=None):
        if not model:
            raise ValueError(f"{name}: set the model name (e.g. OPENAI_MODEL in backend/.env)")
        self.name, self.base_url, self.model, self.api_key = name, base_url.rstrip("/"), model, api_key
        self.calls_left, self.timeout = max_calls, timeout
        self._post = post or self._http_post

    def _http_post(self, url: str, body: dict) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read())

    def generate_response(self, prompt: str, *, system_instruction: str | None = None, temperature: float | None = None,
                          max_tokens: int | None = None) -> str:
        if self.calls_left <= 0:
            log.warning("%s: per-run call cap reached; using fallback", self.name)
            return ""
        self.calls_left -= 1
        messages = ([{"role": "system", "content": system_instruction}] if system_instruction else []) + \
                   [{"role": "user", "content": prompt}]
        body = {"model": self.model, "messages": messages, "temperature": 0.4 if temperature is None else temperature}
        if max_tokens:
            body["max_tokens"] = max(max_tokens, 800)  # reasoning models need room before the answer
        try:
            data = self._post(f"{self.base_url}/chat/completions", body)
            text = data["choices"][0]["message"].get("content") or ""
        except (urllib.error.URLError, KeyError, IndexError, ValueError, TimeoutError) as exc:
            log.warning("%s request failed: %s", self.name, exc)
            return ""
        return THINK.sub("", text).strip()

    def compose_message(self, sender_role: str, recipient_role: str, intent: str, topic: str) -> str:
        text = self.generate_response(
            f"Write one short sentence a {sender_role} agent sends to a {recipient_role} agent to {intent.replace('_', ' ')} "
            f"about ticket {topic}. Reply with the sentence only.", temperature=0.6, max_tokens=60)
        return text.splitlines()[0].strip().strip('"') if text else TEMPLATES.get(intent, "{topic}").format(
            role=recipient_role, topic=topic)


def openai_from_env(max_calls: int) -> OpenAICompatAdapter:
    return OpenAICompatAdapter(name="openai", base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
                               model=os.getenv("OPENAI_MODEL", ""), api_key=os.getenv("OPENAI_API_KEY"), max_calls=max_calls)


def ollama_from_env(max_calls: int) -> OpenAICompatAdapter:
    return OpenAICompatAdapter(name="ollama", base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"),
                               model=os.getenv("OLLAMA_MODEL", "ministral-3:3b-instruct-2512-q4_K_M"), max_calls=max_calls,
                               timeout=180.0)
