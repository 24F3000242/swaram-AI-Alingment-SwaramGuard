"""Optional LLM-written message text via the Anthropic Messages API.

Spending is capped by `max_calls`; once exhausted (or on any error) the adapter
falls back to deterministic templates so a run never fails because of the model.
"""
from __future__ import annotations

import os

import httpx

from app.adapters.base import DeterministicAdapter

API_URL = "https://api.anthropic.com/v1/messages"


class AnthropicAdapter:
    name = "anthropic"

    def __init__(self, model: str, max_calls: int = 20, timeout: float = 15.0):
        self.api_key = os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set; use agent_backend='deterministic'")
        self.model = model
        self.calls_left = max_calls
        self.timeout = timeout
        self._fallback = DeterministicAdapter()

    def compose_message(self, sender_role: str, recipient_role: str, intent: str, topic: str) -> str:
        if self.calls_left <= 0:
            return self._fallback.compose_message(sender_role, recipient_role, intent, topic)
        self.calls_left -= 1
        prompt = (
            f"You are a {sender_role} agent in a synthetic workplace simulation. "
            f"Write one short sentence (max 25 words) to the {recipient_role} agent. "
            f"Intent: {intent}. Topic: {topic}. Reply with the sentence only."
        )
        try:
            resp = httpx.post(
                API_URL,
                headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": self.model, "max_tokens": 80, "messages": [{"role": "user", "content": prompt}]},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            blocks = resp.json().get("content", [])
            text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
            return text or self._fallback.compose_message(sender_role, recipient_role, intent, topic)
        except (httpx.HTTPError, ValueError):
            return self._fallback.compose_message(sender_role, recipient_role, intent, topic)

    def generate_response(
        self,
        prompt: str,
        *,
        system_instruction: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """General response generation for agent decisions and freeform synthesis."""
        if self.calls_left <= 0:
            return self._fallback.generate_response(prompt, system_instruction=system_instruction)
        self.calls_left -= 1
        body: dict = {
            "model": self.model,
            "max_tokens": max_tokens or 150,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_instruction:
            body["system"] = system_instruction
        if temperature is not None:
            body["temperature"] = temperature
        try:
            resp = httpx.post(
                API_URL,
                headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json=body,
                timeout=self.timeout,
            )
            resp.raise_for_status()
            blocks = resp.json().get("content", [])
            text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text").strip()
            return text or self._fallback.generate_response(prompt, system_instruction=system_instruction)
        except (httpx.HTTPError, ValueError):
            return self._fallback.generate_response(prompt, system_instruction=system_instruction)
