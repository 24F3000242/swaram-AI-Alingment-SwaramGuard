"""Pluggable agent-behaviour adapters.

Adapters write free-text content and generate agent reasoning responses.
They never bypass policy checks, and detection never trusts their text as evidence.
"""
from __future__ import annotations

import os

from app.adapters.base import AgentAdapter, DeterministicAdapter
from app.config import get_settings


def available_adapters() -> list[dict[str, object]]:
    s = get_settings()
    gemini_key = os.getenv("GEMINI_API_KEY")
    gemini_model = os.getenv("GEMINI_MODEL") or s.gemini_model
    return [
        {"id": "deterministic", "label": "Deterministic templates", "available": True},
        {
            "id": "gemini",
            "label": f"Google Gemini API ({gemini_model})",
            "available": bool(gemini_key),
        },
        {
            "id": "anthropic",
            "label": f"Anthropic API ({s.llm_model})",
            "available": bool(os.getenv("ANTHROPIC_API_KEY")),
        },
        {
            "id": "openai",
            "label": f"OpenAI-compatible API ({os.getenv('OPENAI_MODEL') or 'set OPENAI_MODEL'})",
            "available": bool(os.getenv("OPENAI_API_KEY") and os.getenv("OPENAI_MODEL")),
        },
        {
            "id": "ollama",
            "label": f"Local Ollama ({os.getenv('OLLAMA_MODEL', 'ministral-3:3b-instruct-2512-q4_K_M')})",
            "available": _ollama_up(),
        },
    ]


def _ollama_up() -> bool:
    from app.adapters.openai_compat import reachable

    return reachable(os.getenv("OLLAMA_BASE_URL", "http://localhost:11434/v1"))


def get_adapter(name: str) -> AgentAdapter:
    if name in ("", "deterministic"):
        return DeterministicAdapter()
    if name == "gemini":
        from app.adapters.gemini_adapter import GeminiAdapter

        s = get_settings()
        return GeminiAdapter(
            model=os.getenv("GEMINI_MODEL") or s.gemini_model,
            max_calls=s.llm_max_calls,
        )
    if name == "anthropic":
        from app.adapters.anthropic_adapter import AnthropicAdapter

        s = get_settings()
        return AnthropicAdapter(model=s.llm_model, max_calls=s.llm_max_calls)
    if name in ("openai", "ollama"):
        from app.adapters.openai_compat import ollama_from_env, openai_from_env

        return (openai_from_env if name == "openai" else ollama_from_env)(get_settings().llm_max_calls)
    raise ValueError(f"Unknown agent backend: {name}")


__all__ = ["AgentAdapter", "DeterministicAdapter", "available_adapters", "get_adapter"]
