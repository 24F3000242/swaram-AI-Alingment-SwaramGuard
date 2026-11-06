"""Environment-driven settings. No secrets are hardcoded; see `.env.example`."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = BACKEND_DIR.parent
FIXTURES_DIR = REPO_DIR / "fixtures"


def _load_dotenv() -> None:
    """Minimal .env loader so the app runs without extra dependencies."""
    for candidate in (BACKEND_DIR / ".env", REPO_DIR / ".env"):
        if not candidate.exists():
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


@dataclass(frozen=True)
class Settings:
    storage: str  # "auto" | "sqlite" | "firestore" | "memory"
    workspace: str
    sqlite_path: str
    firebase_credentials: str | None
    firebase_project_id: str | None
    llm_provider: str
    llm_model: str
    llm_max_calls: int
    gemini_model: str = "gemini-3.5-flash-lite"
    gemini_api_key: str | None = None
    cors_origins: list[str] = field(default_factory=list)


def get_settings() -> Settings:
    _load_dotenv()
    return Settings(
        storage=os.getenv("SWARMGUARD_STORAGE", "auto").lower(),
        workspace=os.getenv("SWARMGUARD_WORKSPACE", "default"),
        sqlite_path=os.getenv("SWARMGUARD_SQLITE_PATH", str(BACKEND_DIR / "data" / "swarmguard.db")),
        firebase_credentials=os.getenv("FIREBASE_CREDENTIALS") or None,
        firebase_project_id=os.getenv("FIREBASE_PROJECT_ID") or None,
        llm_provider=os.getenv("SWARMGUARD_LLM_PROVIDER", "deterministic").lower(),
        llm_model=os.getenv("SWARMGUARD_LLM_MODEL", "claude-haiku-5-5"),
        llm_max_calls=int(os.getenv("SWARMGUARD_LLM_MAX_CALLS", "80")),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite"),
        gemini_api_key=os.getenv("GEMINI_API_KEY") or None,
        cors_origins=[o.strip() for o in os.getenv("SWARMGUARD_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if o.strip()],
    )
