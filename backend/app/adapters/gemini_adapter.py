"""Google Gemini API adapter using the official Google Gen AI SDK (`google-genai`).


Spending and rate limits:

- Per-instance spending cap (`max_calls`).

- Global shared daily budget across runs (default 100 RPD).

- RPM sliding window rate limiter (default 60 RPM).

- Safe handling of HTTP 429 rate limit exceptions with automatic fallback.

"""

from __future__ import annotations


from datetime import datetime, timedelta, timezone
from pathlib import Path
import logging
import threading
import json

import os
import re

import time

from typing import Any


from google import genai

from google.genai import errors, types


from app.adapters.base import DeterministicAdapter


logger = logging.getLogger(__name__)


DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"

DEFAULT_DAILY_BUDGET = 480  # just under Google's free-tier 500/day, so a quota error is rare

DEFAULT_RPM_LIMIT = 14  # free tier: 15/min for Flash-Lite (5/min for 2.5 Flash); stay just under


def mask_secret(secret: str | None) -> str:

    """Safely mask API key for diagnostics and logs."""

    if not secret:

        return "<unset>"

    if len(secret) <= 8:

        return "***"

    return f"{secret[:4]}...{secret[-4:]}"


_RETRY_RE = re.compile(r"retry in\s+(?:(\d+)h)?\s*(?:(\d+)m)?\s*(?:([\d.]+)s)?", re.I)


def retry_after_seconds(message: str) -> float | None:
    """Google's hint in a 429 ("Please retry in 8h3m22.4s"), so a spent daily quota isn't retried every minute."""
    m = _RETRY_RE.search(message or "")
    if not m or not any(m.groups()):
        return None
    h, mins, secs = (float(g) if g else 0.0 for g in m.groups())
    return h * 3600 + mins * 60 + secs


# Google's free tier for gemini-3.5-flash-lite (measured Nov 2026). Daily quotas reset at midnight US Pacific time.
GOOGLE_FREE_TIER = {"rpm": 15, "daily": 500}
QUOTA_FILE = Path(__file__).resolve().parents[2] / "data" / "gemini_quota.json"


def _pacific_offset_hours(t: datetime) -> int:
    """UTC offset of US Pacific time (DST from the 2nd Sunday of March to the 1st Sunday of November, 2 a.m. local)."""
    def nth_sunday(year: int, month: int, n: int) -> datetime:
        first = datetime(year, month, 1, tzinfo=timezone.utc)
        return first + timedelta(days=(6 - first.weekday()) % 7 + 7 * (n - 1))

    dst_start = nth_sunday(t.year, 3, 2) + timedelta(hours=10)  # 2 a.m. PST = 10:00 UTC
    dst_end = nth_sunday(t.year, 11, 1) + timedelta(hours=9)  # 2 a.m. PDT = 09:00 UTC
    return -7 if dst_start <= t < dst_end else -8


def quota_day(now: float) -> str:
    """The Google quota day (US Pacific calendar date) a moment belongs to."""
    t = datetime.fromtimestamp(now, tz=timezone.utc)
    return (t + timedelta(hours=_pacific_offset_hours(t))).date().isoformat()


def next_reset(now: float) -> float:
    """Epoch seconds of the next midnight US Pacific, when Google resets daily quotas."""
    t = datetime.fromtimestamp(now, tz=timezone.utc)
    local = t + timedelta(hours=_pacific_offset_hours(t))
    midnight_local = datetime(local.year, local.month, local.day, tzinfo=timezone.utc) + timedelta(days=1)
    guess = midnight_local - timedelta(hours=_pacific_offset_hours(t))
    return (midnight_local - timedelta(hours=_pacific_offset_hours(guess))).timestamp()


def humanize_seconds(seconds: float) -> str:
    seconds = max(0, int(seconds))
    h, m = seconds // 3600, (seconds % 3600) // 60
    return f"{h}h {m}m" if h else f"{m}m {seconds % 60}s" if m else f"{seconds}s"


class GeminiQuotaTracker:
    """Daily and per-minute Gemini quota, shared by every adapter in the process and persisted across restarts.

    The daily count follows Google's quota day (resets at midnight US Pacific) and is saved to a small JSON file, so
    the app and the scripts see the same usage. When Google itself reports the daily quota spent (HTTP 429 "per
    day"), calls stop until the reset instead of being retried every minute.
    """

    def __init__(self, daily_budget: int = DEFAULT_DAILY_BUDGET, rpm_limit: int = DEFAULT_RPM_LIMIT,
                 state_file: str | Path | None = None) -> None:
        self.daily_budget = int(os.getenv("GEMINI_DAILY_BUDGET", daily_budget))
        self.rpm_limit = int(os.getenv("GEMINI_MAX_RPM", rpm_limit))
        self._state_file = state_file
        self._lock = threading.Lock()
        self.day = quota_day(time.time())
        self.daily_calls_used = 0
        self.call_timestamps: list[float] = []
        self.cooldown_until: float = 0.0  # short pause after a per-minute 429
        self.exhausted_until: float = 0.0  # Google reported the daily quota spent
        self._load()

    # ---------------------------------------------------------------- persistence (shared by app and scripts)
    def _path(self) -> Path | None:
        raw = self._state_file if self._state_file is not None else os.getenv("GEMINI_QUOTA_FILE", str(QUOTA_FILE))
        return None if str(raw).lower() in ("", "off") else Path(raw)

    def _load(self) -> None:
        path = self._path()
        if not path or not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if data.get("day") == self.day:
            self.daily_calls_used = max(self.daily_calls_used, int(data.get("calls", 0)))
            self.exhausted_until = max(self.exhausted_until, float(data.get("exhausted_until", 0.0)))

    def _save(self) -> None:
        path = self._path()
        if not path:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"day": self.day, "calls": self.daily_calls_used,
                                        "exhausted_until": self.exhausted_until}), encoding="utf-8")
        except OSError:
            logger.debug("could not persist Gemini quota usage to %s", path)

    def _refresh_window(self) -> None:
        now = time.time()
        day = quota_day(now)
        if day != self.day:  # Google's quota day rolled over
            self.day, self.daily_calls_used, self.exhausted_until = day, 0, 0.0
        self._load()  # pick up calls made by other processes (scripts, the server)
        cutoff = now - 60.0
        self.call_timestamps = [t for t in self.call_timestamps if t > cutoff]

    # ---------------------------------------------------------------- checks
    def can_call(self) -> tuple[bool, str | None]:
        """Check whether an API call is permitted within daily and RPM quotas."""
        with self._lock:
            now = time.time()
            self._refresh_window()
            if now < self.exhausted_until:
                return False, (f"Google's daily Gemini quota is used up; it resets in "
                               f"{humanize_seconds(self.exhausted_until - now)}")
            if now < self.cooldown_until:
                return False, f"in cooldown after HTTP 429 until {self.cooldown_until:.1f}"
            if self.daily_calls_used >= self.daily_budget:
                return False, (f"daily quota exhausted ({self.daily_calls_used}/{self.daily_budget} calls used); "
                               f"resets in {humanize_seconds(next_reset(now) - now)}")
            if len(self.call_timestamps) >= self.rpm_limit:
                return False, f"RPM limit exceeded ({len(self.call_timestamps)}/{self.rpm_limit} calls in 60s)"
            return True, None

    def remaining(self) -> int:
        with self._lock:
            self._refresh_window()
            if time.time() < self.exhausted_until:
                return 0
            return max(0, self.daily_budget - self.daily_calls_used)

    def seconds_until_slot(self) -> float | None:
        """Seconds until the rate limits allow a call (0 = now). None if the daily quota is spent."""
        with self._lock:
            now = time.time()
            self._refresh_window()
            if self.daily_calls_used >= self.daily_budget or now < self.exhausted_until:
                return None
            wait = max(0.0, self.cooldown_until - now)
            if len(self.call_timestamps) >= self.rpm_limit:
                wait = max(wait, self.call_timestamps[-self.rpm_limit] + 60.0 - now)
            return wait

    def wait_for_slot(self, max_wait: float) -> None:
        """Pace calls to the per-minute limit instead of falling back to scripted text mid-run."""
        wait = self.seconds_until_slot()
        if wait and wait <= max_wait:
            logger.info("Gemini rate limit: waiting %.1fs for the next free slot", wait)
            time.sleep(wait + 0.05)

    # ---------------------------------------------------------------- recording
    def record_call(self) -> None:
        """Record a successful API invocation."""
        with self._lock:
            now = time.time()
            self._refresh_window()
            self.daily_calls_used += 1
            self.call_timestamps.append(now)
            self._save()

    def record_429(self, cooldown_seconds: float = 60.0, *, daily: bool = False) -> None:
        """Record an HTTP 429. A daily-quota 429 (or a retry hint longer than 10 minutes) blocks until the reset."""
        with self._lock:
            now = time.time()
            if daily or cooldown_seconds > 600:
                self.exhausted_until = now + cooldown_seconds if cooldown_seconds > 600 else next_reset(now)
                self._save()
            else:
                self.cooldown_until = now + cooldown_seconds

    def reset(self) -> None:
        """Reset quota counters (used in testing)."""
        with self._lock:
            self.day = quota_day(time.time())
            self.daily_calls_used = 0
            self.call_timestamps.clear()
            self.cooldown_until = 0.0
            self.exhausted_until = 0.0
            self._save()

    def status(self) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            self._refresh_window()
            exhausted = now < self.exhausted_until
            resets_at = self.exhausted_until if exhausted else next_reset(now)
            remaining = 0 if exhausted else max(0, self.daily_budget - self.daily_calls_used)
            if exhausted:
                reason = f"Google's daily quota is used up; resets in {humanize_seconds(resets_at - now)}"
            elif remaining == 0:
                reason = f"Daily budget of {self.daily_budget} calls used; resets in {humanize_seconds(resets_at - now)}"
            elif now < self.cooldown_until:
                reason = f"Per-minute limit hit; free again in {humanize_seconds(self.cooldown_until - now)}"
            else:
                reason = None
            return {
                "day": self.day,
                "calls_today": self.daily_calls_used,
                "daily_limit": self.daily_budget,
                "remaining_today": remaining,
                "rpm_limit": self.rpm_limit,
                "calls_last_minute": len(self.call_timestamps),
                "resets_at": datetime.fromtimestamp(resets_at, tz=timezone.utc).isoformat(timespec="seconds"),
                "resets_in_s": int(max(0, resets_at - now)),
                "exhausted": exhausted or remaining == 0,
                "blocked_reason": reason,
                "google_free_tier": GOOGLE_FREE_TIER,
                # kept for older callers
                "daily_budget": self.daily_budget,
                "daily_calls_used": self.daily_calls_used,
                "daily_calls_remaining": remaining,
                "current_rpm": len(self.call_timestamps),
                "in_cooldown": now < self.cooldown_until or exhausted,
            }


GLOBAL_QUOTA_TRACKER = GeminiQuotaTracker()


def get_quota_tracker() -> GeminiQuotaTracker:

    return GLOBAL_QUOTA_TRACKER


def reset_quota_tracker() -> None:

    GLOBAL_QUOTA_TRACKER.reset()


class GeminiAdapter:

    name = "gemini"


    def __init__(

        self,

        api_key: str | None = None,

        model: str | None = None,

        max_calls: int = 20,

        timeout: float | None = None,

        max_retries: int | None = None,

        client: Any | None = None,

        quota_tracker: GeminiQuotaTracker | None = None,

    ):

        self.api_key = api_key or os.getenv("GEMINI_API_KEY")

        if not self.api_key:

            raise ValueError(

                "GEMINI_API_KEY is not set; configure GEMINI_API_KEY in .env or use agent_backend='deterministic'"

            )

        self.model = model or os.getenv("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL

        self.calls_left = max_calls

        env_timeout = float(os.getenv("GEMINI_TIMEOUT", "15.0"))

        self.timeout = timeout if timeout is not None else env_timeout

        env_retries = int(os.getenv("GEMINI_MAX_RETRIES", "3"))

        self.max_retries = max_retries if max_retries is not None else env_retries

        self.quota_tracker = quota_tracker or GLOBAL_QUOTA_TRACKER

        self._fallback = DeterministicAdapter()

        self._client = client

        self.last_finish_reason: str | None = None

        self.last_was_truncated: bool = False


    def _get_client(self) -> genai.Client:

        if self._client is None:

            # types.HttpOptions expects timeout in milliseconds

            timeout_ms = int(self.timeout * 1000) if self.timeout < 1000 else int(self.timeout)

            retry_opts = types.HttpRetryOptions(

                attempts=self.max_retries,

                initial_delay=2.0,

                exp_base=2.0,

                http_status_codes=[408, 429, 500, 502, 503, 504],

            )

            self._client = genai.Client(

                api_key=self.api_key,

                http_options=types.HttpOptions(

                    timeout=timeout_ms,

                    retry_options=retry_opts,

                ),

            )

        return self._client


    def compose_message(self, sender_role: str, recipient_role: str, intent: str, topic: str) -> str:

        """Compose message text using Gemini, falling back to deterministic template on any failure."""

        fallback = self._fallback.compose_message(sender_role, recipient_role, intent, topic)

        if self.calls_left <= 0:

            return fallback


        prompt = (

            f"You are a {sender_role} agent in a synthetic workplace simulation. "

            f"Write one short sentence (max 25 words) to the {recipient_role} agent. "

            f"Intent: {intent}. Topic: {topic}. Reply with the sentence only."

        )

        return self.generate_response(

            prompt,

            max_tokens=80,

            temperature=0.7,

            fallback_text=fallback,

        )


    def generate_response(

        self,

        prompt: str,

        *,

        system_instruction: str | None = None,

        temperature: float | None = None,

        max_tokens: int | None = None,

        fallback_text: str | None = None,

        strict: bool = False,

    ) -> str:

        """General response-generation interface for agent reasoning, tool selection, and communication."""

        default_fallback = (

            fallback_text

            if fallback_text is not None

            else self._fallback.generate_response(prompt, system_instruction=system_instruction)

        )


        # 1. Check per-instance spending cap

        if self.calls_left <= 0:

            if strict:

                raise RuntimeError("Gemini spending cap reached: 0 calls left for this session")

            logger.info("Spending cap reached for Gemini adapter (0 calls left); using deterministic fallback")

            return default_fallback


        # 2. Check global daily and RPM quota limits

        self.quota_tracker.wait_for_slot(float(os.getenv("GEMINI_MAX_WAIT_S", "65")))

        allowed, reason = self.quota_tracker.can_call()

        if not allowed:

            if strict:

                raise RuntimeError(f"Gemini API call blocked by quota protection: {reason}")

            logger.warning("Gemini API call blocked by quota protection (%s); using fallback", reason)

            return default_fallback


        self.calls_left -= 1


        config_kwargs: dict[str, Any] = {}
        if system_instruction:
            config_kwargs["system_instruction"] = system_instruction

        # Determine effective token limit:
        # In Gemini thinking models (such as gemini-3.x and gemini-2.5), thinking tokens
        # and response tokens share the same max_output_tokens budget. Setting max_output_tokens
        # below 8192 prematurely cuts off the model during reasoning, triggering MAX_TOKENS truncation.
        effective_max = max_tokens
        if effective_max is not None and effective_max < 8192:
            effective_max = 8192
        elif effective_max is None:
            effective_max = 8192

        config_kwargs["max_output_tokens"] = effective_max

        # Configure thinking: for Gemini 3.x, use low thinking level for fast operations; for older models use budget
        if "3" in self.model:
            config_kwargs["thinking_config"] = types.ThinkingConfig(thinking_level="low")
        elif effective_max <= 150:
            config_kwargs["thinking_config"] = types.ThinkingConfig(thinking_budget=0)
            if temperature is not None:
                config_kwargs["temperature"] = temperature
        elif temperature is not None:
            config_kwargs["temperature"] = temperature

        config = types.GenerateContentConfig(**config_kwargs) if config_kwargs else None


        last_error = None

        last_code = None


        for attempt in range(1, self.max_retries + 1):

            try:

                client = self._get_client()

                resp = client.models.generate_content(

                    model=self.model,

                    contents=prompt,

                    config=config,

                )

                text = (resp.text or "").strip()

                candidate = resp.candidates[0] if (getattr(resp, "candidates", None) and len(resp.candidates) > 0) else None

                finish_reason = getattr(candidate, "finish_reason", None) if candidate else None

                fr_str = str(finish_reason).upper() if finish_reason else ""

                self.last_finish_reason = fr_str

                self.last_was_truncated = "MAX_TOKENS" in fr_str

                if self.last_was_truncated:

                    logger.warning("Gemini response was truncated due to token limit (finish_reason=%s)", fr_str)


                if not text:

                    if strict:

                        raise RuntimeError(f"Gemini returned empty or filtered response for model '{self.model}'")

                    logger.warning("Gemini returned empty or filtered response for model '%s'", self.model)

                    return default_fallback


                # Record successful call in quota tracker

                self.quota_tracker.record_call()

                return text

            except errors.APIError as err:

                last_code = getattr(err, "code", "unknown")

                err_msg = getattr(err, "message", None) or str(err)

                last_error = err_msg

                if last_code == 429 or "RESOURCE_EXHAUSTED" in str(err_msg):

                    logger.warning("Gemini HTTP 429 (Rate Limit / Quota Exceeded); triggering quota tracker cooldown: %s", err_msg)
                    _wait = retry_after_seconds(str(err_msg))

                    self.quota_tracker.record_429(_wait or 60.0, daily="per day" in str(err_msg).lower())

                else:

                    logger.warning("Gemini APIError [%s] for model '%s' (attempt %d/%d): %s", last_code, self.model, attempt, self.max_retries, err_msg)


                # Transient errors retry with backoff

                if last_code in (504, 503, 502, 500, 408) and attempt < self.max_retries:

                    backoff = 2.0 * (2 ** (attempt - 1))

                    logger.info("Retrying transient %s error after %.1fs backoff...", last_code, backoff)

                    time.sleep(backoff)

                    continue


                if strict:

                    raise RuntimeError(f"Gemini APIError [{last_code}] for model '{self.model}': {err_msg}") from err

                return default_fallback

            except Exception as err:

                if strict and isinstance(err, RuntimeError):

                    raise

                err_str = str(err)

                last_error = err_str

                if "429" in err_str or "RESOURCE_EXHAUSTED" in err_str:

                    logger.warning("Gemini HTTP 429 rate limit detected; cooling down")
                    _wait = retry_after_seconds(err_str)

                    self.quota_tracker.record_429(_wait or 60.0, daily="per day" in err_str.lower())

                else:

                    logger.warning("Gemini request exception for model '%s' (attempt %d/%d): %s", self.model, attempt, self.max_retries, type(err).__name__)


                if attempt < self.max_retries and ("deadline" in err_str.lower() or "timeout" in err_str.lower() or "unavailable" in err_str.lower()):

                    backoff = 2.0 * (2 ** (attempt - 1))

                    logger.info("Retrying after %.1fs backoff on timeout/network exception: %s", backoff, err)

                    time.sleep(backoff)

                    continue


                if strict:

                    raise RuntimeError(f"Gemini request exception for model '{self.model}': {err}") from err

                return default_fallback


    def verify_connection(self) -> dict[str, Any]:

        """Verify real connection to Gemini API with current adapter configuration."""

        return self.check_connection(

            api_key=self.api_key,

            model=self.model,

            timeout=self.timeout,

            max_retries=self.max_retries,

            client=self._client,

        )


    @classmethod

    def check_connection(

        cls,

        api_key: str | None = None,

        model: str | None = None,

        timeout: float | None = None,

        max_retries: int | None = None,

        client: Any | None = None,

    ) -> dict[str, Any]:

        """Safe diagnostics method to test Gemini API connectivity without exposing secrets.


        Includes configurable timeout and exponential backoff retry for transient 504 / 503 errors.

        """

        key = api_key or os.getenv("GEMINI_API_KEY")

        selected_model = model or os.getenv("GEMINI_MODEL") or DEFAULT_GEMINI_MODEL

        req_timeout = timeout if timeout is not None else float(os.getenv("GEMINI_TIMEOUT", "45.0"))

        retries = max_retries if max_retries is not None else int(os.getenv("GEMINI_MAX_RETRIES", "3"))


        if not key:

            return {

                "status": "error",

                "ok": False,

                "connected": False,

                "model": selected_model,

                "api_key_configured": False,

                "masked_key": None,

                "error": "GEMINI_API_KEY is not set in environment or .env file",

            }


        masked = mask_secret(key)

        timeout_ms = int(req_timeout * 1000) if req_timeout < 1000 else int(req_timeout)


        # Ultra-minimal prompt for connection test

        gen_config_kwargs: dict[str, Any] = {"max_output_tokens": 10}

        if "3" in selected_model:

            gen_config_kwargs["thinking_config"] = types.ThinkingConfig(thinking_level="low")


        last_code = None

        last_error = None


        for attempt in range(1, retries + 1):

            try:

                t0 = time.time()

                c = client or genai.Client(

                    api_key=key,

                    http_options=types.HttpOptions(

                        timeout=timeout_ms,

                        retry_options=types.HttpRetryOptions(

                            attempts=2,

                            initial_delay=2.0,

                            http_status_codes=[408, 429, 500, 502, 503, 504],

                        ),

                    ),

                )

                resp = c.models.generate_content(

                    model=selected_model,

                    contents="Ping",

                    config=types.GenerateContentConfig(**gen_config_kwargs),

                )

                elapsed_ms = int((time.time() - t0) * 1000)

                text = (resp.text or "").strip()

                return {

                    "status": "connected",

                    "ok": True,

                    "connected": True,

                    "model": selected_model,

                    "api_key_configured": True,

                    "masked_key": masked,

                    "response": text,

                    "latency_ms": elapsed_ms,

                    "attempts": attempt,

                }

            except errors.APIError as err:

                last_code = getattr(err, "code", "unknown")

                err_msg = getattr(err, "message", None) or str(err)

                last_error = err_msg.replace(key, masked)

                logger.warning("Gemini probe attempt %d/%d failed with code %s: %s", attempt, retries, last_code, last_error)

                if last_code in (504, 503, 408, 502, 500) and attempt < retries:

                    backoff = 2.0 * (2 ** (attempt - 1))

                    time.sleep(backoff)

            except Exception as err:

                last_error = str(err).replace(key, masked)

                logger.warning("Gemini probe attempt %d/%d exception: %s", attempt, retries, last_error)

                if attempt < retries:

                    backoff = 2.0 * (2 ** (attempt - 1))

                    time.sleep(backoff)


        return {

            "status": "error",

            "ok": False,

            "connected": False,

            "model": selected_model,

            "api_key_configured": True,

            "masked_key": masked,

            "error": f"APIError ({last_code}): {last_error}" if last_code else f"Error: {last_error}",

            "attempts": retries,

        }
