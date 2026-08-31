"""Minimal, dependency-free client for Google Gemini's generateContent API.

Design choices:
  * Stdlib only (urllib). The host side of this project deliberately carries no
    third-party dependencies so a judge can reproduce it from a clean Python
    install without a resolver step. The only heavy dependency is Docker, which
    the sandbox genuinely needs.
  * Every call returns a GenResult carrying latency and token usage. An LLM call
    is an unreliable external dependency; we treat it like one (timeout, bounded
    retries with exponential backoff) and we measure it, because the brief's
    metric table asks for cost per task and the changelog asks for evidence.
  * JSON mode is a first-class argument. Most agent stages must return a machine
    -readable object; we ask Gemini for application/json and parse defensively.
"""
from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

# gemini-3.7-flash is the newest flash model but was returning sustained 503
# (capacity) on this key during the build window, at ~60s per failed attempt.
# gemini-3.5-flash is thinking-capable, answers in ~10s, and was reliably
# available, so it is the workhorse. Override with SLOPGATE_MODEL if 3.7 frees up.
DEFAULT_MODEL = os.environ.get("SLOPGATE_MODEL", "gemini-3.5-flash")
# Used only when the primary model returns repeated 503/overload. A run that
# fell back is logged so the reproduction guide can state which model answered.
FALLBACK_MODEL = "gemini-2.5-flash"
API_ROOT = "https://generativelanguage.googleapis.com/v1beta"
REQUEST_TIMEOUT_SECONDS = 120
MAX_RETRIES = 3  # bounded so one bad call can't stall a whole evaluation for minutes

# Rough public price for Gemini Flash-class models, USD per 1M tokens. Used only
# to populate the cost column of the evaluation table; it is an estimate and is
# labeled as such wherever it surfaces.
PRICE_PER_MTOK_INPUT = 0.30
PRICE_PER_MTOK_OUTPUT = 2.50


class GeminiError(RuntimeError):
    """Raised when the API cannot be reached or returns an unusable response."""


@dataclass
class GenResult:
    text: str
    prompt_tokens: int
    output_tokens: int
    latency_s: float
    model: str
    raw: dict = field(default_factory=dict, repr=False)

    @property
    def est_cost_usd(self) -> float:
        return (
            self.prompt_tokens / 1_000_000 * PRICE_PER_MTOK_INPUT
            + self.output_tokens / 1_000_000 * PRICE_PER_MTOK_OUTPUT
        )

    def json(self) -> Any:
        """Parse the response text as JSON, tolerating markdown code fences."""
        return _loads_lenient(self.text)


def load_api_key() -> str:
    """Read the key from the environment, falling back to a git-ignored .env.

    The key is never hardcoded and never logged. The .env file is in .gitignore
    so it cannot reach the submission (hackathon ground rule 08).
    """
    key = os.environ.get("GEMINI_API_KEY")
    if key:
        return key.strip()
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if env_path.is_file():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("GEMINI_API_KEY=") and not line.startswith("#"):
                return line.split("=", 1)[1].strip()
    raise GeminiError(
        "GEMINI_API_KEY not found. Set it in the environment or in a .env file "
        "at the project root (see .env.example)."
    )


def _loads_lenient(text: str) -> Any:
    """Parse JSON that a model may have wrapped in ```json fences or prose."""
    text = text.strip()
    if text.startswith("```"):
        # drop the opening fence line and any closing fence
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Last resort: grab the outermost JSON object/array by brace matching.
        start = min(
            (i for i in (text.find("{"), text.find("[")) if i != -1),
            default=-1,
        )
        if start != -1:
            for end in range(len(text), start, -1):
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    continue
        raise


def generate(
    prompt: str,
    *,
    system: Optional[str] = None,
    json_mode: bool = False,
    temperature: float = 0.0,
    model: str = DEFAULT_MODEL,
    api_key: Optional[str] = None,
    max_output_tokens: int = 8192,
    allow_fallback: bool = True,
) -> GenResult:
    """Call generateContent once and return the text plus usage.

    temperature defaults to 0 for reproducibility across judge reruns. On
    repeated overload (503) of the primary model, falls back once to
    FALLBACK_MODEL rather than failing the whole run.
    """
    key = api_key or load_api_key()
    try:
        return _generate_once(prompt, system, json_mode, temperature, model,
                              key, max_output_tokens)
    except GeminiError as exc:
        overloaded = "HTTP 503" in str(exc) or "HTTP 429" in str(exc)
        if allow_fallback and overloaded and model != FALLBACK_MODEL:
            return _generate_once(prompt, system, json_mode, temperature,
                                  FALLBACK_MODEL, key, max_output_tokens)
        raise


def _generate_once(prompt, system, json_mode, temperature, model, key,
                   max_output_tokens) -> GenResult:
    url = f"{API_ROOT}/models/{model}:generateContent"

    body: dict[str, Any] = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": temperature,
            "maxOutputTokens": max_output_tokens,
        },
    }
    if system:
        body["systemInstruction"] = {"parts": [{"text": system}]}
    if json_mode:
        body["generationConfig"]["responseMimeType"] = "application/json"

    payload = json.dumps(body).encode("utf-8")
    last_err: Optional[Exception] = None

    for attempt in range(MAX_RETRIES):
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json", "x-goog-api-key": key},
            method="POST",
        )
        start = time.time()
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            latency = time.time() - start
            return _parse_response(data, latency, model)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            last_err = GeminiError(f"HTTP {exc.code}: {detail}")
            # 4xx other than 429 will not be fixed by retrying.
            if exc.code < 500 and exc.code != 429:
                raise last_err
        except (urllib.error.URLError, TimeoutError, socket.timeout,
                OSError, json.JSONDecodeError) as exc:
            # socket.timeout is not a TimeoutError subclass on Python 3.9, and a
            # dropped connection surfaces as a bare OSError — both are transient
            # and worth retrying rather than crashing the whole case.
            last_err = GeminiError(f"{type(exc).__name__}: {exc}")

        if attempt < MAX_RETRIES - 1:
            time.sleep(min(2 ** attempt, 16))  # 1,2,4,8,16s

    raise last_err or GeminiError("generate() failed with no captured error")


def _parse_response(data: dict, latency: float, model: str) -> GenResult:
    candidates = data.get("candidates") or []
    if not candidates:
        block = data.get("promptFeedback", {}).get("blockReason")
        raise GeminiError(f"No candidates returned (blockReason={block!r})")

    parts = candidates[0].get("content", {}).get("parts", []) or []
    text = "".join(p.get("text", "") for p in parts)

    finish = candidates[0].get("finishReason")
    if not text and finish:
        raise GeminiError(f"Empty completion (finishReason={finish})")

    usage = data.get("usageMetadata", {})
    return GenResult(
        text=text,
        prompt_tokens=usage.get("promptTokenCount", 0),
        output_tokens=usage.get("candidatesTokenCount", 0),
        latency_s=latency,
        model=model,
        raw=data,
    )
