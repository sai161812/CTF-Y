"""
providers.py
------------
Unified LLM caller. Supports Anthropic Claude and Google Gemini.
Switch providers by setting the CTF_PROVIDER env var or editing config.py.

Usage:
    export CTF_PROVIDER=anthropic   ANTHROPIC_API_KEY=sk-ant-...
    export CTF_PROVIDER=gemini      GEMINI_API_KEY=AIza...
"""

import httpx
import config


# ──────────────────────────────────────────────────────────────────────────────
# Anthropic
# ──────────────────────────────────────────────────────────────────────────────

def _call_anthropic(system: str, user: str) -> str:
    if not config.ANTHROPIC_API_KEY:
        raise ValueError("ANTHROPIC_API_KEY is not set. Export it or edit config.py.")

    resp = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": config.ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        json={
            "model": config.ANTHROPIC_MODEL,
            "max_tokens": config.MAX_TOKENS,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        },
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()["content"][0]["text"].strip()


# ──────────────────────────────────────────────────────────────────────────────
# Google Gemini
# ──────────────────────────────────────────────────────────────────────────────

def _call_gemini(system: str, user: str) -> str:
    if not config.GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY is not set. Export it or edit config.py.")

    # Gemini combines system + user into a single `contents` list.
    # We prepend the system prompt as a user turn + a model ack to simulate it.
    contents = [
        {"role": "user",  "parts": [{"text": system}]},
        {"role": "model", "parts": [{"text": "Understood. I will follow these instructions exactly."}]},
        {"role": "user",  "parts": [{"text": user}]},
    ]

    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{config.GEMINI_MODEL}:generateContent?key={config.GEMINI_API_KEY}"
    )

    resp = httpx.post(
        url,
        headers={"content-type": "application/json"},
        json={
            "contents": contents,
            "generationConfig": {
                "maxOutputTokens": config.MAX_TOKENS,
                "temperature": 0.2,
            },
        },
        timeout=60,
    )
    resp.raise_for_status()

    data = resp.json()
    # Navigate Gemini's response structure
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"].strip()
    except (KeyError, IndexError) as e:
        raise RuntimeError(f"Unexpected Gemini response structure: {data}") from e


# ──────────────────────────────────────────────────────────────────────────────
# Public interface
# ──────────────────────────────────────────────────────────────────────────────

def call_llm(system: str, user: str) -> str:
    """
    Call the configured LLM provider with a system prompt and user message.
    Returns the model's text response.

    Provider is selected by config.PROVIDER ("anthropic" | "gemini").
    Override at runtime:
        import config; config.PROVIDER = "gemini"
    """
    provider = config.PROVIDER.lower().strip()

    if provider == "anthropic":
        return _call_anthropic(system, user)
    elif provider in ("gemini", "google"):
        return _call_gemini(system, user)
    else:
        raise ValueError(
            f"Unknown provider '{provider}'. "
            f"Set CTF_PROVIDER to 'anthropic' or 'gemini'."
        )


def current_provider_info() -> dict:
    """Return info about which provider + model is active."""
    p = config.PROVIDER.lower()
    if p == "anthropic":
        return {
            "provider": "anthropic",
            "model": config.ANTHROPIC_MODEL,
            "key_set": bool(config.ANTHROPIC_API_KEY),
        }
    elif p in ("gemini", "google"):
        return {
            "provider": "gemini",
            "model": config.GEMINI_MODEL,
            "key_set": bool(config.GEMINI_API_KEY),
        }
    return {"provider": p, "model": "unknown", "key_set": False}