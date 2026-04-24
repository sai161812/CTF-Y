"""
classifier.py
-------------
Uses Claude to classify a CTF challenge and suggest an initial attack plan.
"""

import json
import httpx
from config import ANTHROPIC_API_KEY, MODEL, MAX_TOKENS

SYSTEM_PROMPT = """You are an expert CTF (Capture The Flag) solver with deep knowledge of:
- Web exploitation (SQLi, LFI, SSTI, SSRF, XSS, JWT attacks, IDOR, path traversal)
- Cryptography (classical ciphers, RSA, XOR, encoding schemes, hash cracking)
- Forensics / steganography (image/audio/file analysis, hidden data, metadata)
- Binary exploitation and reverse engineering

Your job is to analyze a CTF challenge description and classify it, then return a structured JSON plan.

ALWAYS respond with ONLY valid JSON in this exact format:
{
  "category": "<web|crypto|forensics|misc>",
  "subcategories": ["<specific types e.g. sqli, lfi, rsa, lsb_stego>"],
  "confidence": <0.0-1.0>,
  "reasoning": "<brief analysis>",
  "initial_steps": ["<ordered list of first actions to take>"],
  "tools_to_use": ["<list of tool function names from modules>"],
  "flags_to_try": ["<any obvious flag guesses if applicable>"],
  "hints": ["<any clues spotted in description>"]
}"""


def classify(challenge_description: str, files: list[str] = None,
             url: str = None) -> dict:
    """
    Classify a CTF challenge using Claude.
    
    Args:
        challenge_description: The challenge text/description
        files: List of file paths attached to challenge
        url: Target URL if it's a web challenge
    
    Returns:
        Classification dict with category, steps, and tools
    """
    context_parts = [f"CHALLENGE DESCRIPTION:\n{challenge_description}"]

    if url:
        context_parts.append(f"TARGET URL: {url}")

    if files:
        context_parts.append(f"ATTACHED FILES: {', '.join(files)}")

    user_msg = "\n\n".join(context_parts)

    try:
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": MODEL,
                "max_tokens": MAX_TOKENS,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user_msg}],
            },
            timeout=30,
        )
        resp.raise_for_status()
        text = resp.json()["content"][0]["text"].strip()

        # Strip markdown fences if present
        if text.startswith("```"):
            text = "\n".join(text.split("\n")[1:])
            if text.endswith("```"):
                text = text[:-3]

        return json.loads(text)

    except json.JSONDecodeError as e:
        return {
            "category": "unknown",
            "subcategories": [],
            "confidence": 0.0,
            "reasoning": f"JSON parse error: {e}",
            "initial_steps": ["manual analysis required"],
            "tools_to_use": [],
            "flags_to_try": [],
            "hints": [],
        }
    except Exception as e:
        return {
            "category": "unknown",
            "subcategories": [],
            "confidence": 0.0,
            "reasoning": f"Classifier error: {e}",
            "initial_steps": ["manual analysis required"],
            "tools_to_use": [],
            "flags_to_try": [],
            "hints": [],
        }