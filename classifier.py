"""
classifier.py
-------------
Uses the configured LLM provider to classify a CTF challenge
and return a structured attack plan.
"""

import json
from providers import call_llm

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
    Classify a CTF challenge using the configured LLM provider.

    Args:
        challenge_description: The challenge text/description
        files: List of file paths attached to challenge
        url:   Target URL if it's a web challenge

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
        text = call_llm(SYSTEM_PROMPT, user_msg)

        # Strip markdown fences if model wrapped output in ```json ... ```
        if text.startswith("```"):
            text = "\n".join(text.split("\n")[1:])
            if text.endswith("```"):
                text = text[:-3]

        return json.loads(text.strip())

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