import re
from config import FLAG_PATTERNS


def extract_flag(text: str) -> str | None:
    """Return first flag-pattern match found in text, or None."""
    for pattern in FLAG_PATTERNS:
        match = re.search(pattern, text)
        if match:
            return match.group(0)
    return None


def extract_all_flags(text: str) -> list[str]:
    """Return all unique flag-pattern matches found in text."""
    found = set()
    for pattern in FLAG_PATTERNS:
        for match in re.finditer(pattern, text):
            found.add(match.group(0))
    return list(found)


def looks_like_flag(text: str) -> bool:
    return extract_flag(text) is not None


def score_output(text: str) -> int:
    """
    Heuristic score: how 'promising' is a tool output?
    Used to rank actions the agent should prioritise.
    """
    score = 0
    if looks_like_flag(text):
        score += 1000
    # Common interesting keywords
    keywords = ["password", "secret", "admin", "root:", "bin/bash",
                "private key", "BEGIN RSA", "BEGIN PGP", "JFIF", "PNG",
                "correct", "success", "token", "cookie", "session"]
    for kw in keywords:
        if kw.lower() in text.lower():
            score += 10
    return score