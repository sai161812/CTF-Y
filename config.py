import os
from dotenv import load_dotenv

load_dotenv()  # reads .env from the project root

# ══════════════════════════════════════════════════════════════════════════════
# AI PROVIDER  — pick "anthropic" or "gemini"
# ══════════════════════════════════════════════════════════════════════════════
PROVIDER = os.getenv("CTF_PROVIDER", "anthropic")   # "anthropic" | "gemini"

# ── Anthropic ─────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL   = "claude-sonnet-4-20250514"

# ── Google Gemini ─────────────────────────────────────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL   = "gemini-1.5-pro"                   # or "gemini-1.5-flash" for speed

MAX_TOKENS = 4096

# ══════════════════════════════════════════════════════════════════════════════
# FLAG PATTERNS  — edit freely, add your CTF's prefix here
# Format: raw Python regex strings. Must match the full flag token.
# Examples:
#   r'ACSC\{[^}]+\}'          → ACSC{...}
#   r'n00bz\{[^}]+\}'         → n00bz{...}
#   r'[A-Z0-9]+\{[^}]{4,}\}'  → any ALLCAPS prefix (generic catch-all)
# ══════════════════════════════════════════════════════════════════════════════
FLAG_PATTERNS = [
    # ── Specific known formats (checked first) ────────────────────────────────
    r'picoCTF\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'HackTheBox\{[^}]+\}',
    r'DUCTF\{[^}]+\}',
    r'ACSC\{[^}]+\}',
    r'1337UP\{[^}]+\}',
    r'SHELL\{[^}]+\}',
    r'uiuctf\{[^}]+\}',
    r'lactf\{[^}]+\}',
    r'corctf\{[^}]+\}',
    r'idekCTF\{[^}]+\}',
    r'BCTF\{[^}]+\}',
    r'SDCTF\{[^}]+\}',

    # ── Generic (case-insensitive prefix + braces) ────────────────────────────
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'CTF\{[^}]+\}',

    # ── Catch-all: 2–12 uppercase/digit/underscore chars followed by {…} ──────
    # Increase specificity by raising min prefix length if you get false positives
    r'[A-Z0-9_]{2,12}\{[A-Za-z0-9_\-!@#$%^&*()+= ]{4,100}\}',
]

# Add your CTF's custom flag format below — one pattern per line:
# FLAG_PATTERNS.append(r'MYCTF\{[^}]+\}')

# ══════════════════════════════════════════════════════════════════════════════
# AGENT BEHAVIOUR
# ══════════════════════════════════════════════════════════════════════════════
MAX_STEPS    = 25    # hard cap on reasoning steps per challenge
TIMEOUT_CMD  = 30    # seconds for subprocess calls
TIMEOUT_HTTP = 10    # seconds for HTTP requests

# ── HTTP defaults ──────────────────────────────────────────────────────────────
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}