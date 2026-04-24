import os

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODEL = "claude-sonnet-4-20250514"
MAX_TOKENS = 4096

MAX_STEPS = 25          # hard cap on reasoning iterations per challenge
TIMEOUT_CMD = 30        # seconds for subprocess calls
TIMEOUT_HTTP = 10       # seconds for HTTP requests

FLAG_PATTERNS = [
    r'picoCTF\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'HackTheBox\{[^}]+\}',
    r'DUCTF\{[^}]+\}',
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'[A-Z0-9_]{2,10}\{[A-Za-z0-9_\-!@#$%^&*()+= ]{4,80}\}', 
]

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}