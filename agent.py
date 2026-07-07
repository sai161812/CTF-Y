"""
agent.py
--------
The core CTF solver agent.

Usage:
    python agent.py --desc "Decode this message: aGVsbG8=" --category crypto
    python agent.py --desc "Login bypass challenge" --url http://target.ctf/login
    python agent.py --desc "Find the flag in this image" --file challenge.png
    python agent.py  # interactive mode
"""

import argparse
import json
import textwrap
import sys
from pathlib import Path
from typing import Any

import config
from classifier import classify
from providers import call_llm, current_provider_info
from tools.flag import extract_flag, extract_all_flags, score_output

# ── Module imports ─────────────────────────────────────────────────────────────
import modules.crypto as crypto
import modules.forensics as forensics
import modules.web as web


# ──────────────────────────────────────────────────────────────────────────────
# Tool registry — functions the agent can call
# ──────────────────────────────────────────────────────────────────────────────

TOOLS = {
    # ── Crypto ────────────────────────────────────────────────────────────────
    "try_all_encodings":    lambda data: crypto.try_all_encodings(data),
    "identify_cipher":      lambda text: crypto.identify_cipher(text),
    "caesar_brute":         lambda text: crypto.caesar_brute(text),
    "caesar_decrypt":       lambda text, shift: crypto.caesar_decrypt(text, int(shift)),
    "vigenere_decrypt":     lambda text, key: crypto.vigenere_decrypt(text, key),
    "vigenere_kasiski":     lambda text: crypto.vigenere_kasiski(text),
    "atbash":               lambda text: crypto.atbash(text),
    "rot13":                lambda text: crypto.rot_n(text, 13),
    "substitution_auto":    lambda text: crypto.substitution_auto(text),
    "morse_decode":         lambda text: crypto.morse_decode(text),
    "xor_single_brute":     lambda hex_data: crypto.xor_single_byte_brute(bytes.fromhex(hex_data)),
    "xor_multi":            lambda hex_data, hex_key: crypto.xor_multi_key(
                                bytes.fromhex(hex_data), bytes.fromhex(hex_key)).hex(),
    "xor_guess_keylen":     lambda hex_data: crypto.xor_guess_keylen(bytes.fromhex(hex_data)),
    "xor_break":            lambda hex_data, keylen: crypto.xor_break_multi(
                                bytes.fromhex(hex_data), int(keylen)).hex(),
    "rsa_full_solve":       lambda n, e, c: crypto.rsa_full_solve(int(n), int(e), int(c)),
    "rsa_small_e":          lambda c, e: crypto.rsa_small_e(int(c), int(e)),
    "rsa_wiener":           lambda e, n: crypto.rsa_wiener(int(e), int(n)),
    "factordb":             lambda n: crypto.factordb_lookup(int(n)),
    "rail_fence":           lambda text, rails: crypto.rail_fence_decode(text, int(rails)),
    "bacon_decode":         lambda text: crypto.bacon_decode(text),
    "long_to_bytes":        lambda n: crypto.long_to_bytes(int(n)).decode("utf-8", errors="replace"),

    # ── Forensics ─────────────────────────────────────────────────────────────
    "file_info":            lambda fp: forensics.file_info(fp),
    "auto_analyze_file":    lambda fp: forensics.auto_analyze(fp),
    "extract_strings":      lambda fp: forensics.extract_strings(fp)[:100],
    "hexdump":              lambda fp: forensics.hexdump(fp),
    "extract_metadata":     lambda fp: forensics.extract_metadata(fp),
    "binwalk_scan":         lambda fp: forensics.find_embedded_files(fp),
    "binwalk_extract":      lambda fp: forensics.binwalk_extract(fp),
    "parse_png_chunks":     lambda fp: forensics.parse_png_chunks(fp),
    "lsb_extract":          lambda fp: forensics.lsb_extract_python(fp),
    "zsteg":                lambda fp: forensics.zsteg_scan(fp),
    "steghide":             lambda fp, pw="": forensics.steghide_extract(fp, pw),
    "steg_planes":          lambda fp: forensics.stegsolve_planes(fp),
    "wav_lsb":              lambda fp: forensics.wavsteg_extract(fp),
    "spectrogram":          lambda fp: forensics.spectrogram_screenshot(fp),
    "pcap_summary":         lambda fp: forensics.pcap_summary(fp),
    "pcap_http":            lambda fp: forensics.pcap_http(fp),
    "crack_zip":            lambda fp: forensics.crack_zip_password(fp),
    "list_zip":             lambda fp: forensics.list_zip(fp),

    # ── Web ───────────────────────────────────────────────────────────────────
    "web_recon":            lambda url: web.auto_recon(url),
    "get":                  lambda url, **kw: web.get(url, **kw),
    "post":                 lambda url, **kw: web.post(url, **kw),
    "sqli_fuzz":            lambda url, param, method="GET": web.sqli_fuzz(url, param, method),
    "lfi_fuzz":             lambda url, param: web.lfi_fuzz(url, param),
    "ssti_fuzz":            lambda url, param, method="GET": web.ssti_fuzz(url, param, method),
    "ssrf_fuzz":            lambda url, param: web.ssrf_fuzz(url, param),
    "cmd_inject":           lambda url, param: web.cmd_injection_fuzz(url, param),
    "header_inject":        lambda url, val="127.0.0.1": web.header_injection(url, val),
    "dir_fuzz":             lambda url: web.directory_fuzz(url),
    "api_fuzz":             lambda url: web.api_param_fuzz(url),
    "robots_txt":           lambda url: web.robots_txt(url),
    "git_leak":             lambda url: web.git_leak_check(url),
    "decode_jwt":           lambda token: web.decode_jwt(token),
    "forge_jwt_none":       lambda token, **kw: web.forge_jwt_none_alg(token, kw or None),
    "crack_jwt":            lambda token: web.crack_jwt_secret(token),
    "graphql_introspect":   lambda url: web.graphql_introspect(url),
}

TOOL_DESCRIPTIONS = {
    # Crypto
    "try_all_encodings":    "Try base64, base32, hex, ROT13, binary, decimal on a string",
    "identify_cipher":      "Heuristically identify cipher type from ciphertext",
    "caesar_brute":         "Brute-force all 25 Caesar shifts",
    "caesar_decrypt":       "Decrypt Caesar cipher with a known shift",
    "vigenere_decrypt":     "Decrypt Vigenere cipher with known key",
    "vigenere_kasiski":     "Estimate Vigenere key length via index of coincidence",
    "atbash":               "Apply Atbash cipher",
    "rot13":                "Apply ROT13",
    "substitution_auto":    "Auto-solve substitution cipher via frequency analysis",
    "morse_decode":         "Decode Morse code string",
    "xor_single_brute":     "Brute-force single-byte XOR (input: hex string)",
    "xor_multi":            "XOR data with multi-byte key (inputs: hex strings)",
    "xor_guess_keylen":     "Guess XOR key length via Hamming distance",
    "xor_break":            "Break multi-byte XOR given key length",
    "rsa_full_solve":       "Try all RSA attacks (small-e, Wiener, FactorDB) — args: n, e, c",
    "rsa_small_e":          "RSA small public exponent attack",
    "rsa_wiener":           "Wiener's attack for small private exponent",
    "factordb":             "Query factordb.com to factor RSA modulus n",
    "rail_fence":           "Rail fence cipher decode — args: text, rails",
    "bacon_decode":         "Decode Bacon's cipher",
    "long_to_bytes":        "Convert large integer to bytes/string",
    # Forensics
    "file_info":            "Get file type, size, hashes",
    "auto_analyze_file":    "Full automatic forensics analysis of a file",
    "extract_strings":      "Extract printable strings from file",
    "hexdump":              "Hex dump of file header",
    "extract_metadata":     "Extract EXIF/metadata from file",
    "binwalk_scan":         "Scan for embedded files with binwalk",
    "binwalk_extract":      "Extract embedded files with binwalk",
    "parse_png_chunks":     "Parse PNG chunks looking for hidden tEXt/iTXt data",
    "lsb_extract":          "Extract LSB steganography from image",
    "zsteg":                "Run zsteg on PNG/BMP for steganography",
    "steghide":             "Try steghide extraction (args: filepath, password)",
    "steg_planes":          "Extract bit planes (StegSolve equivalent)",
    "wav_lsb":              "Extract LSB from WAV audio",
    "spectrogram":          "Generate audio spectrogram",
    "pcap_summary":         "Summarize PCAP network capture",
    "pcap_http":            "Extract HTTP from PCAP",
    "crack_zip":            "Crack password-protected ZIP",
    "list_zip":             "List contents of ZIP file",
    # Web
    "web_recon":            "Full web recon: forms, links, dirs, cookies",
    "get":                  "HTTP GET request",
    "post":                 "HTTP POST request",
    "sqli_fuzz":            "SQL injection fuzzing — args: url, param, method",
    "lfi_fuzz":             "LFI/path traversal fuzzing — args: url, param",
    "ssti_fuzz":            "Server-side template injection fuzzing — args: url, param",
    "ssrf_fuzz":            "SSRF fuzzing — args: url, param",
    "cmd_inject":           "Command injection fuzzing — args: url, param",
    "header_inject":        "IP-bypass header injection",
    "dir_fuzz":             "Directory/file discovery",
    "api_fuzz":             "API parameter fuzzing",
    "robots_txt":           "Fetch robots.txt",
    "git_leak":             "Check for exposed .git directory",
    "decode_jwt":           "Decode JWT token without verification",
    "forge_jwt_none":       "Forge JWT with 'none' algorithm",
    "crack_jwt":            "Brute-force JWT secret from wordlist",
    "graphql_introspect":   "Run GraphQL introspection query",
}


# ──────────────────────────────────────────────────────────────────────────────
# Agent reasoning
# ──────────────────────────────────────────────────────────────────────────────

AGENT_SYSTEM = """You are an elite CTF solver agent. You solve Capture The Flag challenges by:
1. Analyzing outputs from recon/attack tools
2. Deciding which tool to run next
3. Iterating until you find the flag

You have access to a toolkit. Each turn you receive:
- The challenge description
- Your action history so far
- The last tool output

You respond with ONLY valid JSON in this format:
{
  "thought": "<your reasoning about what you've found and what to try next>",
  "action": "<tool_name>",
  "args": ["<arg1>", "<arg2>"],
  "confidence": <0.0-1.0>,
  "done": false
}

If you found the flag OR are certain there is no flag to be found:
{
  "thought": "<reasoning>",
  "action": "done",
  "args": [],
  "flag": "<the flag if found, else null>",
  "done": true
}

RULES:
- Pick ONE tool per turn that will give you the most information
- If a tool reveals a flag pattern like CTF{...} or HTB{...} — set done=true immediately
- Don't repeat the exact same tool+args combination
- If web recon found forms/params, fuzz them for SQLi/SSTI/LFI/SSRF
- For crypto: always try try_all_encodings first, then identify_cipher
- For forensics: always start with auto_analyze_file
- For web: always start with web_recon
- Be specific in your thought — explain exactly what you observed and why you chose this action"""


def call_llm_json(user_content: str) -> dict:
    """Call the configured LLM and parse JSON from the response."""
    text = call_llm(AGENT_SYSTEM, user_content)

    # Strip markdown fences if model wrapped output in ```json ... ```
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:])
        if text.endswith("```"):
            text = text[:-3].rstrip()

    return json.loads(text)


def execute_tool(action: str, args: list) -> Any:
    """Look up and call a tool from the registry."""
    if action not in TOOLS:
        return f"Unknown tool: {action}. Available: {list(TOOLS.keys())}"
    fn = TOOLS[action]
    try:
        return fn(*args)
    except TypeError as e:
        return f"Tool call error (wrong args?): {e}"
    except Exception as e:
        return f"Tool execution error: {type(e).__name__}: {e}"


def pretty_result(result: Any, max_len: int = 3000) -> str:
    """Serialize tool output to a string the agent can read."""
    if isinstance(result, str):
        text = result
    elif isinstance(result, (dict, list)):
        text = json.dumps(result, indent=2, default=str)
    elif isinstance(result, bytes):
        try:
            text = result.decode("utf-8", errors="replace")
        except Exception:
            text = result.hex()
    else:
        text = str(result)
    return text[:max_len] + ("... [truncated]" if len(text) > max_len else "")


def build_context(challenge: dict, history: list[dict], last_output: str) -> str:
    """Build the user message for the agent."""
    lines = [
        f"CHALLENGE: {challenge['description']}",
    ]
    if challenge.get("url"):
        lines.append(f"URL: {challenge['url']}")
    if challenge.get("files"):
        lines.append(f"FILES: {', '.join(challenge['files'])}")

    lines.append(f"\nCATEGORY: {challenge.get('category', 'unknown')}")
    lines.append(f"SUBCATEGORIES: {challenge.get('subcategories', [])}")

    lines.append(f"\nSTEPS SO FAR ({len(history)}):")
    for i, h in enumerate(history[-8:]):   # last 8 only to save tokens
        lines.append(f"  {i+1}. {h['action']}({h['args']}) → {h['result_preview']}")

    lines.append(f"\nLAST TOOL OUTPUT:\n{last_output}")

    lines.append(f"\nAVAILABLE TOOLS:\n" +
                 "\n".join(f"  {k}: {v}" for k, v in TOOL_DESCRIPTIONS.items()))

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# Main solve loop
# ──────────────────────────────────────────────────────────────────────────────

def solve(description: str, url: str = None, files: list[str] = None,
          category: str = None, verbose: bool = True) -> dict:
    """
    Full CTF solve loop.
    
    Returns:
        {
          "flag": str | None,
          "steps": list,
          "history": list
        }
    """
    pinfo = current_provider_info()
    print("\n" + "═" * 60)
    print("  [!] CTF SOLVER AGENT")
    print("═" * 60)
    print(f"  Provider:  {pinfo['provider'].upper()}  ({pinfo['model']})")
    print(f"  API key:   {'[OK] set' if pinfo['key_set'] else '[X] MISSING — set env var'}")
    print(f"  Challenge: {textwrap.shorten(description, 80)}")
    if url:
        print(f"  URL: {url}")
    if files:
        print(f"  Files: {files}")

    # ── Step 1: Classify ──────────────────────────────────────────────────────
    print("\n[*] Classifying challenge...")
    classification = classify(description, files=files, url=url)
    if category:
        classification["category"] = category

    print(f"    Category:    {classification.get('category')}")
    print(f"    Subcats:     {classification.get('subcategories')}")
    print(f"    Confidence:  {classification.get('confidence')}")
    print(f"    Reasoning:   {classification.get('reasoning', '')[:100]}")

    challenge = {
        "description": description,
        "url": url,
        "files": files or [],
        "category": classification.get("category"),
        "subcategories": classification.get("subcategories", []),
    }

    # ── Step 2: Pick initial action from classifier's plan ────────────────────
    initial_output = f"Classification complete. Suggested first steps:\n" + \
                     "\n".join(f"  - {s}" for s in classification.get("initial_steps", []))
    
    # Quick-check: if classifier spotted the flag already
    for guess in classification.get("flags_to_try", []):
        if extract_flag(guess):
            print(f"\n[+] FLAG FOUND IN DESCRIPTION: {guess}")
            return {"flag": guess, "steps": [], "history": []}

    # ── Step 3: Reasoning loop ────────────────────────────────────────────────
    history = []
    messages = []
    last_output = initial_output
    flag = None

    for step in range(config.MAX_STEPS):
        print(f"\n[Step {step + 1}/{config.MAX_STEPS}] Thinking...")

        # Build context message
        user_content = build_context(challenge, history, last_output)

        # Ask LLM what to do
        try:
            decision = call_llm_json(user_content)
        except Exception as e:
            print(f"    [!] Claude API error: {e}")
            break

        action = decision.get("action", "done")
        args = decision.get("args", [])
        thought = decision.get("thought", "")
        done = decision.get("done", False)
        found_flag = decision.get("flag")

        print(f"    [?] {textwrap.shorten(thought, 100)}")
        print(f"    [*] Action: {action}({', '.join(str(a) for a in args)})")

        # Done?
        if done or action == "done":
            flag = found_flag
            if flag:
                print(f"\n[+] FLAG FOUND: {flag}")
            else:
                print("\n[-] Agent gave up — no flag found.")
            break

        # Execute tool
        result = execute_tool(action, args)
        result_str = pretty_result(result)

        # Check for flag in output
        flags_in_output = extract_all_flags(result_str)
        if flags_in_output:
            flag = flags_in_output[0]
            print(f"\n[+] FLAG FOUND IN OUTPUT: {flag}")
            history.append({
                "action": action,
                "args": args,
                "result_preview": result_str[:100],
            })
            break

        # Score and log
        score = score_output(result_str)
        preview = result_str[:120].replace("\n", " ")
        print(f"    [>] Output (score={score}): {preview}...")

        history.append({
            "action": action,
            "args": args,
            "result_preview": result_str[:150],
        })
        last_output = result_str

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "═" * 60)
    if flag:
        print(f"  [*] FINAL FLAG: {flag}")
    else:
        print("  [-] No flag found. Review the step history for clues.")
    print(f"  Steps taken: {len(history)}")
    print("═" * 60 + "\n")

    return {
        "flag": flag,
        "steps": [h["action"] for h in history],
        "history": history,
        "classification": classification,
    }


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def interactive_mode():
    print("\n[!] CTF Solver — Interactive Mode")
    print("─" * 40)
    description = input("Challenge description: ").strip()
    url = input("Target URL (leave blank if none): ").strip() or None
    files_input = input("File paths, comma-separated (leave blank if none): ").strip()
    files = [f.strip() for f in files_input.split(",") if f.strip()] or None
    category = input("Force category (web/crypto/forensics/misc, or blank): ").strip() or None
    return solve(description, url=url, files=files, category=category)


def main():
    parser = argparse.ArgumentParser(description="CTF Solver Agent")
    parser.add_argument("--desc", "-d", help="Challenge description", default=None)
    parser.add_argument("--url", "-u", help="Target URL", default=None)
    parser.add_argument("--file", "-f", help="File path(s), comma-separated", default=None)
    parser.add_argument("--category", "-c",
                        choices=["web", "crypto", "forensics", "misc"],
                        help="Force category", default=None)
    args = parser.parse_args()

    if not args.desc:
        result = interactive_mode()
    else:
        files = [f.strip() for f in args.file.split(",")] if args.file else None
        result = solve(
            args.desc,
            url=args.url,
            files=files,
            category=args.category,
        )

    if result.get("flag"):
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()