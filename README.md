# CTF-Y

Experimental CTF assistant using Claude or Gemini APIs to select Python tools for web, cryptography, and forensics challenges.

The agent classifies a challenge, asks the model to choose a registered tool, executes it, and feeds the output into the next iteration. It is intended for CTF and explicitly authorized lab targets; this is an intended use boundary, not an enforced target allowlist.

## Current limitations

- No measured solve rate or checked-in challenge evaluation is available.
- Tool outputs are checked for configured flag patterns, but a flag supplied by the model on completion is accepted without independent validation or challenge-server confirmation.
- The system prompt asks the model not to repeat tool calls; the execution loop does not enforce deduplication.
- Model output is parsed as JSON and tool names are checked against the registry, but tool arguments have no schema validation.
- Requests depend on external model APIs. The web module disables TLS certificate verification for challenge requests.

---

## 1. Install

```bash
pip install -r requirements.txt

# Optional CLI tools (recommended for forensics)
sudo apt install binwalk steghide exiftool tshark fcrackzip sox
gem install zsteg      # Ruby gem for PNG stego
```

---

## 2. Pick your AI provider

### Option A — Anthropic Claude (default)
```bash
export CTF_PROVIDER=anthropic
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Option B — Google Gemini
```bash
export CTF_PROVIDER=gemini
export GEMINI_API_KEY="AIza..."
```

You can also hardcode the choice in `config.py`:
```python
PROVIDER      = "gemini"          # "anthropic" | "gemini"
GEMINI_MODEL  = "gemini-2.0-flash"  # current value in config.py
```

---

## 3. Configure flag formats

Open `config.py` and edit `FLAG_PATTERNS`. Each entry is a Python regex.
The list is checked top-to-bottom; first match wins.

```python
FLAG_PATTERNS = [
    # Already included:
    r'picoCTF\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'DUCTF\{[^}]+\}',
    # ...

    # Add yours:
    r'MYCTF\{[^}]+\}',
    r'n00bz\{[^}]+\}',
    r'ACSC\{[^}]+\}',
]
```

Generic catch-all at the bottom covers unknown prefixes:
```
r'[A-Z0-9_]{2,12}\{[A-Za-z0-9_\-!@#$%^&*()+= ]{4,100}\}'
```
If you get false positives remove it, or tighten the length bounds.

---

## 4. Run

```bash
# Interactive mode
python agent.py

# One-shot
python agent.py --desc "Decode this: aGVsbG8="
python agent.py --desc "Login bypass, find the flag" --url http://target.ctf/login
python agent.py --desc "Flag hidden in image"        --file challenge.png
python agent.py --desc "..." --url http://... --category web   # force category
```

### Programmatic
```python
from agent import solve

result = solve(
    description="Login bypass - find the admin flag",
    url="http://challenge.ctf/login",
    category="web",
)
print(result["flag"])
```

For file challenges, the Python API accepts `files=["challenge.png"]`; `--file` is the CLI option. The CLI exits with status `0` when a flag is returned and `1` otherwise. A returned flag still needs confirmation against the challenge server.

### Diagnose a failed run

| Symptom | Check |
|---|---|
| Missing API key | Set the key for the selected `CTF_PROVIDER`; `config.py` also loads `.env`. |
| Provider rejects the model | Check the model constant in `config.py` against models available to your provider account. |
| `Tool not found` | Install the external CLI used by that action; Python dependencies do not include those executables. |
| `Timed out after ...s` | Inspect the chosen action and `TIMEOUT_CMD`; HTTP requests use the separate `TIMEOUT_HTTP`. |
| No flag after the loop | Inspect the printed steps and `MAX_STEPS` (25 by default); reaching the cap is not proof the challenge is unsolvable. |

The forensics setup and tool-availability probe use Linux commands (`apt`, `which`). Use a Linux environment or WSL for that workflow; native Windows parity is not established.

---

## 5. File layout

```
ctf-agent/
├── agent.py          ← main reasoning loop
├── classifier.py     ← challenge classifier (LLM-powered)
├── providers.py      ← unified Claude / Gemini caller  ← PROVIDER SWITCH HERE
├── config.py         ← API keys, flag patterns, timeouts  ← FLAG FORMAT HERE
├── requirements.txt  ← pip deps
├── modules/
│   ├── crypto.py     ← encodings, Caesar/Vigenere/XOR/RSA/Morse/...
│   ├── forensics.py  ← file analysis, stego, PCAP, binwalk, ...
│   └── web.py        ← SQLi, LFI, SSTI, SSRF, JWT, dir fuzz, ...
├── tools/
│   ├── flag.py       ← flag extraction + scoring
│   └── runner.py     ← subprocess wrapper
└── challenges/       ← drop challenge files here
```

---

## 6. Implemented tools

These are implemented routines, not measured solve rates or independently verified vulnerability coverage.

| Category     | What's covered |
|--------------|----------------|
| **Crypto**   | Base64/32/85/hex/binary/decimal, ROT13, Caesar brute, Vigenere + Kasiski keylen, Atbash, XOR single+multi brute, RSA small-e / Wiener / FactorDB, Substitution freq analysis, Morse, Rail fence, Bacon |
| **Forensics**| File type/magic, strings, hexdump, EXIF metadata, binwalk scan+extract, PNG chunk parser, LSB stego, zsteg, steghide, bit-plane extract, WAV LSB, spectrogram, PCAP HTTP+strings, ZIP listing+crack |
| **Web**      | HTTP recon, SQLi (error/union/blind/time), LFI + PHP wrappers, SSTI (Jinja2/Twig/FreeMarker RCE), SSRF (AWS/GCP meta), CMD injection, IP header bypass, dir fuzz, JWT decode/none-alg forge/secret crack, GraphQL introspect, .git leak |