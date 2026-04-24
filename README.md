# 🚩 CTF Solver Agent

AI-powered end-to-end CTF solver. Claude or Gemini as the brain.

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
GEMINI_MODEL  = "gemini-1.5-pro"  # or "gemini-1.5-flash" for speed
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

## 6. Tool coverage

| Category     | What's covered |
|--------------|----------------|
| **Crypto**   | Base64/32/85/hex/binary/decimal, ROT13, Caesar brute, Vigenere + Kasiski keylen, Atbash, XOR single+multi brute, RSA small-e / Wiener / FactorDB, Substitution freq analysis, Morse, Rail fence, Bacon |
| **Forensics**| File type/magic, strings, hexdump, EXIF metadata, binwalk scan+extract, PNG chunk parser, LSB stego, zsteg, steghide, bit-plane extract, WAV LSB, spectrogram, PCAP HTTP+strings, ZIP listing+crack |
| **Web**      | Full recon, SQLi (error/union/blind/time), LFI + PHP wrappers, SSTI (Jinja2/Twig/FreeMarker RCE), SSRF (AWS/GCP meta), CMD injection, IP header bypass, dir fuzz, JWT decode/none-alg forge/secret crack, GraphQL introspect, .git leak |