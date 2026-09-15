# CTF-Y

**An experimental LLM-assisted toolkit for Capture The Flag challenges.**

Connects Claude or Gemini to Python tools for web challenges, cryptography, and digital forensics. A bounded reasoning loop classifies the challenge, selects tools, and uses their output to choose the next action.

## Architecture

| Component | Code |
| --- | --- |
| Classification and tool-selection loop | [classifier.py](classifier.py) · [agent.py](agent.py) |
| Model providers and retries | [providers.py](providers.py) |
| Challenge tools | [Web](modules/web.py) · [Crypto](modules/crypto.py) · [Forensics](modules/forensics.py) |
| Flag extraction and subprocess execution | [tools/flag.py](tools/flag.py) · [tools/runner.py](tools/runner.py) |

## Quick start

Linux environment; requires an API key for the selected provider.

```bash
git clone https://github.com/sai161812/CTF-Y.git
cd CTF-Y
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export CTF_PROVIDER=anthropic
export ANTHROPIC_API_KEY="your-api-key"
python agent.py
```

For Gemini, set `CTF_PROVIDER=gemini` and `GEMINI_API_KEY`. Check model availability and adjust model identifiers, timeouts, step limits, and flag patterns in [config.py](config.py).

Some forensic tools require optional dependencies:

```bash
sudo apt install binwalk steghide exiftool tshark fcrackzip sox
gem install zsteg
```

To inspect a local challenge file:

```bash
python agent.py --desc "Find the flag in this challenge image" --file challenge.png
```

## Status and boundaries

Prototype with manual challenge testing; no published benchmark. Returned flags are candidates and require verification with the challenge platform.

Use authorized CTF targets and labs. The agent runs local tools without sandbox isolation and sends challenge context and tool output to the selected model provider.

[Evaluation notes, limitations, contribution, and Python API](docs/EVALUATION.md)
