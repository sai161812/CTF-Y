# CTF-Y

**An experimental LLM-assisted toolkit for Capture The Flag challenges.**

CTF-Y connects Claude or Gemini to Python tools for web challenges, cryptography, and digital forensics. It classifies a challenge, selects tools, and feeds their output back into a bounded reasoning loop.

The project explores how model-guided tool selection can assist CTF investigation. It is a prototype; tool coverage is not a measured solve rate.

## How it works

1. `classifier.py` proposes a category and initial steps.
2. `agent.py` builds context from the challenge, recent actions, and tool output.
3. The model returns a JSON tool selection; `execute_tool()` dispatches a registered function.
4. Output is checked for candidate flags and passed into the next iteration.
5. The loop stops on a candidate flag, a model stop decision, an API failure, or `MAX_STEPS`.

| Component | Implementation |
| --- | --- |
| Classification and orchestration | [classifier.py](classifier.py), [agent.py](agent.py) |
| Claude/Gemini requests and rate-limit retries | [providers.py](providers.py) |
| Encoding and cryptography helpers | [modules/crypto.py](modules/crypto.py) |
| File, image, audio, and capture analysis | [modules/forensics.py](modules/forensics.py) |
| HTTP reconnaissance and web challenge helpers | [modules/web.py](modules/web.py) |
| Candidate-flag extraction and scoring | [tools/flag.py](tools/flag.py) |
| External command execution | [tools/runner.py](tools/runner.py) |

## Setup

The commands below target a Linux environment. Some forensic operations require separately installed command-line tools.

```bash
git clone https://github.com/sai161812/CTF-Y.git
cd CTF-Y
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Install the optional tools needed for your challenges:

```bash
sudo apt install binwalk steghide exiftool tshark fcrackzip sox
gem install zsteg
```

Choose a provider and supply its API key through the environment:

```bash
export CTF_PROVIDER=anthropic
export ANTHROPIC_API_KEY="your-api-key"
# Alternatively:
# export CTF_PROVIDER=gemini
# export GEMINI_API_KEY="your-api-key"
```

Model identifiers, step limits, timeouts, and flag patterns are configured in [config.py](config.py). Check that the configured model is available to your provider account before running. Provider access and usage costs depend on your account.

## Run

```bash
# Interactive prompts
python agent.py

# A challenge description and local file
python agent.py --desc "Find the flag in this challenge image" --file challenge.png

# A web challenge hosted in your own local lab
python agent.py --desc "Find the flag in my local lab" --url http://127.0.0.1:8000 --category web
```

Python API:

```python
from agent import solve

result = solve(
    description="Find the flag in this challenge image",
    files=["challenge.png"],
    category="forensics",
)
print(result["flag"])  # Candidate flag; verify with the challenge platform.
```

## Execution boundaries

Use only with CTF targets and labs you are authorized to test. The agent can make network requests and invoke local tools; the subprocess wrapper is not a sandbox.

Challenge descriptions, recent action history, and tool output are sent to the configured external model provider. Use a disposable lab environment and avoid supplying private files or credentials as challenge material.

## Current validation and limitations

- The maintainer has manually tried challenges and verified accepted flags. A reproducible benchmark with challenge identifiers, failed attempts, and provider settings has not yet been published.
- A regex match or model-provided flag is only a candidate. The agent does not confirm acceptance with the challenge platform; CLI exit code zero is not proof of a solve.
- Tool names are checked against a registry, but arguments do not have a comprehensive schema-validation layer.
- Avoiding repeated tool calls is requested in the prompt, rather than enforced by a dedicated loop guard.
- Optional CLI dependencies and provider/model availability affect which paths work.
- This repository currently has no committed automated test suite.

## Evaluation to add

Record the commit, model, configuration, challenge source/category, candidate flag acceptance, tool-call count, elapsed time, and failure reason for every attempt. Include failed attempts and compare against the same model without tools before making performance claims.

## Contribution

Built with substantial AI assistance. Sai's work includes integration, debugging, and manual challenge testing.
