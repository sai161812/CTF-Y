# Evaluation notes

## Current evidence

The maintainer reports manually trying challenges and verifying accepted flags. A reproducible benchmark has not yet been published. The repository currently contains no automated test suite.

## Implementation limits

- A regex match or model-provided flag is a candidate, not confirmation of challenge acceptance. CLI exit code zero does not independently establish a solve.
- Tool names are checked against a registry; arguments do not have a comprehensive schema-validation layer.
- Avoiding repeated tool calls is a prompt instruction rather than an enforced loop guard.
- Optional CLI dependencies and provider/model availability affect which paths work.

## Reproducible evaluation plan

For every attempt, record:

| Field | What to capture |
| --- | --- |
| Version | Git commit and dependency versions |
| Model | Provider, model identifier, and generation settings |
| Configuration | Step limit, timeouts, and flag patterns |
| Challenge | Source, identifier, category, and authorized environment |
| Outcome | Platform-accepted flag, failure, or timeout |
| Execution | Tool-call count, elapsed time, and recorded usage/cost when available |
| Failure analysis | Incorrect candidate, unavailable tool, API error, repeated action, or other cause |

Include failed attempts. Compare the agent against the same model without tools on the same challenges under a stated budget, and report repeated-run variability. Do not publish solve-rate or efficiency claims before collecting results.

## Python API

```python
from agent import solve

result = solve(
    description="Find the flag in this challenge image",
    files=["challenge.png"],
    category="forensics",
)
print(result["flag"])  # Verify the candidate with the challenge platform.
```

## Contribution

Built with substantial AI assistance. Sai's work includes integration, debugging, and manual challenge testing.
