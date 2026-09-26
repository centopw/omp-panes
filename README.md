# omp-safeguard

Deterministic safety guardrails for `omp`.

- **Layer 1 (Fast & 0 tokens):** Local regex checks block `rm -rf /`, `sudo`, disk formats, global package managers (`npm -g`, `pip`, `brew`), and credential reads.
- **Layer 2 (Workspace jail):** Blocks file writes and edits outside the project directory.
- **Layer 3 (Optional AI Judge):** Uses a fast System One judge model to catch tricky commands if configured.

## Enabling the Judge Model

By default, the plugin uses **0 tokens** (regex only).

To enable the secondary AI judge:
```bash
export OMP_SAFEGUARD_JUDGE=1
# Or configure TypeSafe / System One key
export TYPESAFE_API_KEY="your-key"
```

## Installation

```bash
omp plugin link ./omp-safeguard
```
