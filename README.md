# omp-safeguard

A native `omp` plugin that **spawns visible subagents into Zellij / tmux panes** and **enforces guardrails** so workers cannot harm your system.

![Demo](demo.gif)

## Features

### 1. Visible Worker Panes (`spawn_worker` tool)
Allows the lead orchestrator to spawn visible subagents into split or floating panes:
- **Auto-detects** Zellij (`ZELLIJ`) or tmux (`TMUX`).
- **Configurable splits**: split `right` (vertical), split `down` (horizontal), or `floating` (Zellij).
- **Watch in real-time**: workers render directly in your terminal, not hidden in the background.

### 2. Built-in Safeguards (Active in all panes)
- **Zero tokens consumed**: instant local checks block `rm -rf /`, `sudo`, disk formats, package manager mutations (`npm -g`, `brew`, `pip`).
- **Workspace jail**: blocks file writes and edits outside the current project directory.
- **Optional AI Judge**: enables System One / fast judge models via `export OMP_SAFEGUARD_JUDGE=1`.

## Installation

```bash
omp plugin install https://github.com/centopw/omp-safeguard.git
```

Or link locally:
```bash
omp plugin link ./omp-safeguard
```

## Usage

Start `omp` inside Zellij or tmux:

```bash
# Inside Zellij
zellij
omp

# Or inside tmux
tmux
omp
```

Then tell the orchestrator:
> *"Spawn a subagent to write unit tests for the auth module."*

The orchestrator will call `spawn_worker` and open a visible pane running `omp` alongside your workspace.
