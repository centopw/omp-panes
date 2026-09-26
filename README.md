# omp-panes

A native `omp` plugin that **spawns visible subagents into Zellij & tmux panes**, each with an **enforced tool-capability whitelist**.

![Demo](demo.gif)

## Features

### 1. Visible worker panes (`spawn_worker` tool)

The lead orchestrator spawns subagents into real terminal panes instead of hidden background jobs:

- **Auto-detects** Zellij (`ZELLIJ`) or tmux (`TMUX`).
- **Configurable layout**: split `right`, split `down`, or `floating` (Zellij only).
- **Watch in real time**: workers render next to you; you can read, steer, or kill any of them.

### 2. Per-worker capability whitelist

Every worker is spawned with a **policy** — a preset set of capabilities. `spawn_worker` forwards the policy into the worker process through `OMP_PANES_WORKER_ID` / `OMP_PANES_POLICY` / `OMP_PANES_CAPS`, so the same plugin file running inside the worker enforces it.

| Capability | Grants tools |
| --- | --- |
| `read` | `read`, `grep`, `glob`, `lsp` |
| `write` | `write`, `edit` |
| `shell` | `bash` |
| `network` | `web_search`, `browser` |
| `python` | `python`, `notebook` |
| `task` | `task` (nested subagents) |
| `plan` | `todo`, `ask` |
| `install` | *(permission only)* project-local package installs |

Preset policies:

| `toolPolicy` | Capabilities | Use for |
| --- | --- | --- |
| `readonly` | read, network, plan | Reviewers, researchers, read-only auditors |
| `readonly_shell` | + shell | Investigators that may run commands but not mutate |
| `edit` | read, network, plan, write | Doc/code writers with no shell |
| `edit_shell` *(default)* | read, network, plan, write, shell | Ordinary implementation workers |
| `no_install` | + python, task | Full workspace access, no dependency changes |
| `full` | all (includes `install`) | Unrestricted — may add project-local dependencies |

### 3. Automatic denial + orchestrator notification

If a worker attempts a tool or command outside its whitelist:

1. The call is **blocked before execution** — the worker sees `Safeguard: Tool "write" is not granted by policy "readonly" …`.
2. The attempt is appended to a shared audit log at `~/.omp/agent/panes/violations.jsonl` (override with `OMP_PANES_VIOLATION_LOG`).
3. The orchestrator is **notified automatically** — a `omp-panes security notice` message names the worker, its policy, the denied tool/command, and the reason. The operator also gets a UI toast.
4. The orchestrator can pull the full history with the `worker_violations` tool.

### 4. Baseline safeguards (active in every pane, zero token cost)

Local regex/path checks that run before any tool executes:

- Blocks `rm -rf /`, `mkfs`/`dd`/`fdisk`, `sudo`/`doas`, fork bombs, force-pushes to `main`/`master`/`prod`, and reads of `.ssh`/`.aws`/`.gnupg`/`.env.production`.
- Blocks system package managers (`brew`, `apt`, `yum`, `dnf`, `pacman`) and global installs (`npm -g`, `yarn global add`) unconditionally.
- **Workspace jail**: blocks `write`/`edit` outside the current project directory, plus `.git/config`, `.git/hooks`, and shell rc files.
- **Optional AI judge**: set `export OMP_SAFEGUARD_JUDGE=1` to route ambiguous `bash` commands through `runEphemeralTurn` (fails open).

## Installation

```bash
omp plugin install https://github.com/centopw/omp-panes.git
```

Or link a local checkout:

```bash
omp plugin link ./omp-panes
```

## Usage

Start `omp` inside Zellij or tmux:

```bash
zellij   # or: tmux
omp
```

Then talk to the orchestrator:

> *"Spawn a `readonly` worker to audit the auth module for injection bugs."*

> *"Spawn a worker named Tests with policy `edit_shell` to add unit tests for `src/auth.ts`."*

The orchestrator calls `spawn_worker` and a visible pane opens running `omp` under that policy.

## `spawn_worker` parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `name` | string | — | Pane title / worker name |
| `prompt` | string | — | Instructions for the subagent |
| `direction` | `"right"` \| `"down"` | `"right"` | Split direction |
| `floating` | boolean | `false` | Floating pane (Zellij only) |
| `toolPolicy` | policy name \| `"custom"` | `"edit_shell"` | Capability preset |
| `capabilities` | capability[] | — | Used when `toolPolicy: "custom"` |
| `hardStrip` | boolean | `false` | Also remove disallowed tools from the worker's tool catalog (`--tools`). Saves tokens, but tool-level attempts are then rejected silently by the runtime instead of being logged and reported. |

## Worker environment variables

Set automatically by `spawn_worker`; useful when launching a worker by hand:

| Variable | Meaning |
| --- | --- |
| `OMP_PANES_WORKER_ID` | Non-empty marks this process as a restricted worker |
| `OMP_PANES_WORKER_NAME` | Display name |
| `OMP_PANES_POLICY` | Policy name (for reporting) |
| `OMP_PANES_CAPS` | Comma-separated granted capabilities |
| `OMP_PANES_VIOLATION_LOG` | Audit log path |
