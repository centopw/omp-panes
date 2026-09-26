import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import * as path from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";
import { spawnSync } from "node:child_process";

// ---------------------------------------------------------------------------
// Capability / policy model
// ---------------------------------------------------------------------------

/** Capability -> concrete omp tool names it grants. `install` grants no tool;
 *  it is a permission-only capability checked at the bash command level. */
const CAPABILITY_TOOLS: Record<string, string[]> = {
  read: ["read", "grep", "glob", "lsp"],
  write: ["write", "edit"],
  shell: ["bash"],
  network: ["web_search", "browser"],
  python: ["python", "notebook"],
  task: ["task"],
  plan: ["todo", "ask"],
  install: [],
};

const ALL_CAPABILITIES = Object.keys(CAPABILITY_TOOLS);

/** Named presets the orchestrator can hand to a sub-agent. */
const POLICIES: Record<string, { label: string; capabilities: string[] }> = {
  readonly: { label: "Read-only", capabilities: ["read", "network", "plan"] },
  readonly_shell: { label: "Read-only + shell", capabilities: ["read", "network", "plan", "shell"] },
  edit: { label: "Edit files", capabilities: ["read", "network", "plan", "write"] },
  edit_shell: {
    label: "Edit files + shell",
    capabilities: ["read", "network", "plan", "write", "shell"],
  },
  no_install: {
    label: "Full workspace access (no installs)",
    capabilities: ["read", "network", "plan", "write", "shell", "python", "task"],
  },
  full: { label: "Unrestricted (includes project-local installs)", capabilities: ALL_CAPABILITIES },
};

const DEFAULT_POLICY = "edit_shell";

/** Commands that require the `install` capability (project-local installs). */
const INSTALL_COMMANDS: RegExp[] = [
  /\b(npm|pnpm|bun|yarn)\s+(i|install|add|ci)\b/,
  /\b(pip|pip3)\s+install\b/,
  /\b(brew|apt|apt-get|yum|dnf|pacman)\s+(install|add|upgrade|tap|reinstall)\b/,
  /\b(cargo|go)\s+(install|get)\b/,
  /\bgem\s+install\b/,
];

/** Never allowed, regardless of policy. */
const DANGEROUS_COMMANDS: Array<{ test: RegExp; message: string }> = [
  {
    test: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+([/~]|\.\.|\*)/,
    message: "recursive deletion of root, home, parent, or wildcard paths",
  },
  { test: /\b(mkfs|dd\s+if=|fdisk|parted)\b/, message: "direct disk/partition manipulation" },
  { test: /\b(sudo|doas|su\s+-?)\b/, message: "privilege escalation" },
  { test: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, message: "fork-bomb pattern" },
  { test: /\bgit\s+push\s+.*(-f|--force).*(main|master|prod)/, message: "force push to a protected branch" },
  {
    test: /\b(cat|head|tail|less|more|grep)\s+.*(\.ssh\/|\.aws\/credentials|\.gnupg\/|\.env\.production)/,
    message: "reading host credentials or private keys",
  },
  {
    test: /\b(brew\s+(install|uninstall|upgrade|tap|reinstall)|apt|apt-get|yum|dnf|pacman)\b/,
    message: "system package manager mutation",
  },
  { test: /\b(npm|pnpm|bun)\s+.*(-g|--global)\b|\byarn\s+global\s+add\b/, message: "global package installation" },
];

const FORBIDDEN_FILE_PATTERNS = [
  /\.ssh($|\/)/,
  /\.gnupg($|\/)/,
  /\.aws($|\/)/,
  /\.git\/config$/,
  /\.git\/hooks($|\/)/,
  /\.bashrc$/,
  /\.zshrc$/,
  /\.profile$/,
];

// ---------------------------------------------------------------------------
// Shared worker<->orchestrator state
// ---------------------------------------------------------------------------

const AGENT_DIR = process.env.PI_CODING_AGENT_DIR || path.join(os.homedir(), ".omp", "agent");
const VIOLATION_LOG = process.env.OMP_PANES_VIOLATION_LOG || path.join(AGENT_DIR, "panes", "violations.jsonl");

type Violation = {
  id: string;
  ts: number;
  workerId: string;
  workerName: string;
  policy: string;
  kind: "tool" | "command";
  target: string;
  reason: string;
};

function appendViolation(v: Violation): void {
  try {
    fs.mkdirSync(path.dirname(VIOLATION_LOG), { recursive: true });
    fs.appendFileSync(VIOLATION_LOG, `${JSON.stringify(v)}\n`, "utf8");
  } catch {
    // Never let audit logging break the guard.
  }
}

function readViolations(): Violation[] {
  try {
    if (!fs.existsSync(VIOLATION_LOG)) return [];
    return fs
      .readFileSync(VIOLATION_LOG, "utf8")
      .split("\n")
      .filter(Boolean)
      .flatMap((line) => {
        try {
          return [JSON.parse(line) as Violation];
        } catch {
          return [];
        }
      });
  } catch {
    return [];
  }
}

function resolveCapabilities(policy: string, custom?: string[]): string[] {
  if (policy === "custom") {
    const requested = (custom ?? []).filter((c) => c in CAPABILITY_TOOLS);
    if (requested.length > 0) return requested;
  }
  return (POLICIES[policy] ?? POLICIES[DEFAULT_POLICY]).capabilities;
}

function toolsForCapabilities(capabilities: string[]): string[] {
  const set = new Set<string>();
  for (const cap of capabilities) {
    for (const tool of CAPABILITY_TOOLS[cap] ?? []) set.add(tool);
  }
  return [...set];
}

// ---------------------------------------------------------------------------

export default function (pi: ExtensionAPI) {
  const z = pi.zod;
  pi.setLabel("OMP Panes");

  // --- A worker process identifies itself through this env var -------------
  const workerId = process.env.OMP_PANES_WORKER_ID;
  const isWorker = typeof workerId === "string" && workerId.length > 0;
  const workerName = process.env.OMP_PANES_WORKER_NAME ?? workerId ?? "";
  const workerPolicy = process.env.OMP_PANES_POLICY ?? DEFAULT_POLICY;
  const workerCapabilities = (process.env.OMP_PANES_CAPS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const effectiveCapabilities = isWorker ? workerCapabilities : [];
  const allowedTools = new Set(toolsForCapabilities(effectiveCapabilities));
  const canInstall = effectiveCapabilities.includes("install");

  // --- Orchestrator-side worker registry ----------------------------------
  const activeWorkers = new Map<string, { name: string; policy: string; startedAt: number }>();
  const notifiedViolations = new Set<string>();
  let violationWatcher: unknown = null;

  /**
   * Collects violations from workers spawned in this session that have not
   * been reported yet, marks them notified, and pushes them to the
   * orchestrator (agent context) and the operator (UI toast).
   */
  function drainViolations(ctx: { ui: { notify: (m: string, l?: string) => void } }): Violation[] {
    const pending = readViolations().filter(
      (v) => activeWorkers.has(v.workerId) && !notifiedViolations.has(v.id)
    );
    if (pending.length === 0) return [];

    for (const v of pending) notifiedViolations.add(v.id);

    const lines = pending.map(
      (v) => `[${v.workerName} | ${v.policy}] attempted restricted ${v.kind} "${v.target}" — ${v.reason}`
    );
    const content = [
      `omp-panes security notice: ${pending.length} sub-agent violation(s).`,
      ...lines,
      "Instruct the worker to stay within its assigned capabilities, or re-spawn it with a wider toolPolicy.",
    ].join("\n");

    try {
      pi.sendMessage({ customType: "omp-panes.violation", content, display: content }, { deliverAs: "aside" });
    } catch {
      // Session may be shutting down; the file log remains authoritative.
    }

    ctx.ui.notify(`omp-panes: ${pending.length} restricted access attempt(s) from sub-agent(s)`, "warning");
    return pending;
  }

  /** Poll-based notification, so an idle orchestrator still learns about a violation. */
  function startViolationWatcher(ctx: { ui: { notify: (m: string, l?: string) => void } }): void {
    if (violationWatcher) return;
    const interval = (ctx as unknown as { setInterval?: (fn: () => void, ms: number) => unknown }).setInterval;
    if (typeof interval !== "function") return;
    violationWatcher = interval(() => {
      if (activeWorkers.size > 0) drainViolations(ctx);
    }, 2000);
  }

  // -----------------------------------------------------------------------
  // 1. TOOL: spawn_worker — visible pane + capability whitelist
  // -----------------------------------------------------------------------
  pi.registerTool({
    name: "spawn_worker",
    label: "Spawn Worker Pane",
    description:
      "Spawn a visible subagent in a Zellij or tmux pane with an enforced tool-capability whitelist. The subagent cannot use any tool or command outside its assigned policy; violations are blocked and reported back to you.",
    parameters: z.object({
      name: z.string().describe("Short descriptive name for the pane (e.g. Backend-Worker, Tests)"),
      prompt: z.string().describe("The prompt or instructions for the subagent to execute"),
      direction: z
        .enum(["right", "down"])
        .default("right")
        .describe("Split direction: 'right' (vertical split) or 'down' (horizontal split)"),
      floating: z
        .boolean()
        .default(false)
        .describe("Open as floating pane instead of tiled (Zellij only)"),
      toolPolicy: z
        .enum(["custom", ...Object.keys(POLICIES)] as [string, ...string[]])
        .default(DEFAULT_POLICY)
        .describe(
          `Capability whitelist preset. ${Object.entries(POLICIES)
            .map(([k, v]) => `${k}=${v.capabilities.join("+")}`)
            .join("; ")}. Use "custom" with capabilities to build your own.`
        ),
      capabilities: z
        .array(z.enum(ALL_CAPABILITIES as [string, ...string[]]))
        .optional()
        .describe(`Used when toolPolicy="custom". Available: ${ALL_CAPABILITIES.join(", ")}`),
      hardStrip: z
        .boolean()
        .default(false)
        .describe(
          "Also remove disallowed tool definitions from the subagent's catalog (--tools). Fewer tokens, but tool-level attempts are then rejected silently by the runtime instead of being logged and reported."
        ),
    }),
    async execute(_id, params, _signal, _onUpdate, ctx) {
      const isZellij = typeof process.env.ZELLIJ !== "undefined";
      const isTmux = typeof process.env.TMUX !== "undefined";

      if (!isZellij && !isTmux) {
        return {
          content: [
            {
              type: "text",
              text: "Cannot spawn pane: neither Zellij nor tmux session detected. Start omp inside Zellij or tmux first.",
            },
          ],
          isError: true,
        };
      }

      const policyName = params.toolPolicy ?? DEFAULT_POLICY;
      const capabilities = resolveCapabilities(policyName, params.capabilities);
      const grantedTools = toolsForCapabilities(capabilities);
      const id = `w-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`;

      const envPairs = [
        `OMP_PANES_WORKER_ID=${id}`,
        `OMP_PANES_WORKER_NAME=${params.name}`,
        `OMP_PANES_POLICY=${policyName}`,
        `OMP_PANES_CAPS=${capabilities.join(",")}`,
        `OMP_PANES_VIOLATION_LOG=${VIOLATION_LOG}`,
      ];

      const argv: string[] = ["env", ...envPairs, "omp"];
      if (params.hardStrip) argv.push(`--tools=${grantedTools.join(",")}`);
      argv.push(params.prompt);

      let result: { status: number | null; stderr?: { toString(): string } | null };

      if (isZellij) {
        const args = ["run", "--direction", params.direction, "--name", params.name, "--cwd", ctx.cwd];
        if (params.floating) args.push("--floating");
        args.push("--", ...argv);
        result = spawnSync("zellij", args, { cwd: ctx.cwd, stdio: "pipe" });
      } else {
        const splitFlag = params.direction === "down" ? "-v" : "-h";
        const shellCommand = argv.map((a) => `'${a.replace(/'/g, `'\\''`)}'`).join(" ");
        const tmuxArgs = ["split-window", splitFlag, "-c", ctx.cwd];
        if (params.name) {
          tmuxArgs.push("-P", "-F", "#{pane_id}");
        }
        tmuxArgs.push(shellCommand);
        result = spawnSync("tmux", tmuxArgs, { cwd: ctx.cwd, stdio: "pipe" });
      }

      if (result.status !== 0) {
        const err = result.stderr?.toString() || "Unknown error";
        return {
          content: [{ type: "text", text: `Failed to spawn pane: ${err}` }],
          isError: true,
        };
      }

      activeWorkers.set(id, { name: params.name, policy: policyName, startedAt: Date.now() });
      startViolationWatcher(ctx as never);

      return {
        content: [
          {
            type: "text",
            text: [
              `Spawned visible worker pane "${params.name}" (${params.direction}, ${isZellij ? "Zellij" : "tmux"}).`,
              `Worker ID: ${id}`,
              `Tool policy: ${policyName} — capabilities: ${capabilities.join(", ")}`,
              `Allowed tools: ${grantedTools.join(", ")}${capabilities.includes("install") ? " (+ project-local installs)" : ""}`,
              `Task: "${params.prompt}"`,
              "Any restricted tool or command this worker attempts is denied and reported back to you automatically.",
            ].join("\n"),
          },
        ],
      };
    },
  });

  // -----------------------------------------------------------------------
  // 2. TOOL: worker_violations — pull-based violation report
  // -----------------------------------------------------------------------
  pi.registerTool({
    name: "worker_violations",
    label: "Worker Violations",
    description:
      "List restricted tool or command attempts made by spawned sub-agents. Returns each violation with the worker name, policy, target, and reason.",
    parameters: z.object({
      workerId: z.string().optional().describe("Only report violations from this worker ID"),
      onlyActive: z
        .boolean()
        .default(true)
        .describe("Restrict to workers spawned in this session"),
    }),
    async execute(_id, params) {
      let records = readViolations();
      if (params.onlyActive) records = records.filter((v) => activeWorkers.has(v.workerId));
      if (params.workerId) records = records.filter((v) => v.workerId === params.workerId);

      if (records.length === 0) {
        return { content: [{ type: "text", text: "No worker violations recorded." }] };
      }

      const text = records
        .map(
          (v) =>
            `[${new Date(v.ts).toISOString()}] ${v.workerName} (${v.policy}) blocked ${v.kind} "${v.target}" — ${v.reason}`
        )
        .join("\n");

      return {
        content: [{ type: "text", text: `${records.length} violation(s):\n${text}` }],
        details: { violations: records },
      };
    },
  });

  // -----------------------------------------------------------------------
  // 3. Worker startup banner
  // -----------------------------------------------------------------------
  pi.on("session_start", async (_event, ctx) => {
    if (!isWorker) return;
    ctx.ui.notify(
      `OMP Panes worker "${workerName}" — policy: ${workerPolicy} [${effectiveCapabilities.join(", ")}]`,
      "info"
    );
  });

  // -----------------------------------------------------------------------
  // 3b. Orchestrator-side event-driven drain (covers short-lived sessions
  //     that would never reach a poll tick) and timer cleanup.
  // -----------------------------------------------------------------------
  pi.on("agent_end", async (_event, ctx) => {
    if (isWorker || activeWorkers.size === 0) return;
    drainViolations(ctx);
  });

  pi.on("session_shutdown", (_event, ctx) => {
    if (violationWatcher) {
      const clear = (ctx as unknown as { clearTimer?: (t: unknown) => void }).clearTimer;
      if (typeof clear === "function") clear(violationWatcher);
      violationWatcher = null;
    }
  });

  // -----------------------------------------------------------------------
  // 4. GUARD: deny out-of-policy tools/commands, log, notify
  // -----------------------------------------------------------------------
  pi.on("tool_call", async (event, ctx) => {
    const cwd = ctx.cwd;

    function deny(kind: "tool" | "command", target: string, reason: string) {
      if (isWorker) {
        appendViolation({
          id: `${workerId}:${Date.now()}:${target}`,
          ts: Date.now(),
          workerId: workerId as string,
          workerName,
          policy: workerPolicy,
          kind,
          target,
          reason,
        });
        ctx.ui.notify(`Blocked ${kind}: ${target}`, "warning");
      }
      return { block: true, reason: `Safeguard: ${reason}` };
    }

    // --- Whitelist enforcement (sub-agent only) ---
    if (isWorker && !allowedTools.has(event.toolName)) {
      return deny(
        "tool",
        event.toolName,
        `Tool "${event.toolName}" is not granted by policy "${workerPolicy}" (allowed: ${[...allowedTools].join(", ")}).`
      );
    }

    // --- Workspace jail for writes/edits ---
    if (event.toolName === "write" || event.toolName === "edit") {
      const rawPath = (event.input as { path?: string })?.path;
      if (typeof rawPath === "string") {
        const targetPath = path.isAbsolute(rawPath) ? path.normalize(rawPath) : path.resolve(cwd, rawPath);

        if (!targetPath.startsWith(cwd)) {
          return deny("tool", rawPath, `Path "${rawPath}" is outside the project workspace (${cwd}).`);
        }

        for (const pattern of FORBIDDEN_FILE_PATTERNS) {
          if (pattern.test(targetPath)) {
            return deny("tool", rawPath, `Modifying "${rawPath}" is prohibited by security policy.`);
          }
        }
      }
    }

    // --- Command-level enforcement ---
    if (event.toolName === "bash") {
      const command = (event.input as { command?: string })?.command;
      if (typeof command === "string") {
        for (const { test, message } of DANGEROUS_COMMANDS) {
          if (test.test(command)) {
            return deny("command", command.slice(0, 200), `Refused ${message}.`);
          }
        }

        if (!canInstall) {
          for (const test of INSTALL_COMMANDS) {
            if (test.test(command)) {
              return deny(
                "command",
                command.slice(0, 200),
                `Package installation requires the "install" capability; policy "${workerPolicy}" does not grant it.`
              );
            }
          }
        }

        const judgeActive =
          process.env.OMP_SAFEGUARD_JUDGE === "1" || !!process.env.TYPESAFE_API_KEY;

        if (judgeActive && typeof ctx.runEphemeralTurn === "function") {
          try {
            const { replyText } = await ctx.runEphemeralTurn({
              promptText: `SECURITY CHECK: Is this bash command safe to run in a dev project without harming the host system or modifying files outside the current directory?\nCommand: ${command}\nAnswer ONLY "SAFE" or "BLOCKED: <short reason>".`,
              tools: false,
              maxTokens: 30,
            });

            if (replyText && /BLOCKED:/i.test(replyText)) {
              const reason = replyText.replace(/^.*BLOCKED:\s*/i, "").trim();
              return deny("command", command.slice(0, 200), `Judge: ${reason}`);
            }
          } catch {
            // Fail open when the judge is unreachable.
          }
        }
      }
    }

    return undefined;
  });
}
