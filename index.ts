import type { ExtensionAPI } from "@oh-my-pi/pi-coding-agent";
import * as path from "node:path";

export default function (pi: ExtensionAPI) {
  pi.setLabel("OMP Safeguard");

  // Destructive bash commands (Fast Layer 1: 0 tokens)
  const DANGEROUS_COMMANDS: Array<{ test: RegExp; message: string }> = [
    {
      test: /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+([/~]|\.\.|\*)/,
      message: "Refused recursive deletion of root, home, parent, or wildcard paths.",
    },
    {
      test: /\b(mkfs|dd\s+if=|fdisk|parted)\b/,
      message: "Refused direct disk/partition manipulation.",
    },
    {
      test: /\b(sudo|doas|su\s+-?)\b/,
      message: "Refused privilege escalation. Commands must run unprivileged.",
    },
    {
      test: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
      message: "Refused fork-bomb pattern.",
    },
    {
      test: /\bgit\s+push\s+.*(-f|--force).*(main|master|prod)/,
      message: "Refused force push to protected branches.",
    },
    {
      test: /\b(cat|head|tail|less|more|grep)\s+.*(\.ssh\/|\.aws\/credentials|\.gnupg\/|\.env\.production)/,
      message: "Refused reading host credentials or private keys.",
    },
    // System and global package managers (covers flag ordering: npm -g i, npm i -g)
    {
      test: /\b(brew\s+(install|uninstall|upgrade|tap|reinstall)|apt|apt-get|yum|dnf|pacman)\b/,
      message: "Refused system package manager mutation (brew/apt/yum).",
    },
    {
      test: /\b(npm|pnpm|bun)\s+.*(-g|--global)\b|\byarn\s+global\s+add\b/,
      message: "Refused global npm/pnpm/yarn package installation.",
    },
    {
      test: /\b(pip|pip3)\s+install\b/,
      message: "Refused pip package installation.",
    },
  ];

  // Critical files that should never be written or edited
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

  pi.on("tool_call", async (event, ctx) => {
    const cwd = ctx.cwd;

    // 1. Guard File Write & Edit operations (Workspace Jail)
    if (event.toolName === "write" || event.toolName === "edit") {
      const rawPath = (event.input as { path?: string })?.path;
      if (typeof rawPath === "string") {
        const targetPath = path.isAbsolute(rawPath) ? path.normalize(rawPath) : path.resolve(cwd, rawPath);

        // Block writing outside project root
        if (!targetPath.startsWith(cwd)) {
          return {
            block: true,
            reason: `Safeguard: Path "${rawPath}" is outside project workspace (${cwd}).`,
          };
        }

        // Block modifying sensitive system or shell files
        for (const pattern of FORBIDDEN_FILE_PATTERNS) {
          if (pattern.test(targetPath)) {
            return {
              block: true,
              reason: `Safeguard: Modifying "${rawPath}" is blocked by security policy.`,
            };
          }
        }
      }
    }

    // 2. Guard Shell Commands (bash)
    if (event.toolName === "bash") {
      const command = (event.input as { command?: string })?.command;
      if (typeof command === "string") {
        // Step A: Fast regex check (0 tokens, immediate)
        for (const { test, message } of DANGEROUS_COMMANDS) {
          if (test.test(command)) {
            return {
              block: true,
              reason: `Safeguard: ${message}`,
            };
          }
        }

        // Step B: System One / Judge model check (only if user enabled it)
        const judgeActive =
          process.env.OMP_SAFEGUARD_JUDGE === "1" ||
          !!process.env.TYPESAFE_API_KEY;

        if (judgeActive && typeof ctx.runEphemeralTurn === "function") {
          try {
            const { replyText } = await ctx.runEphemeralTurn({
              promptText: `SECURITY CHECK: Is this bash command safe to run in a dev project without harming the host system or modifying files outside current directory?\nCommand: ${command}\nAnswer ONLY "SAFE" or "BLOCKED: <short reason>".`,
              tools: false,
              maxTokens: 30,
            });

            if (replyText && /BLOCKED:/i.test(replyText)) {
              const reason = replyText.replace(/^.*BLOCKED:\s*/i, "").trim();
              return {
                block: true,
                reason: `Safeguard (Judge): ${reason}`,
              };
            }
          } catch {
            // Fail open if judge is unreachable to avoid blocking normal dev workflow
          }
        }
      }
    }

    return undefined;
  });
}
