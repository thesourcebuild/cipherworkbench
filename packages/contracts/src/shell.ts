export type CommandShell = "bash" | "powershell" | "cmd";
export type CommandLayout = "multiline" | "single-line";
export type CliTool = string;

export interface ShellCommand {
  /** Optional explanation rendered using the selected shell's comment syntax. */
  comment?: string;
  /** One logical command split at the places where a multiline display may wrap. */
  parts: readonly string[];
}

export type ShellCommandVariants =
  readonly ShellCommand[] | Readonly<Partial<Record<CommandShell, readonly ShellCommand[]>>>;

export interface CliProviderCommand {
  id: string; // e.g. "openssl", "sslx", "gnutls", "coreutils", "python"
  label: string; // e.g. "OpenSSL", "sslx", "GnuTLS (certtool)", "GNU coreutils"
  commands: ShellCommandVariants;
}

const CONTINUATION: Record<CommandShell, string> = {
  bash: "\\",
  powershell: "`",
  cmd: "^",
};

const COMMENT_PREFIX: Record<CommandShell, string> = {
  bash: "#",
  powershell: "#",
  cmd: "REM",
};

function hasSharedCommands(
  variants: ShellCommandVariants,
): variants is readonly ShellCommand[] {
  return Array.isArray(variants);
}

function commandsForShell(
  variants: ShellCommandVariants,
  shell: CommandShell,
): readonly ShellCommand[] {
  if (hasSharedCommands(variants)) return variants;
  return variants[shell] ?? variants.bash ?? variants.powershell ?? variants.cmd ?? [];
}

export function formatShellCommands(
  variants: ShellCommandVariants,
  shell: CommandShell,
  layout: CommandLayout,
): string {
  return commandsForShell(variants, shell)
    .map((command) => {
      const parts = command.parts.map((part) => part.trim()).filter(Boolean);
      const comment = command.comment
        ? command.comment
            .split("\n")
            .map((line) => {
              const trimmed = line.trim();
              return trimmed ? `${COMMENT_PREFIX[shell]} ${trimmed}` : COMMENT_PREFIX[shell];
            })
            .join("\n") + "\n"
        : "";

      if (layout === "single-line" || parts.length < 2) {
        return comment + parts.join(" ");
      }

      const continuation = ` ${CONTINUATION[shell]}`;
      return (
        comment +
        parts
          .map(
            (part, index) =>
              `${index === 0 ? "" : "  "}${part}${index < parts.length - 1 ? continuation : ""}`,
          )
          .join("\n")
      );
    })
    .join("\n\n");
}

/**
 * Formats a byte count into a human-readable size string (e.g. "3.8 KB", "500 B", "12.4 MB").
 */
export function formatByteSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/**
 * Checks whether an input Uint8Array can be cleanly and safely inlined into a single-line shell pipe.
 * Returns the decoded UTF-8 string if it is single-line, contains no control characters,
 * and does not exceed maxLen. Returns undefined if it should be handled via a file instead.
 */
export function getInlineTextSample(input?: Uint8Array, maxLen: number = 256): string | undefined {
  if (!input) return undefined;
  if (input.length === 0) return "";
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(input);
    // Disallow control characters (\x00-\x1F, \x7F) including newlines (\n, \r)
    if (!/[\x00-\x1F\x7F]/.test(decoded) && decoded.length <= maxLen) {
      return decoded;
    }
  } catch {}
  return undefined;
}

export interface InputExclusionInfo {
  note: string;
  defaultFileName: string;
}

/**
 * Generates an informative guidance note and recommended fallback filename
 * when input cannot be inlined into a shell command snippet.
 */
export function describeInputExclusion(input: Uint8Array): InputExclusionInfo {
  const size = formatByteSize(input.length);
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(input);
    if (decoded.includes("\n") || decoded.includes("\r")) {
      return {
        note: `Input is multi-line (${size}) — save to input.txt or use File mode:`,
        defaultFileName: "input.txt",
      };
    }
    if (decoded.length > 256) {
      return {
        note: `Input exceeds inline shell limit (${size}) — save to input.txt or use File mode:`,
        defaultFileName: "input.txt",
      };
    }
  } catch {}
  return {
    note: `Input is binary (${size}) — save to input.bin or use File mode:`,
    defaultFileName: "input.bin",
  };
}

/**
 * Prepends an advisory note to each command comment in a ShellCommandVariants structure.
 */
export function prefixVariantsComment(
  variants: ShellCommandVariants,
  note: string,
): ShellCommandVariants {
  if (Array.isArray(variants)) {
    return variants.map((cmd) => ({
      ...cmd,
      comment: cmd.comment ? `${note}\n${cmd.comment}` : note,
    }));
  }
  const variantRecord = variants as Readonly<Partial<Record<CommandShell, readonly ShellCommand[]>>>;
  const res: Partial<Record<CommandShell, readonly ShellCommand[]>> = {};
  const shells: readonly CommandShell[] = ["bash", "powershell", "cmd"];
  for (const shell of shells) {
    const cmds = variantRecord[shell];
    if (cmds) {
      res[shell] = cmds.map((cmd: ShellCommand) => ({
        ...cmd,
        comment: cmd.comment ? `${note}\n${cmd.comment}` : note,
      }));
    }
  }
  return res;
}

/**
 * Constructs shell command variants for piping input data across Bash, PowerShell, and Command Prompt.
 *
 * Windows Command Prompt and PowerShell require special handling when piping strings
 * to prevent trailing CRLF newlines and pipeline encoding issues:
 * - Bash / zsh:       printf "%s" '<data>' | <tool>
 * - Command Prompt:   <nul set /p ="<data>" | <tool>
 * - PowerShell:       cmd /c '<nul set /p ="<data>" | <tool>'
 */
export function buildPipedShellVariants(
  command: string | Readonly<Record<CommandShell, string>>,
  data?: string,
  comment?: string,
): Readonly<Record<CommandShell, readonly ShellCommand[]>> {
  const getCmd = (shell: CommandShell): string =>
    typeof command === "string" ? command : command[shell];

  if (data === undefined) {
    return {
      bash: [{ ...(comment ? { comment } : {}), parts: [getCmd("bash")] }],
      powershell: [{ ...(comment ? { comment } : {}), parts: [getCmd("powershell")] }],
      cmd: [{ ...(comment ? { comment } : {}), parts: [getCmd("cmd")] }],
    };
  }

  const safeBash = data.replace(/'/g, "'\\''");
  const safeCmd = data.replace(/["^&|<>%]/g, "^$&");
  const safePs = safeCmd.replace(/'/g, "''");

  const bashCmd = getCmd("bash");
  const psCmd = getCmd("powershell");
  const cmdCmd = getCmd("cmd");

  return {
    bash: [
      {
        ...(comment ? { comment } : {}),
        parts: [`printf "%s" '${safeBash}' | ${bashCmd}`],
      },
    ],
    powershell: [
      {
        ...(comment ? { comment } : {}),
        parts: [`cmd /c '<nul set /p ="${safePs}" | ${psCmd}'`],
      },
    ],
    cmd: [
      {
        ...(comment ? { comment } : {}),
        parts: [`<nul set /p ="${safeCmd}" | ${cmdCmd}`],
      },
    ],
  };
}

function quoteFileName(file: string, shell: CommandShell): string {
  if (!/[\s"'$`\\&|<>]/.test(file)) return file;
  if (shell === "cmd") return `"${file.replace(/"/g, '""')}"`;
  if (shell === "powershell") return `"${file.replace(/[`"$]/g, "`$&")}"`;
  return `"${file.replace(/["\\$`]/g, "\\$&")}"`;
}

/**
 * Constructs shell command variants for running a tool against a file path.
 *
 * Quotes the file path if it contains spaces or shell metacharacters.
 * Supports `{file}` template substitution (e.g. for `certutil -hashfile {file} SHA256`).
 */
export function buildFileShellVariants(
  command: string | Readonly<Record<CommandShell, string>>,
  fileName: string = "file.txt",
  comment?: string,
): Readonly<Record<CommandShell, readonly ShellCommand[]>> {
  const getCmd = (shell: CommandShell, fileArg: string): string => {
    const raw = typeof command === "string" ? command : command[shell];
    return raw.includes("{file}") ? raw.replace(/\{file\}/g, fileArg) : `${raw} ${fileArg}`;
  };

  const bashArg = quoteFileName(fileName, "bash");
  const psArg = quoteFileName(fileName, "powershell");
  const cmdArg = quoteFileName(fileName, "cmd");

  return {
    bash: [
      {
        ...(comment ? { comment } : {}),
        parts: [getCmd("bash", bashArg)],
      },
    ],
    powershell: [
      {
        ...(comment ? { comment } : {}),
        parts: [getCmd("powershell", psArg)],
      },
    ],
    cmd: [
      {
        ...(comment ? { comment } : {}),
        parts: [getCmd("cmd", cmdArg)],
      },
    ],
  };
}

