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
        ? `${COMMENT_PREFIX[shell]} ${command.comment.trim()}\n`
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

