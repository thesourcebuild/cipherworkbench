export type CommandShell = "bash" | "powershell" | "cmd";
export type CommandLayout = "multiline" | "single-line";

export interface ShellCommand {
  /** Optional explanation rendered using the selected shell's comment syntax. */
  comment?: string;
  /** One logical command split at the places where a multiline display may wrap. */
  parts: readonly string[];
}

export type ShellCommandVariants =
  readonly ShellCommand[] | Readonly<Partial<Record<CommandShell, readonly ShellCommand[]>>>;

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
