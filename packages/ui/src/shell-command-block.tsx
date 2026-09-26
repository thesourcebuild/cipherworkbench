"use client";

import { useState } from "react";
import { CopyButton } from "./copy-button";
import {
  formatShellCommands,
  type CommandLayout,
  type CommandShell,
  type ShellCommandVariants,
} from "./shell-command";

export interface ShellCommandBlockProps {
  title: string;
  commands: ShellCommandVariants;
  defaultShell?: CommandShell;
  defaultLayout?: CommandLayout;
}

const SHELL_LABEL: Record<CommandShell, string> = {
  bash: "Bash / zsh",
  powershell: "PowerShell",
  cmd: "Command Prompt",
};

const SHELLS = Object.keys(SHELL_LABEL) as CommandShell[];

/** A copyable command preview that can be rendered for the user's current shell. */
export function ShellCommandBlock({
  title,
  commands,
  defaultShell = "bash",
  defaultLayout = "multiline",
}: ShellCommandBlockProps) {
  const [shell, setShell] = useState<CommandShell>(defaultShell);
  const [layout, setLayout] = useState<CommandLayout>(defaultLayout);
  const value = formatShellCommands(commands, shell, layout);

  return (
    <div className="rounded-lg border border-slate-200 bg-slate-900 p-3 font-mono text-xs text-slate-100 dark:border-slate-800">
      <div className="mb-1.5 flex flex-wrap items-center gap-1.5 border-b border-slate-800 pb-1.5 font-sans text-[11px] font-medium text-slate-400">
        <span className="mr-auto min-w-40">{title}</span>
        <select
          aria-label={`${title} shell`}
          value={shell}
          onChange={(event) => setShell(event.target.value as CommandShell)}
          className="rounded border border-slate-700 bg-slate-800 px-1.5 py-1 text-[10px] text-slate-200"
        >
          {SHELLS.map((option) => (
            <option key={option} value={option}>
              {SHELL_LABEL[option]}
            </option>
          ))}
        </select>
        <select
          aria-label={`${title} layout`}
          value={layout}
          onChange={(event) => setLayout(event.target.value as CommandLayout)}
          className="rounded border border-slate-700 bg-slate-800 px-1.5 py-1 text-[10px] text-slate-200"
        >
          <option value="multiline">Multi-line</option>
          <option value="single-line">Single line</option>
        </select>
        <CopyButton
          value={value}
          size="sm"
          className="h-7 border-slate-700 bg-slate-800 px-2 text-[10px] text-slate-200 hover:bg-slate-700"
        />
      </div>
      <pre className="overflow-x-auto whitespace-pre-wrap">{value}</pre>
    </div>
  );
}
