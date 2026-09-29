"use client";

import { useState } from "react";
import { CopyButton } from "./copy-button";
import {
  formatShellCommands,
  type CliTool,
  type CommandLayout,
  type CommandShell,
  type ShellCommandVariants,
} from "./shell-command";

export interface ShellCommandBlockProps {
  title: string;
  commands: ShellCommandVariants;
  sslxCommands?: ShellCommandVariants;
  defaultTool?: CliTool;
  defaultShell?: CommandShell;
  defaultLayout?: CommandLayout;
}

const SHELL_LABEL: Record<CommandShell, string> = {
  bash: "Bash / zsh",
  powershell: "PowerShell",
  cmd: "Command Prompt",
};

const SHELLS: CommandShell[] = ["bash", "powershell", "cmd"];

/** A copyable command preview that can be rendered for the user's current shell. */
export function ShellCommandBlock({
  title,
  commands,
  sslxCommands,
  defaultTool = "openssl",
  defaultShell = "bash",
  defaultLayout = "multiline",
}: ShellCommandBlockProps) {
  const hasSslx = Boolean(sslxCommands);
  const [tool, setTool] = useState<CliTool>(defaultTool);
  const [shell, setShell] = useState<CommandShell>(defaultShell);
  const [layout, setLayout] = useState<CommandLayout>(defaultLayout);

  const activeCommands = (tool === "sslx" && sslxCommands) ? sslxCommands : commands;
  const value = formatShellCommands(activeCommands, shell, layout);

  return (
    <div className="rounded-lg border border-slate-200 bg-slate-900 p-3 font-mono text-xs text-slate-100 dark:border-slate-800">
      <div className="mb-1.5 flex flex-wrap items-center gap-1.5 border-b border-slate-800 pb-1.5 font-sans text-[11px] font-medium text-slate-400">
        <span className="mr-auto min-w-40">{title}</span>
        {hasSslx && (
          <select
            aria-label={`${title} tool`}
            value={tool}
            onChange={(event) => setTool(event.target.value as CliTool)}
            className="rounded border border-indigo-500/50 bg-indigo-950/60 px-2 py-1 text-[10px] font-semibold text-indigo-200"
          >
            <option value="openssl">OpenSSL</option>
            <option value="sslx">sslx</option>
          </select>
        )}
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
