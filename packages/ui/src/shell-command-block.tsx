"use client";

import { useState } from "react";
import { CopyButton } from "./copy-button";
import {
  formatShellCommands,
  formatCodeExport,
  canWrapShellCommands,
  type CliProviderCommand,
  type CommandLayout,
  type CommandShell,
  type CodeLanguage,
  type CommandExportFormat,
  type ShellCommandVariants,
} from "./shell-command";

export interface ShellCommandBlockProps {
  title: string;
  commands?: ShellCommandVariants;
  sslxCommands?: ShellCommandVariants;
  gnutlsCommands?: ShellCommandVariants;
  providers?: readonly CliProviderCommand[];
  defaultTool?: string;
  defaultShell?: CommandExportFormat;
  defaultLayout?: CommandLayout;
}

const isCodeLanguage = (fmt: CommandExportFormat): fmt is CodeLanguage =>
  fmt === "python" || fmt === "go" || fmt === "rust";

/** A copyable command preview that can be rendered for the user's current shell or language. */
export function ShellCommandBlock({
  title,
  commands,
  sslxCommands,
  gnutlsCommands,
  providers,
  defaultTool,
  defaultShell = "bash",
  defaultLayout = "multiline",
}: ShellCommandBlockProps) {
  const resolvedProviders: readonly CliProviderCommand[] = providers ?? [
    ...(commands ? [{ id: "openssl", label: "OpenSSL", commands }] : []),
    ...(sslxCommands ? [{ id: "sslx", label: "sslx", commands: sslxCommands }] : []),
    ...(gnutlsCommands ? [{ id: "gnutls", label: "GnuTLS (certtool)", commands: gnutlsCommands }] : []),
  ];

  const initialTool = defaultTool ?? resolvedProviders[0]?.id ?? "openssl";
  const [tool, setTool] = useState<string>(initialTool);
  const [shell, setShell] = useState<CommandExportFormat>(defaultShell);
  const [layout, setLayout] = useState<CommandLayout>(defaultLayout);

  const activeProvider = resolvedProviders.find((p) => p.id === tool) ?? resolvedProviders[0];
  const activeCommands = activeProvider?.commands ?? [];
  const inCodeMode = isCodeLanguage(shell);
  const canWrap = !inCodeMode && canWrapShellCommands(activeCommands, shell as CommandShell);
  const value = inCodeMode
    ? formatCodeExport(activeCommands, shell, activeProvider?.snippets?.[shell])
    : formatShellCommands(activeCommands, shell as CommandShell, canWrap ? layout : "single-line");

  return (
    <div className="rounded-lg border border-slate-200 bg-slate-900 p-3 font-mono text-xs text-slate-100 dark:border-slate-800">
      <div className="mb-1.5 flex flex-wrap items-center gap-1.5 border-b border-slate-800 pb-1.5 font-sans text-[11px] font-medium text-slate-400">
        <span className="mr-auto min-w-40">{title}</span>
        {resolvedProviders.length > 1 ? (
          <select
            aria-label={`${title} tool`}
            value={activeProvider?.id ?? tool}
            onChange={(event) => setTool(event.target.value)}
            className="rounded border border-indigo-500/50 bg-indigo-950/60 px-2 py-1 text-[10px] font-semibold text-indigo-200"
          >
            {resolvedProviders.map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        ) : resolvedProviders.length === 1 && resolvedProviders[0] ? (
          <span className="rounded border border-indigo-500/40 bg-indigo-950/50 px-2 py-0.5 text-[10px] font-semibold text-indigo-300">
            {resolvedProviders[0].label}
          </span>
        ) : null}
        <select
          aria-label={`${title} shell`}
          value={shell}
          onChange={(event) => setShell(event.target.value as CommandExportFormat)}
          className="rounded border border-slate-700 bg-slate-800 px-1.5 py-1 text-[10px] text-slate-200"
        >
          <optgroup label="Shell">
            <option value="bash">Bash / zsh</option>
            <option value="powershell">PowerShell</option>
            <option value="cmd">Command Prompt</option>
          </optgroup>
          <optgroup label="Code Export">
            <option value="python">Python</option>
            <option value="go">Go</option>
            <option value="rust">Rust</option>
          </optgroup>
        </select>
        {canWrap && (
          <select
            aria-label={`${title} layout`}
            value={layout}
            onChange={(event) => setLayout(event.target.value as CommandLayout)}
            className="rounded border border-slate-700 bg-slate-800 px-1.5 py-1 text-[10px] text-slate-200"
          >
            <option value="multiline">Multi-line</option>
            <option value="single-line">Single line</option>
          </select>
        )}
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
