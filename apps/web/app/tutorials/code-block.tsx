"use client";

import { useState, type ReactNode, isValidElement } from "react";

interface CodeBlockProps {
  children?: ReactNode;
}

function extractText(node: ReactNode): string {
  if (typeof node === "string") return node;
  if (typeof node === "number") return String(node);
  if (!node) return "";
  if (Array.isArray(node)) return node.map(extractText).join("");
  if (isValidElement(node) && node.props && typeof node.props === "object") {
    const props = node.props as { children?: ReactNode };
    return extractText(props.children);
  }
  return "";
}

function extractLanguage(children: ReactNode): string {
  const node = Array.isArray(children) ? children[0] : children;
  if (isValidElement(node) && node.props && typeof node.props === "object") {
    const props = node.props as { className?: string };
    if (props.className) {
      const match = props.className.match(/language-(\w+)/);
      if (match && match[1]) return match[1];
    }
  }
  return "text";
}

const LANGUAGE_LABELS: Record<string, string> = {
  powershell: "PowerShell",
  bash: "Bash / Shell",
  sh: "Shell",
  python: "Python",
  ini: "Config / INI",
  json: "JSON",
  yaml: "YAML",
  text: "Code",
};

export function CodeBlock({ children }: CodeBlockProps) {
  const [copied, setCopied] = useState(false);
  const rawCode = extractText(children).trim();
  const langKey = extractLanguage(children).toLowerCase();
  const displayLang = LANGUAGE_LABELS[langKey] || langKey.toUpperCase();

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(rawCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  const lines = rawCode.split("\n");

  return (
    <div className="group relative my-6 overflow-hidden rounded-xl border border-slate-800 bg-[#0d1117] shadow-xl">
      {/* Header Bar */}
      <div className="flex items-center justify-between border-b border-slate-800/90 bg-[#161b22] px-4 py-2.5 text-xs">
        <div className="flex items-center gap-2.5">
          {/* Subtle terminal dots */}
          <div className="flex items-center gap-1.5 opacity-70">
            <span className="h-2.5 w-2.5 rounded-full bg-rose-500/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80" />
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80" />
          </div>
          <span className="ml-2 font-mono text-[11px] font-semibold tracking-wider text-slate-300 uppercase">
            {displayLang}
          </span>
        </div>

        {/* Copy Button */}
        <button
          type="button"
          onClick={handleCopy}
          aria-label={copied ? "Copied code" : "Copy code"}
          className={`flex items-center gap-1.5 rounded-md px-2.5 py-1 font-mono text-[11px] font-medium transition-all ${
            copied
              ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/40"
              : "border border-slate-700/60 bg-slate-800/70 text-slate-200 hover:border-slate-500 hover:bg-slate-700 hover:text-white"
          }`}
        >
          {copied ? (
            <>
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 20 20"
                fill="currentColor"
                className="h-3.5 w-3.5 text-emerald-400"
              >
                <path
                  fillRule="evenodd"
                  d="M16.704 4.153a.75.75 0 0 1 .143 1.052l-8 10.5a.75.75 0 0 1-1.127.075l-4.5-4.5a.75.75 0 0 1 1.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 0 1 1.05-.143Z"
                  clipRule="evenodd"
                />
              </svg>
              <span>Copied!</span>
            </>
          ) : (
            <>
              <svg
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 20 20"
                fill="currentColor"
                className="h-3.5 w-3.5 text-slate-400"
              >
                <path d="M7 3.5A1.5 1.5 0 0 1 8.5 2h3.879a1.5 1.5 0 0 1 1.06.44l3.122 3.12a1.5 1.5 0 0 1 .439 1.061V16.5A1.5 1.5 0 0 1 15.5 18h-7A1.5 1.5 0 0 1 7 16.5v-13Z" />
                <path d="M4.5 6A1.5 1.5 0 0 0 3 7.5v11A1.5 1.5 0 0 0 4.5 20h7a1.5 1.5 0 0 0 1.5-1.5v-1h-2v1h-6.5v-10h1v-2h-1Z" />
              </svg>
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      {/* Code Area with High-Contrast Crisp Text & High-Visibility Selection */}
      <div className="overflow-x-auto p-4 font-mono text-[13px] leading-relaxed selection:bg-blue-600 selection:text-white [&_*]:selection:bg-blue-600 [&_*]:selection:text-white">
        <div className="table w-full border-collapse">
          {lines.map((line, idx) => {
            const trimmed = line.trim();
            const isComment = trimmed.startsWith("#") || trimmed.startsWith("//");
            return (
              <div key={idx} className="table-row">
                <span className="table-cell w-10 select-none pr-4 text-right font-mono text-xs text-slate-600">
                  {idx + 1}
                </span>
                <span
                  className={`table-cell whitespace-pre font-mono text-[13px] leading-6 selection:bg-blue-600 selection:text-white ${
                    isComment
                      ? "text-slate-400 italic"
                      : "text-slate-100 font-normal"
                  }`}
                >
                  {line || "\u00A0"}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
