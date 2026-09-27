"use client";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { cn } from "@ocs/ui";

export interface TutorialMarkdownProps {
  content: string;
  className?: string;
  inline?: boolean;
}

export function TutorialMarkdown({ content, className, inline = false }: TutorialMarkdownProps) {
  if (inline) {
    return (
      <span className={cn("text-inherit leading-relaxed", className)}>
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          components={{
            p: ({ children }) => <span>{children}</span>,
            strong: ({ children }) => (
              <strong className="font-bold text-inherit underline-offset-2">{children}</strong>
            ),
            em: ({ children }) => <em className="italic text-inherit">{children}</em>,
            code: ({ children }) => (
              <code className="rounded border border-slate-200/80 bg-slate-100/90 px-1 py-0.2 font-mono text-[11px] font-semibold text-indigo-700 dark:border-slate-700/80 dark:bg-slate-800/90 dark:text-indigo-300">
                {children}
              </code>
            ),
          }}
        >
          {content}
        </ReactMarkdown>
      </span>
    );
  }

  return (
    <div className={cn("text-sm text-slate-700 dark:text-slate-300 leading-relaxed", className)}>
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          p: ({ children }) => <p className="mb-2 last:mb-0 leading-relaxed">{children}</p>,
          strong: ({ children }) => (
            <strong className="font-bold text-slate-950 dark:text-white">{children}</strong>
          ),
          em: ({ children }) => (
            <em className="italic text-slate-800 dark:text-slate-200">{children}</em>
          ),
          code: ({ children }) => (
            <code className="rounded border border-slate-200 bg-slate-100 px-1.5 py-0.5 font-mono text-[12px] font-semibold text-indigo-700 dark:border-slate-700 dark:bg-slate-800 dark:text-indigo-300">
              {children}
            </code>
          ),
          ul: ({ children }) => (
            <ul className="my-2 list-disc space-y-1 pl-5 text-slate-700 dark:text-slate-300">
              {children}
            </ul>
          ),
          ol: ({ children }) => (
            <ol className="my-2 list-decimal space-y-1 pl-5 text-slate-700 dark:text-slate-300">
              {children}
            </ol>
          ),
          li: ({ children }) => <li className="leading-relaxed">{children}</li>,
          blockquote: ({ children }) => (
            <blockquote className="my-2 border-l-2 border-indigo-400 pl-3 italic text-slate-600 dark:border-indigo-600 dark:text-slate-400">
              {children}
            </blockquote>
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
