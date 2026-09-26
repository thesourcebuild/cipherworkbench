import type { HTMLAttributes } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { cn } from "./cn";

export interface MarkdownProps extends HTMLAttributes<HTMLDivElement> {
  value: string;
}

export function Markdown({ value, className, ...props }: MarkdownProps) {
  return (
    <div
      className={cn(
        "max-h-96 overflow-auto rounded-md border border-slate-200 bg-slate-50 px-4 py-3 text-xs leading-relaxed text-slate-700 [&_pre_code]:rounded-none [&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_pre_code]:text-slate-100 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300",
        className,
      )}
      {...props}
    >
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        skipHtml
        components={{
          h1: ({ children }) => (
            <h1 className="mb-3 mt-1 text-lg font-bold text-slate-950 dark:text-slate-50">
              {children}
            </h1>
          ),
          h2: ({ children }) => (
            <h2 className="mb-2 mt-4 text-base font-bold text-slate-950 dark:text-slate-50">
              {children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3 className="mb-2 mt-4 text-sm font-semibold text-slate-950 first:mt-0 dark:text-slate-50">
              {children}
            </h3>
          ),
          h4: ({ children }) => (
            <h4 className="mb-1.5 mt-3 text-xs font-semibold text-slate-900 dark:text-slate-100">
              {children}
            </h4>
          ),
          p: ({ children }) => <p className="my-2">{children}</p>,
          strong: ({ children }) => (
            <strong className="font-semibold text-slate-950 dark:text-slate-50">
              {children}
            </strong>
          ),
          ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5">{children}</ul>,
          ol: ({ children }) => (
            <ol className="my-2 list-decimal space-y-1 pl-5">{children}</ol>
          ),
          blockquote: ({ children }) => (
            <blockquote className="my-3 border-l-2 border-indigo-400 pl-3 text-slate-600 dark:text-slate-400">
              {children}
            </blockquote>
          ),
          a: ({ children, href }) => (
            <a
              href={href}
              target="_blank"
              rel="noreferrer"
              className="font-medium text-indigo-600 underline decoration-indigo-300 underline-offset-2 dark:text-indigo-400"
            >
              {children}
            </a>
          ),
          code: ({ children, className: codeClassName }) => (
            <code
              className={`${codeClassName ?? ""} rounded bg-slate-200 px-1 py-0.5 font-mono text-[11px] text-slate-900 dark:bg-slate-800 dark:text-slate-100`}
            >
              {children}
            </code>
          ),
          pre: ({ children }) => (
            <pre className="my-3 overflow-x-auto rounded-md border border-slate-800 bg-slate-900 p-3 font-mono text-[11px] leading-relaxed text-slate-100">
              {children}
            </pre>
          ),
          table: ({ children }) => (
            <div className="my-3 overflow-x-auto">
              <table className="w-full border-collapse text-left text-[11px]">{children}</table>
            </div>
          ),
          th: ({ children }) => (
            <th className="border border-slate-300 bg-slate-100 px-2 py-1.5 font-semibold dark:border-slate-700 dark:bg-slate-900">
              {children}
            </th>
          ),
          td: ({ children }) => (
            <td className="border border-slate-300 px-2 py-1.5 align-top dark:border-slate-700">
              {children}
            </td>
          ),
          hr: () => <hr className="my-4 border-slate-300 dark:border-slate-700" />,
        }}
      >
        {value}
      </ReactMarkdown>
    </div>
  );
}

export default Markdown;
