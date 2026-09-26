import Link from "next/link";
import type { ComponentProps, ReactNode } from "react";
import type { MDXComponents } from "mdx/types";
import { CodeBlock } from "./app/guides/code-block";
import {
  GuideCallout,
  GuideReveal,
  StatusBadge,
  TutorialCallout,
  TutorialReveal,
} from "./app/guides/guide-components";

function extractText(node: ReactNode): string {
  if (typeof node === "string") return node;
  if (typeof node === "number") return String(node);
  if (!node) return "";
  if (Array.isArray(node)) return node.map(extractText).join("");
  if (
    typeof node === "object" &&
    "props" in node &&
    (node as { props: { children?: ReactNode } }).props
  ) {
    return extractText((node as { props: { children?: ReactNode } }).props.children);
  }
  return "";
}

function slugify(node: ReactNode): string {
  const text = extractText(node);
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}

function MdxLayout({ children }: { children?: ReactNode }) {
  return (
    <article className="space-y-6 text-slate-800 dark:text-slate-200">
      {children}
    </article>
  );
}

function MdxLink({ href = "#", children, title }: ComponentProps<"a">) {
  const external = typeof href === "string" && /^https?:\/\//.test(href);

  return external ? (
    <a
      href={href}
      title={title}
      target="_blank"
      rel="noreferrer"
      className="font-medium text-indigo-600 underline decoration-indigo-300 underline-offset-4 hover:text-indigo-700 dark:text-indigo-400 dark:decoration-indigo-700 dark:hover:text-indigo-300 transition-colors"
    >
      {children}
    </a>
  ) : (
    <Link
      href={href}
      title={title}
      className="font-medium text-indigo-600 underline decoration-indigo-300 underline-offset-4 hover:text-indigo-700 dark:text-indigo-400 dark:decoration-indigo-700 dark:hover:text-indigo-300 transition-colors"
    >
      {children}
    </Link>
  );
}

const components = {
  wrapper: MdxLayout,
  h1: ({ children }) => (
    <div className="mb-8">
      <span className="inline-flex items-center gap-1.5 rounded-full border border-indigo-200 bg-indigo-50 px-3 py-1 font-mono text-[11px] font-semibold uppercase tracking-wider text-indigo-700 dark:border-indigo-900/60 dark:bg-indigo-950/50 dark:text-indigo-300">
        <span className="h-1.5 w-1.5 rounded-full bg-indigo-500 animate-pulse" />
        PKI Architecture & TLS Guide
      </span>
      <h1 className="mt-3 text-3xl font-extrabold tracking-tight text-slate-900 dark:text-white sm:text-4xl lg:text-5xl leading-tight">
        {children}
      </h1>
    </div>
  ),
  h2: ({ children }) => {
    const slug = slugify(children);
    return (
      <h2
        id={slug}
        className="group mt-12 mb-4 flex items-center justify-between border-b border-slate-200 pb-3 text-2xl font-bold tracking-tight text-slate-900 dark:border-slate-800 dark:text-white scroll-mt-24"
      >
        <span>{children}</span>
        <a
          href={`#${slug}`}
          aria-label={`Link to section: ${extractText(children)}`}
          className="text-slate-400 opacity-0 group-hover:opacity-100 hover:text-indigo-600 dark:hover:text-indigo-400 transition-opacity font-mono font-normal text-lg"
        >
          #
        </a>
      </h2>
    );
  },
  h3: ({ children }) => {
    const slug = slugify(children);
    return (
      <h3
        id={slug}
        className="group mt-8 mb-3 flex items-center justify-between text-lg font-bold text-slate-900 dark:text-white scroll-mt-24"
      >
        <span>{children}</span>
        <a
          href={`#${slug}`}
          aria-label={`Link to subsection: ${extractText(children)}`}
          className="text-xs text-slate-400 opacity-0 group-hover:opacity-100 hover:text-indigo-600 dark:hover:text-indigo-400 transition-opacity font-mono font-normal"
        >
          #
        </a>
      </h3>
    );
  },
  h4: ({ children }) => (
    <h4 className="mt-6 mb-2 text-base font-semibold text-slate-800 dark:text-slate-200">
      {children}
    </h4>
  ),
  p: ({ children }) => (
    <p className="my-4 text-[15px] leading-7 text-slate-600 dark:text-slate-300">
      {children}
    </p>
  ),
  a: MdxLink,
  strong: ({ children }) => (
    <strong className="font-semibold text-slate-950 dark:text-white">{children}</strong>
  ),
  ul: ({ children }) => (
    <ul className="my-4 list-disc space-y-2.5 pl-6 text-[15px] leading-7 text-slate-600 dark:text-slate-300">
      {children}
    </ul>
  ),
  ol: ({ children }) => (
    <ol className="my-4 list-decimal space-y-2.5 pl-6 text-[15px] leading-7 text-slate-600 dark:text-slate-300">
      {children}
    </ol>
  ),
  blockquote: ({ children }) => (
    <blockquote className="my-6 rounded-r-xl border-l-4 border-indigo-500 bg-slate-100/70 py-3.5 pl-5 pr-4 text-[15px] italic text-slate-700 dark:bg-slate-900/60 dark:text-slate-300 font-medium">
      {children}
    </blockquote>
  ),
  code: ({ children, className, ...props }: ComponentProps<"code">) => {
    const isCodeBlock = Boolean(className && className.includes("language-"));
    if (isCodeBlock) {
      return (
        <code className="border-0 bg-transparent p-0 font-mono text-[13px] text-slate-100 dark:text-slate-100" {...props}>
          {children}
        </code>
      );
    }
    return (
      <code
        className="rounded-md border border-slate-200/80 bg-slate-100 px-1.5 py-0.5 font-mono text-[0.85em] font-medium text-indigo-700 dark:border-slate-700/60 dark:bg-slate-800 dark:text-indigo-300"
        {...props}
      >
        {children}
      </code>
    );
  },
  pre: ({ children }) => <CodeBlock>{children}</CodeBlock>,
  hr: () => (
    <hr className="my-10 border-0 h-px bg-gradient-to-r from-transparent via-slate-200 dark:via-slate-800 to-transparent" />
  ),
  table: ({ children }) => (
    <div className="my-8 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xs dark:border-slate-800 dark:bg-slate-900/60">
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] border-collapse text-left text-sm">
          {children}
        </table>
      </div>
    </div>
  ),
  th: ({ children }) => (
    <th className="border-b border-slate-200 bg-slate-100/90 px-4 py-3.5 text-xs font-bold uppercase tracking-wider text-slate-700 dark:border-slate-800 dark:bg-slate-800/80 dark:text-slate-200">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="border-b border-slate-100 px-4 py-3 align-middle text-xs sm:text-sm text-slate-700 dark:border-slate-800/60 dark:text-slate-300">
      {children}
    </td>
  ),
  GuideCallout,
  GuideReveal,
  TutorialCallout,
  TutorialReveal,
  StatusBadge,
} satisfies MDXComponents;

export function useMDXComponents(): MDXComponents {
  return components;
}
