import Link from "next/link";
import type { ComponentProps, ReactNode } from "react";
import type { MDXComponents } from "mdx/types";
import { TutorialCallout, TutorialReveal } from "./app/tutorials/tutorial-components";

function MdxLayout({ children }: { children?: ReactNode }) {
  return (
    <main className="min-h-screen bg-slate-50 px-4 py-8 text-slate-800 dark:bg-slate-950 dark:text-slate-200 sm:px-6 sm:py-12">
      <article className="mx-auto max-w-3xl rounded-xl border border-slate-200 bg-white px-5 py-6 shadow-sm dark:border-slate-800 dark:bg-slate-900 sm:px-9 sm:py-10">
        <nav className="mb-8 border-b border-slate-200 pb-4 text-xs font-semibold uppercase tracking-[0.16em] text-indigo-600 dark:border-slate-800 dark:text-indigo-400">
          <Link href="/">Cipher Workbench</Link>
          <span aria-hidden="true" className="px-2 text-slate-300 dark:text-slate-700">
            /
          </span>
          Tutorials
        </nav>
        {children}
      </article>
    </main>
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
      className="font-medium text-indigo-600 underline decoration-indigo-300 underline-offset-2 dark:text-indigo-400"
    >
      {children}
    </a>
  ) : (
    <Link
      href={href}
      title={title}
      className="font-medium text-indigo-600 underline decoration-indigo-300 underline-offset-2 dark:text-indigo-400"
    >
      {children}
    </Link>
  );
}

const components = {
  wrapper: MdxLayout,
  h1: ({ children }) => (
    <h1 className="mb-5 text-3xl font-bold tracking-tight text-slate-950 dark:text-white sm:text-4xl">
      {children}
    </h1>
  ),
  h2: ({ children }) => (
    <h2 className="mb-3 mt-9 text-xl font-bold text-slate-950 dark:text-white">{children}</h2>
  ),
  h3: ({ children }) => (
    <h3 className="mb-2 mt-7 text-base font-semibold text-slate-950 dark:text-white">
      {children}
    </h3>
  ),
  p: ({ children }) => <p className="my-4 leading-7">{children}</p>,
  a: MdxLink,
  strong: ({ children }) => (
    <strong className="font-semibold text-slate-950 dark:text-white">{children}</strong>
  ),
  ul: ({ children }) => <ul className="my-4 list-disc space-y-2 pl-6">{children}</ul>,
  ol: ({ children }) => <ol className="my-4 list-decimal space-y-2 pl-6">{children}</ol>,
  blockquote: ({ children }) => (
    <blockquote className="my-6 border-l-2 border-indigo-400 pl-4 text-slate-600 dark:text-slate-400">
      {children}
    </blockquote>
  ),
  code: ({ children }) => (
    <code className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[0.9em] text-slate-900 dark:bg-slate-800 dark:text-slate-100">
      {children}
    </code>
  ),
  pre: ({ children }) => (
    <pre className="my-6 overflow-x-auto rounded-lg border border-slate-800 bg-slate-950 p-4 font-mono text-sm leading-6 text-slate-100 [&_code]:bg-transparent [&_code]:p-0">
      {children}
    </pre>
  ),
  table: ({ children }) => (
    <div className="my-6 overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">{children}</table>
    </div>
  ),
  th: ({ children }) => (
    <th className="border border-slate-300 bg-slate-100 px-3 py-2 font-semibold dark:border-slate-700 dark:bg-slate-800">
      {children}
    </th>
  ),
  td: ({ children }) => (
    <td className="border border-slate-300 px-3 py-2 align-top dark:border-slate-700">
      {children}
    </td>
  ),
  TutorialCallout,
  TutorialReveal,
} satisfies MDXComponents;

export function useMDXComponents(): MDXComponents {
  return components;
}
