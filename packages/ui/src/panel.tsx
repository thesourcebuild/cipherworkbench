"use client";

import { useState, type HTMLAttributes, type ReactNode } from "react";
import { cn } from "./cn";

// `title` is deliberately a ReactNode heading, not the HTML tooltip attribute.
export interface PanelProps extends Omit<HTMLAttributes<HTMLDivElement>, "title"> {
  title?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  /** When true, the header becomes a toggle that folds `children` away. Opt-in; bare `<Panel>` calls are unaffected. */
  collapsible?: boolean;
  /** Only meaningful with `collapsible`. Defaults to open. */
  defaultOpen?: boolean;
}

export function Panel({
  title,
  description,
  actions,
  className,
  children,
  collapsible,
  defaultOpen = true,
  ...props
}: PanelProps) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  const open = !collapsible || isOpen;

  return (
    <section
      className={cn(
        "rounded-lg border border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900",
        className,
      )}
      {...props}
    >
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-4 border-b border-slate-200 px-4 py-3 dark:border-slate-800">
          <div className="min-w-0 flex-1">
            {title &&
              (collapsible ? (
                <h2 className="text-sm font-semibold">
                  <button
                    type="button"
                    onClick={() => setIsOpen((o) => !o)}
                    aria-expanded={open}
                    className="flex items-center gap-1.5 text-left hover:text-slate-700 dark:hover:text-slate-300"
                  >
                    <ChevronIcon collapsed={!open} />
                    {title}
                  </button>
                </h2>
              ) : (
                <h2 className="text-sm font-semibold">{title}</h2>
              ))}
            {description && (
              <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{description}</p>
            )}
          </div>
          {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
        </header>
      )}
      {open && <div className="px-4 py-3">{children}</div>}
    </section>
  );
}

function ChevronIcon({ collapsed }: { collapsed: boolean }) {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={cn(
        "shrink-0 text-slate-400 transition-transform",
        collapsed ? "-rotate-90" : "",
      )}
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}
