"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

interface TocItem {
  id: string;
  label: string;
  indent?: boolean;
}

const TOC_ITEMS: TocItem[] = [
  { id: "the-three-fundamental-rules-for-modern-certificates", label: "3 Fundamental Rules" },
  { id: "1-key-algorithm-aware-key-usage", label: "1. Key Usage Rules", indent: true },
  { id: "2-dual-stack-san-key-identifiers", label: "2. Dual-Stack SAN", indent: true },
  { id: "3-windows-shell-safety", label: "3. Windows Shell Safety", indent: true },
  { id: "architectural-hierarchy-comparison", label: "Architecture Comparison" },
  { id: "deep-dive-the-four-deployment-modes", label: "The 4 Deployment Modes" },
  { id: "mode-1-single-self-signed", label: "Mode 1: Single (Self-Signed)", indent: true },
  { id: "mode-2-single-ca-signed", label: "Mode 2: Single (CA-Signed)", indent: true },
  { id: "mode-3-mtls-2-tier-suite", label: "Mode 3: mTLS (2-Tier)", indent: true },
  { id: "mode-4-mtls-enterprise-3-tier", label: "Mode 4: Enterprise (3-Tier)", indent: true },
  { id: "python-server-and-client-implementations", label: "Python Server & Client" },
  { id: "python-https-server-server-py", label: "HTTPS Server (server.py)", indent: true },
  { id: "python-client-client-py", label: "TLS Client (client.py)", indent: true },
  { id: "decision-guide-which-one-should-you-select", label: "Decision Guide & Flowchart" },
];

export function GuideTOC() {
  const [activeId, setActiveId] = useState<string>("");

  useEffect(() => {
    const handleScroll = () => {
      const headings = TOC_ITEMS.map((item) => document.getElementById(item.id)).filter(
        Boolean,
      ) as HTMLElement[];

      const scrollPosition = window.scrollY + 120;

      for (let i = headings.length - 1; i >= 0; i--) {
        const heading = headings[i];
        if (heading && heading.offsetTop <= scrollPosition) {
          setActiveId(heading.id);
          return;
        }
      }

      if (headings.length > 0 && headings[0]) {
        setActiveId(headings[0].id);
      }
    };

    window.addEventListener("scroll", handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <nav aria-label="Table of contents" className="flex flex-col gap-6 text-sm">
      <div>
        <div className="flex items-center gap-2 pb-3 font-semibold uppercase tracking-wider text-xs text-slate-900 dark:text-slate-100">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 20 20"
            fill="currentColor"
            className="h-4 w-4 text-indigo-500"
          >
            <path
              fillRule="evenodd"
              d="M2 4.75A.75.75 0 0 1 2.75 4h14.5a.75.75 0 0 1 0 1.5H2.75A.75.75 0 0 1 2 4.75ZM2 10a.75.75 0 0 1 .75-.75h14.5a.75.75 0 0 1 0 1.5H2.75A.75.75 0 0 1 2 10Zm0 5.25a.75.75 0 0 1 .75-.75h14.5a.75.75 0 0 1 0 1.5H2.75a.75.75 0 0 1-.75-.75Z"
              clipRule="evenodd"
            />
          </svg>
          <span>On This Page</span>
        </div>

        <ul className="space-y-1 border-l border-slate-200 dark:border-slate-800 text-xs">
          {TOC_ITEMS.map((item) => {
            const isActive = activeId === item.id;
            return (
              <li key={item.id}>
                <a
                  href={`#${item.id}`}
                  className={`group flex items-center py-1.5 transition-colors -ml-px border-l-2 ${
                    item.indent ? "pl-5" : "pl-3"
                  } ${
                    isActive
                      ? "border-indigo-600 font-semibold text-indigo-600 dark:border-indigo-400 dark:text-indigo-400"
                      : "border-transparent text-slate-500 hover:border-slate-400 hover:text-slate-900 dark:text-slate-400 dark:hover:border-slate-600 dark:hover:text-slate-200"
                  }`}
                >
                  <span className="truncate">{item.label}</span>
                </a>
              </li>
            );
          })}
        </ul>
      </div>

      {/* Quick Interactive Card */}
      <div className="rounded-xl border border-indigo-100 bg-gradient-to-br from-indigo-50/80 to-purple-50/40 p-4 dark:border-indigo-900/40 dark:from-indigo-950/30 dark:to-purple-950/20">
        <div className="flex items-center gap-2 text-xs font-semibold text-indigo-950 dark:text-indigo-200">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 20 20"
            fill="currentColor"
            className="h-4 w-4 text-indigo-600 dark:text-indigo-400"
          >
            <path
              fillRule="evenodd"
              d="M10 1a4.5 4.5 0 0 0-4.5 4.5V9H5a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2h-.5V5.5A4.5 4.5 0 0 0 10 1Zm3 8V5.5a3 3 0 1 0-6 0V9h6Z"
              clipRule="evenodd"
            />
          </svg>
          <span>Workbench Tools</span>
        </div>
        <p className="mt-1.5 text-[11px] leading-relaxed text-indigo-900/80 dark:text-indigo-300/80">
          Generate, verify, and inspect X.509 certs, RSA/EC keypairs, and hashes directly in your browser.
        </p>
        <Link
          href="/"
          className="mt-3 inline-flex w-full items-center justify-center rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-semibold text-white shadow-xs hover:bg-indigo-700 dark:bg-indigo-500 dark:hover:bg-indigo-600 transition-colors"
        >
          Open Workbench →
        </Link>
      </div>
    </nav>
  );
}

// Alias for backwards compatibility
export const TutorialTOC = GuideTOC;
