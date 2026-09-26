import type { Metadata } from "next";
import type { ReactNode } from "react";
import { SITE_URL } from "../site";
import { GuideHeader } from "./guide-header";
import { GuideTOC } from "./guide-toc";

export const metadata: Metadata = {
  title: "X.509 PKI Architecture & Modern TLS Guides",
  description:
    "A comprehensive engineering guide to self-signed certificates, certificate authorities, mTLS hierarchies, and dual-stack TLS validation across Python and browsers.",
  alternates: { canonical: `${SITE_URL}/guides/` },
};

export default function GuidesLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-800 dark:bg-slate-950 dark:text-slate-200 transition-colors selection:bg-indigo-500/25 selection:text-slate-950 dark:selection:bg-indigo-500/35 dark:selection:text-white">
      <GuideHeader />
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8 sm:py-12">
        <div className="flex flex-col lg:flex-row gap-10 lg:gap-14 items-start">
          <main className="flex-1 min-w-0 max-w-4xl">
            {children}
          </main>
          <aside className="hidden xl:block w-72 shrink-0 sticky top-24">
            <GuideTOC />
          </aside>
        </div>
      </div>
      <footer className="border-t border-slate-200/80 bg-white/50 py-10 text-center text-xs text-slate-500 dark:border-slate-800/80 dark:bg-slate-950/50 dark:text-slate-400">
        <div className="mx-auto max-w-7xl px-4">
          <p className="font-medium text-slate-700 dark:text-slate-300">
            Cipher Workbench · Cryptographic Engineering Suite
          </p>
          <p className="mt-1 text-slate-500 dark:text-slate-500">
            All algorithms, certificates, and keys run 100% offline in your browser. No private keys are ever uploaded or transmitted.
          </p>
        </div>
      </footer>
    </div>
  );
}
