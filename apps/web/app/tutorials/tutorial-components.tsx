import type { ReactNode } from "react";
import { TutorialRevealClient } from "./tutorial-reveal-client";

export function TutorialCallout({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <aside className="my-6 rounded-r-lg border-l-4 border-indigo-500 bg-indigo-50 px-4 py-3 dark:bg-indigo-950/30">
      <p className="m-0 text-sm font-semibold text-indigo-950 dark:text-indigo-100">{title}</p>
      <div className="text-sm text-indigo-900/80 dark:text-indigo-200/80">{children}</div>
    </aside>
  );
}

export function TutorialReveal({
  summary = "Reveal explanation",
  children,
}: {
  summary?: string;
  children?: ReactNode;
}) {
  return <TutorialRevealClient summary={summary}>{children}</TutorialRevealClient>;
}
