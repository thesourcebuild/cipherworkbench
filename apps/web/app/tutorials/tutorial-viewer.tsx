"use client";

import { useMemo } from "react";
import { Button, cn } from "@ocs/ui";
import {
  ALL_TUTORIALS,
  CHARACTERS,
  getTutorial,
} from "./tutorials-data";

export interface TutorialViewerProps {
  tutorialId: string;
  onSelectTutorial: (id: string) => void;
  onLaunchTool: (toolId: string, sampleInput: string) => void;
}

export function TutorialViewer({
  tutorialId,
  onSelectTutorial,
  onLaunchTool,
}: TutorialViewerProps) {
  const tutorial = useMemo(() => {
    return getTutorial(tutorialId) ?? ALL_TUTORIALS[0]!;
  }, [tutorialId]);

  const currentIndex = ALL_TUTORIALS.findIndex((t) => t.id === tutorial.id);
  const prevTutorial = currentIndex > 0 ? ALL_TUTORIALS[currentIndex - 1] : null;
  const nextTutorial =
    currentIndex < ALL_TUTORIALS.length - 1 ? ALL_TUTORIALS[currentIndex + 1] : null;

  return (
    <div className="mx-auto max-w-4xl space-y-8 pb-16">
      {/* Top Banner / Header */}
      <div className="rounded-2xl border border-slate-200/80 bg-gradient-to-br from-white via-slate-50/50 to-indigo-50/20 p-6 shadow-xs dark:border-slate-800 dark:from-slate-900 dark:via-slate-900 dark:to-indigo-950/20">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded-md bg-indigo-600 px-2 py-0.5 text-xs font-bold text-white shadow-2xs dark:bg-indigo-500">
            Scenario {tutorial.number}
          </span>
          <span className="rounded-md border border-slate-200 bg-white px-2 py-0.5 text-xs font-semibold text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
            {tutorial.readTime}
          </span>
          <span
            className={cn(
              "rounded-md border px-2 py-0.5 text-xs font-semibold",
              tutorial.difficulty === "Beginner"
                ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300"
                : tutorial.difficulty === "Intermediate"
                  ? "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300"
                  : "border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300"
            )}
          >
            {tutorial.difficulty}
          </span>
        </div>

        <h1 className="mt-3 text-2xl font-bold tracking-tight text-slate-950 sm:text-3xl dark:text-white">
          {tutorial.title}
        </h1>
        <p className="mt-2 text-base text-slate-600 dark:text-slate-300">
          {tutorial.subtitle}
        </p>

        {/* Character Badges */}
        <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-slate-200/70 pt-4 dark:border-slate-800/70">
          <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Characters involved:
          </span>
          {tutorial.characters.map((name) => {
            const char = CHARACTERS[name];
            return (
              <span
                key={name}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold shadow-2xs",
                  char ? char.color : "border-slate-300 bg-slate-100 text-slate-800"
                )}
              >
                <span>{char?.avatar ?? "👤"}</span>
                <span>{name}</span>
                <span className="text-[10px] opacity-75 font-normal hidden sm:inline">
                  ({char?.role})
                </span>
              </span>
            );
          })}
        </div>
      </div>

      {/* The Analogy & Story Card */}
      <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-2xs dark:border-slate-800 dark:bg-slate-900">
        <h2 className="flex items-center gap-2 text-lg font-bold text-slate-900 dark:text-white">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-100 text-indigo-600 dark:bg-indigo-900/60 dark:text-indigo-400">
            📖
          </span>
          The Everyday Analogy
        </h2>
        <p className="mt-3 text-sm leading-relaxed text-slate-700 dark:text-slate-300">
          {tutorial.analogy}
        </p>

        <div className="mt-4 rounded-lg border border-amber-200/80 bg-amber-50/50 p-4 dark:border-amber-900/40 dark:bg-amber-950/20">
          <h3 className="text-xs font-bold uppercase tracking-wider text-amber-800 dark:text-amber-400">
            The Fundamental Dilemma
          </h3>
          <p className="mt-1 text-sm font-medium text-amber-900 dark:text-amber-200">
            {tutorial.problem}
          </p>
        </div>
      </section>

      {/* Step-by-Step Scenario Walkthrough */}
      <section className="space-y-4">
        <h2 className="flex items-center gap-2 text-lg font-bold text-slate-900 dark:text-white">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-100 text-indigo-600 dark:bg-indigo-900/60 dark:text-indigo-400">
            ⚡
          </span>
          Step-by-Step Scenario Walkthrough
        </h2>

        <div className="space-y-4">
          {tutorial.steps.map((step, idx) => {
            const char = step.speaker ? CHARACTERS[step.speaker] : undefined;

            return (
              <div
                key={idx}
                className="relative rounded-xl border border-slate-200 bg-white p-5 shadow-2xs dark:border-slate-800 dark:bg-slate-900"
              >
                <div className="flex items-start justify-between gap-3">
                  <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                    {step.title}
                  </h3>
                  {char && (
                    <span
                      className={cn(
                        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold shrink-0",
                        char.color
                      )}
                    >
                      <span>{char.avatar}</span>
                      <span>{char.name}</span>
                    </span>
                  )}
                </div>

                <div className="mt-2 text-sm leading-relaxed text-slate-700 dark:text-slate-300 whitespace-pre-line">
                  {step.content}
                </div>

                {step.callout && (
                  <div
                    className={cn(
                      "mt-3 rounded-lg border-l-4 p-3 text-xs leading-relaxed",
                      step.callout.type === "security"
                        ? "border-emerald-500 bg-emerald-50 text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200"
                        : step.callout.type === "warning"
                          ? "border-amber-500 bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:text-amber-200"
                          : "border-indigo-500 bg-indigo-50 text-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-200"
                    )}
                  >
                    <span className="font-bold">
                      {step.callout.type === "security"
                        ? "🛡️ Security Note: "
                        : step.callout.type === "warning"
                          ? "⚠️ Important Catch: "
                          : "💡 Key Insight: "}
                    </span>
                    {step.callout.text}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* Key Takeaways */}
      <section className="rounded-xl border border-slate-200 bg-slate-50/70 p-5 dark:border-slate-800 dark:bg-slate-900/60">
        <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <span>🎯</span> Key Takeaways
        </h3>
        <ul className="mt-3 space-y-2 text-sm text-slate-700 dark:text-slate-300 list-disc pl-5">
          {tutorial.takeaways.map((item, i) => (
            <li key={i}>{item}</li>
          ))}
        </ul>
      </section>

      {/* Interactive Bridge to Workbench */}
      <section className="rounded-2xl border-2 border-indigo-300/80 bg-gradient-to-r from-indigo-50 via-white to-indigo-50/50 p-6 shadow-sm dark:border-indigo-800/80 dark:from-indigo-950/40 dark:via-slate-900 dark:to-indigo-950/30">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <span className="inline-flex items-center gap-1 rounded-md bg-indigo-600 px-2 py-0.5 text-[11px] font-bold text-white dark:bg-indigo-500">
              Interactive Lab
            </span>
            <h3 className="text-base font-bold text-slate-900 dark:text-white">
              Try This Live in Cipher Workbench
            </h3>
            <p className="text-xs text-slate-600 dark:text-slate-300">
              {tutorial.seed.explanation}
            </p>
            {tutorial.seed.sampleInput && (
              <div className="mt-2 inline-block rounded border border-slate-300 bg-white/80 px-2 py-1 font-mono text-[11px] text-slate-800 dark:border-slate-700 dark:bg-slate-800/80 dark:text-slate-200">
                Sample: &quot;{tutorial.seed.sampleInput}&quot;
              </div>
            )}
          </div>

          <Button
            type="button"
            variant="primary"
            size="md"
            onClick={() => onLaunchTool(tutorial.seed.toolId, tutorial.seed.sampleInput)}
            className="shrink-0 bg-indigo-600 hover:bg-indigo-700 text-white shadow-md dark:bg-indigo-500 dark:hover:bg-indigo-600"
          >
            Launch in Workbench →
          </Button>
        </div>
      </section>

      {/* Previous / Next Navigation */}
      <nav
        aria-label="Tutorial pagination"
        className="flex items-center justify-between border-t border-slate-200/80 pt-6 dark:border-slate-800/80"
      >
        {prevTutorial ? (
          <button
            type="button"
            onClick={() => onSelectTutorial(prevTutorial.id)}
            className="flex items-center gap-2 text-xs font-semibold text-slate-700 transition-colors hover:text-indigo-600 dark:text-slate-300 dark:hover:text-indigo-400"
          >
            <span>←</span>
            <div className="text-left">
              <span className="text-[10px] text-slate-400 block">Previous</span>
              <span>{prevTutorial.title}</span>
            </div>
          </button>
        ) : (
          <div />
        )}

        {nextTutorial && (
          <button
            type="button"
            onClick={() => onSelectTutorial(nextTutorial.id)}
            className="flex items-center gap-2 text-xs font-semibold text-slate-700 transition-colors hover:text-indigo-600 dark:text-slate-300 dark:hover:text-indigo-400"
          >
            <div className="text-right">
              <span className="text-[10px] text-slate-400 block">Next</span>
              <span>{nextTutorial.title}</span>
            </div>
            <span>→</span>
          </button>
        )}
      </nav>
    </div>
  );
}
