"use client";

import { useEffect, useMemo, useState } from "react";
import { cn } from "@ocs/ui";
import {
  ALL_TUTORIALS_META as ALL_TUTORIALS,
  CHARACTERS,
  getTutorialMeta,
} from "./tutorials-meta";
import { loadTutorialContent } from "./tutorial-loader";
import type { TutorialContent } from "./tutorial-types";
import { TutorialMarkdown } from "./tutorial-markdown";
import { DtlsHandshakeVisual, TlsHandshakeVisual } from "./transport-handshake-visual";
import { CryptographicFlowVisual } from "./cryptographic-flow-visual";

export interface TutorialViewerProps {
  tutorialId: string;
  onSelectTutorial: (id: string) => void;
  onLaunchTool?: (toolId: string, sampleInput: string) => void;
}

export function TutorialViewer({ tutorialId, onSelectTutorial }: TutorialViewerProps) {
  const meta = useMemo(() => {
    return getTutorialMeta(tutorialId) ?? ALL_TUTORIALS[0]!;
  }, [tutorialId]);

  const [variantSelections, setVariantSelections] = useState<Record<string, string>>({});
  const selectedContentId = useMemo(() => {
    const selected = variantSelections[meta.id];
    return selected && meta.variants?.some((variant) => variant.id === selected)
      ? selected
      : meta.id;
  }, [meta, variantSelections]);
  const selectedVariant = meta.variants?.find((variant) => variant.id === selectedContentId);
  const displayMeta = selectedVariant ?? meta;

  const [content, setContent] = useState<TutorialContent | null>(null);
  const [loadedContentId, setLoadedContentId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    setLoading(true);

    loadTutorialContent(selectedContentId).then((data) => {
      if (active) {
        setContent(data);
        setLoadedContentId(selectedContentId);
        setLoading(false);
      }
    });

    return () => {
      active = false;
    };
  }, [selectedContentId]);

  const currentIndex = ALL_TUTORIALS.findIndex((t) => t.id === meta.id);
  const prevTutorial = currentIndex > 0 ? ALL_TUTORIALS[currentIndex - 1] : null;
  const nextTutorial =
    currentIndex < ALL_TUTORIALS.length - 1 ? ALL_TUTORIALS[currentIndex + 1] : null;

  return (
    <div className="mx-auto max-w-4xl space-y-8 pb-16">
      {/* Top Banner / Header (Instant from Metadata) */}
      <div className="rounded-2xl border border-slate-200/80 bg-gradient-to-br from-white via-slate-50/50 to-indigo-50/20 p-6 shadow-xs dark:border-slate-800 dark:from-slate-900 dark:via-slate-900 dark:to-indigo-950/20">
        <div className="flex flex-wrap items-center gap-2">
          <span className="rounded-md bg-indigo-600 px-2 py-0.5 text-xs font-bold text-white shadow-2xs dark:bg-indigo-500">
            Scenario {meta.number}
          </span>
          <span className="rounded-md border border-slate-200 bg-white px-2 py-0.5 text-xs font-semibold text-slate-600 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300">
            {displayMeta.readTime}
          </span>
          <span
            className={cn(
              "rounded-md border px-2 py-0.5 text-xs font-semibold",
              displayMeta.difficulty === "Beginner"
                ? "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300"
                : displayMeta.difficulty === "Intermediate"
                  ? "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300"
                  : "border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300",
            )}
          >
            {displayMeta.difficulty}
          </span>
          {meta.variants ? (
            <label className="ml-auto flex items-center gap-2 text-xs font-semibold text-slate-600 dark:text-slate-300">
              <span className="whitespace-nowrap">Explanation:</span>
              <select
                aria-label="Handshake version"
                value={selectedContentId}
                onChange={(event) =>
                  setVariantSelections((current) => ({
                    ...current,
                    [meta.id]: event.target.value,
                  }))
                }
                className="h-8 rounded-md border border-slate-300 bg-white px-2 text-xs font-semibold text-slate-900 shadow-xs focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100"
              >
                {meta.variants.map((variant) => (
                  <option key={variant.id} value={variant.id}>
                    {variant.label}
                  </option>
                ))}
              </select>
            </label>
          ) : null}
        </div>

        <h1 className="mt-3 text-2xl font-bold tracking-tight text-slate-950 sm:text-3xl dark:text-white">
          {displayMeta.title}
        </h1>
        <p className="mt-2 text-base text-slate-600 dark:text-slate-300">
          {displayMeta.subtitle}
        </p>

        {/* Character Badges */}
        <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-slate-200/70 pt-4 dark:border-slate-800/70">
          <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Characters involved:
          </span>
          {meta.characters.map((name) => {
            const char = CHARACTERS[name];
            return (
              <span
                key={name}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold shadow-2xs",
                  char ? char.color : "border-slate-300 bg-slate-100 text-slate-800",
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

      {loading || !content || loadedContentId !== selectedContentId ? (
        <div className="space-y-6 animate-pulse">
          <div className="h-32 rounded-xl border border-slate-200 bg-slate-100 dark:border-slate-800 dark:bg-slate-800/50" />
          <div className="space-y-4">
            <div className="h-6 w-48 rounded bg-slate-200 dark:bg-slate-800" />
            <div className="h-28 rounded-xl border border-slate-200 bg-slate-100 dark:border-slate-800 dark:bg-slate-800/50" />
            <div className="h-28 rounded-xl border border-slate-200 bg-slate-100 dark:border-slate-800 dark:bg-slate-800/50" />
          </div>
        </div>
      ) : (
        <>
          {/* The Analogy & Story Card */}
          <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-2xs dark:border-slate-800 dark:bg-slate-900">
            <h2 className="flex items-center gap-2 text-lg font-bold text-slate-900 dark:text-white">
              <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-100 text-indigo-600 dark:bg-indigo-900/60 dark:text-indigo-400">
                📖
              </span>
              The Everyday Analogy
            </h2>
            <TutorialMarkdown content={content.analogy} className="mt-3" />

            <div className="mt-4 rounded-lg border border-amber-200/80 bg-amber-50/50 p-4 dark:border-amber-900/40 dark:bg-amber-950/20">
              <h3 className="text-xs font-bold uppercase tracking-wider text-amber-800 dark:text-amber-400">
                The Fundamental Dilemma
              </h3>
              <TutorialMarkdown
                content={content.problem}
                className="mt-1 font-medium text-amber-900 dark:text-amber-200"
              />
            </div>
          </section>

          {content.visualization?.kind === "tls-handshake" ? (
            <TlsHandshakeVisual version={content.visualization.version} />
          ) : content.visualization?.kind === "dtls-handshake" ? (
            <DtlsHandshakeVisual version={content.visualization.version} />
          ) : content.visualization?.kind === "cryptographic-flow" ? (
            <CryptographicFlowVisual id={content.visualization.id} />
          ) : null}

          {/* Step-by-Step Scenario Walkthrough */}
          <section className="space-y-4">
            <h2 className="flex items-center gap-2 text-lg font-bold text-slate-900 dark:text-white">
              <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-100 text-indigo-600 dark:bg-indigo-900/60 dark:text-indigo-400">
                ⚡
              </span>
              Step-by-Step Scenario Walkthrough
            </h2>

            <div className="space-y-4">
              {content.steps.map((step, idx) => {
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
                            char.color,
                          )}
                        >
                          <span>{char.avatar}</span>
                          <span>{char.name}</span>
                        </span>
                      )}
                    </div>

                    <TutorialMarkdown content={step.content} className="mt-2" />

                    {step.callout && (
                      <div
                        className={cn(
                          "mt-3 rounded-lg border-l-4 p-3 text-xs leading-relaxed",
                          step.callout.type === "security"
                            ? "border-emerald-500 bg-emerald-50 text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200"
                            : step.callout.type === "warning"
                              ? "border-amber-500 bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:text-amber-200"
                              : "border-indigo-500 bg-indigo-50 text-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-200",
                        )}
                      >
                        <span className="font-bold">
                          {step.callout.type === "security"
                            ? "🛡️ Security Note: "
                            : step.callout.type === "warning"
                              ? "⚠️ Important Catch: "
                              : "💡 Key Insight: "}
                        </span>
                        <TutorialMarkdown content={step.callout.text} inline />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </section>

          {content.afterTimeline ? (
            <section className="rounded-xl border border-indigo-200 bg-indigo-50/50 p-5 dark:border-indigo-900/50 dark:bg-indigo-950/20">
              <h2 className="flex items-center gap-2 text-lg font-bold text-slate-900 dark:text-white">
                <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-indigo-100 text-indigo-600 dark:bg-indigo-900/60 dark:text-indigo-400">
                  ↻
                </span>
                {content.afterTimeline.title}
              </h2>
              <TutorialMarkdown content={content.afterTimeline.content} className="mt-3" />

              {content.afterTimeline.callout ? (
                <div
                  className={cn(
                    "mt-3 rounded-lg border-l-4 p-3 text-xs leading-relaxed",
                    content.afterTimeline.callout.type === "security"
                      ? "border-emerald-500 bg-emerald-50 text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200"
                      : content.afterTimeline.callout.type === "warning"
                        ? "border-amber-500 bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:text-amber-200"
                        : "border-indigo-500 bg-indigo-50 text-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-200",
                  )}
                >
                  <span className="font-bold">
                    {content.afterTimeline.callout.type === "security"
                      ? "🛡️ Security Note: "
                      : content.afterTimeline.callout.type === "warning"
                        ? "⚠️ Important Catch: "
                        : "💡 Key Insight: "}
                  </span>
                  <TutorialMarkdown content={content.afterTimeline.callout.text} inline />
                </div>
              ) : null}
            </section>
          ) : null}

          {/* Key Takeaways */}
          <section className="rounded-xl border border-slate-200 bg-slate-50/70 p-5 dark:border-slate-800 dark:bg-slate-900/60">
            <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <span>🎯</span> Key Takeaways
            </h3>
            <ul className="mt-3 space-y-2 text-sm text-slate-700 dark:text-slate-300 list-disc pl-5">
              {content.takeaways.map((item, i) => (
                <li key={i}>
                  <TutorialMarkdown content={item} inline />
                </li>
              ))}
            </ul>
          </section>
        </>
      )}

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
