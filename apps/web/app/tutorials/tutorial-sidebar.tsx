"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { ToolFamily } from "@ocs/engine";
import { cn } from "@ocs/ui";
import {
  ALL_TUTORIALS_META as ALL_TUTORIALS,
  TUTORIAL_CONCEPTS_META as TUTORIAL_CONCEPTS,
} from "./tutorials-meta";

export interface TutorialSidebarProps {
  selectedId: string;
  onSelect: (id: string) => void;
  onCollapse: () => void;
}

const FAMILY_STYLE: Record<ToolFamily, string> = {
  hash: "border-violet-200 bg-violet-50 text-violet-700 dark:border-violet-900 dark:bg-violet-950/40 dark:text-violet-300",
  crc: "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-300",
  checksum:
    "border-cyan-200 bg-cyan-50 text-cyan-700 dark:border-cyan-900 dark:bg-cyan-950/40 dark:text-cyan-300",
  checkdigit:
    "border-orange-200 bg-orange-50 text-orange-700 dark:border-orange-900 dark:bg-orange-950/40 dark:text-orange-300",
  parity:
    "border-teal-200 bg-teal-50 text-teal-700 dark:border-teal-900 dark:bg-teal-950/40 dark:text-teal-300",
  mac: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300",
  kdf: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300",
  cipher:
    "border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300",
  classical:
    "border-stone-300 bg-stone-100 text-stone-600 dark:border-stone-700 dark:bg-stone-900/60 dark:text-stone-300",
  asymmetric:
    "border-indigo-200 bg-indigo-50 text-indigo-700 dark:border-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-300",
  certificates:
    "border-blue-200 bg-blue-50 text-blue-700 dark:border-blue-900 dark:bg-blue-950/40 dark:text-blue-300",
  encoding:
    "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300",
  format:
    "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300",
};

const FAMILY_BADGE: Record<ToolFamily, string> = {
  hash: "hash",
  crc: "CRC",
  checksum: "sum",
  checkdigit: "digit",
  parity: "parity",
  mac: "MAC",
  kdf: "KDF",
  cipher: "cipher",
  classical: "classic",
  asymmetric: "key",
  certificates: "cert",
  encoding: "enc",
  format: "fmt",
};

const COMPLETED_STORAGE_KEY = "cipherworkbench:completed_tutorials";

export function TutorialSidebar({
  selectedId,
  onSelect,
  onCollapse,
}: TutorialSidebarProps) {
  const [search, setSearch] = useState("");
  const [collapsedConcepts, setCollapsedConcepts] = useState<Set<string>>(new Set());
  const [completedIds, setCompletedIds] = useState<Set<string>>(new Set());
  const searchRef = useRef<HTMLInputElement | null>(null);

  // Load completed tutorials from localStorage
  useEffect(() => {
    try {
      const stored = localStorage.getItem(COMPLETED_STORAGE_KEY);
      if (stored) {
        setCompletedIds(new Set(JSON.parse(stored)));
      }
    } catch {
      // Ignore localStorage errors
    }
  }, []);

  const toggleCompleted = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    setCompletedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      try {
        localStorage.setItem(COMPLETED_STORAGE_KEY, JSON.stringify([...next]));
      } catch {
        // Ignore
      }
      return next;
    });
  };

  const filteredConcepts = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return TUTORIAL_CONCEPTS;

    return TUTORIAL_CONCEPTS.map((concept) => {
      const matches = concept.tutorials.filter((t) => {
        return (
          t.title.toLowerCase().includes(q) ||
          t.subtitle.toLowerCase().includes(q) ||
          t.summary.toLowerCase().includes(q) ||
          t.toolId.toLowerCase().includes(q) ||
          t.characters.some((c) => c.toLowerCase().includes(q))
        );
      });
      return {
        ...concept,
        tutorials: matches,
      };
    }).filter((c) => c.tutorials.length > 0);
  }, [search]);

  const toggleConcept = (conceptId: string) => {
    setCollapsedConcepts((prev) => {
      const next = new Set(prev);
      if (next.has(conceptId)) next.delete(conceptId);
      else next.add(conceptId);
      return next;
    });
  };

  const progressPercent = Math.round(
    (completedIds.size / (ALL_TUTORIALS.length || 1)) * 100
  );

  return (
    <div className="flex h-full flex-col bg-white dark:bg-slate-900 select-none">
      {/* Top Header */}
      <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2.5 dark:border-slate-800">
        <div>
          <div className="flex items-center gap-1.5">
            <span className="flex h-2 w-2 rounded-full bg-indigo-500 animate-pulse" />
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-indigo-600 dark:text-indigo-400">
              Interactive Tutorials
            </p>
          </div>
          <p className="mt-0.5 text-xs text-slate-400 dark:text-slate-500">
            {ALL_TUTORIALS.length} Alice &amp; Bob Scenarios
          </p>
        </div>
        <button
          type="button"
          onClick={onCollapse}
          aria-label="Collapse sidebar"
          title="Collapse sidebar"
          className="rounded-md border border-slate-200 p-1.5 text-slate-500 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:text-slate-400 dark:hover:bg-slate-800"
        >
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 20 20"
            fill="currentColor"
            className="h-4 w-4"
          >
            <path
              fillRule="evenodd"
              d="M15.79 14.77a.75.75 0 0 1-1.06.02l-4.5-4.25a.75.75 0 0 1 0-1.08l4.5-4.25a.75.75 0 1 1 1.04 1.08L11.832 10l3.938 3.71a.75.75 0 0 1 .02 1.06Zm-6 0a.75.75 0 0 1-1.06.02l-4.5-4.25a.75.75 0 0 1 0-1.08l4.5-4.25a.75.75 0 1 1 1.04 1.08L5.832 10l3.938 3.71a.75.75 0 0 1 .02 1.06Z"
              clipRule="evenodd"
            />
          </svg>
        </button>
      </div>

      {/* Progress Banner */}
      <div className="border-b border-slate-200/80 bg-slate-50/60 p-3 dark:border-slate-800/80 dark:bg-slate-950/40">
        <div className="flex items-center justify-between text-xs">
          <span className="font-medium text-slate-600 dark:text-slate-300">
            Course Progress
          </span>
          <span className="font-semibold text-indigo-600 dark:text-indigo-400">
            {completedIds.size} of {ALL_TUTORIALS.length} ({progressPercent}%)
          </span>
        </div>
        <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
          <div
            className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-indigo-600 transition-all duration-300"
            style={{ width: `${progressPercent}%` }}
          />
        </div>
      </div>

      {/* Search Input */}
      <div className="border-b border-slate-200 p-2 dark:border-slate-800">
        <div className="relative">
          <span className="pointer-events-none absolute inset-y-0 left-2.5 flex items-center text-slate-400">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 20 20"
              fill="currentColor"
              className="h-3.5 w-3.5"
            >
              <path
                fillRule="evenodd"
                d="M9 3.5a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11ZM2 9a7 7 0 1 1 12.452 4.391l3.328 3.329a.75.75 0 1 1-1.06 1.06l-3.329-3.328A7 7 0 0 1 2 9Z"
                clipRule="evenodd"
              />
            </svg>
          </span>
          <input
            ref={searchRef}
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter tutorials (Alice, Eve, AES...)"
            className="w-full rounded-md border border-slate-200 bg-white py-1.5 pr-8 pl-8 text-xs text-slate-900 placeholder:text-slate-400 focus:border-indigo-500 focus:outline-hidden dark:border-slate-700 dark:bg-slate-800 dark:text-slate-100 dark:placeholder:text-slate-500 dark:focus:border-indigo-400"
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch("")}
              className="absolute inset-y-0 right-2 flex items-center text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
            >
              <span className="text-xs">×</span>
            </button>
          )}
        </div>
      </div>

      {/* List of Concepts and Tutorials */}
      <div className="flex-1 overflow-y-auto p-2 space-y-3">
        {filteredConcepts.map((concept) => {
          const isCollapsed = collapsedConcepts.has(concept.id);

          return (
            <div key={concept.id} className="space-y-1">
              {/* Concept Accordion Header */}
              <button
                type="button"
                onClick={() => toggleConcept(concept.id)}
                className="flex w-full items-center justify-between rounded-md px-2 py-1.5 text-left text-xs font-semibold text-slate-700 transition-colors hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800/60"
              >
                <div className="flex items-center gap-1.5 truncate">
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    viewBox="0 0 20 20"
                    fill="currentColor"
                    className={cn(
                      "h-3.5 w-3.5 shrink-0 text-slate-400 transition-transform",
                      isCollapsed ? "-rotate-90" : "rotate-0"
                    )}
                  >
                    <path
                      fillRule="evenodd"
                      d="M5.22 8.22a.75.75 0 0 1 1.06 0L10 11.94l3.72-3.72a.75.75 0 1 1 1.06 1.06l-4.25 4.25a.75.75 0 0 1-1.06 0L5.22 9.28a.75.75 0 0 1 0-1.06Z"
                      clipRule="evenodd"
                    />
                  </svg>
                  <span className="truncate">{concept.title}</span>
                </div>
                <span className="shrink-0 rounded-sm bg-slate-100 px-1 py-0.5 text-[10px] font-medium text-slate-500 dark:bg-slate-800 dark:text-slate-400">
                  {concept.tutorials.length}
                </span>
              </button>

              {/* Tutorial Items */}
              {!isCollapsed && (
                <div className="space-y-0.5 pl-2">
                  {concept.tutorials.map((tutorial) => {
                    const isSelected = selectedId === tutorial.id;
                    const isCompleted = completedIds.has(tutorial.id);

                    return (
                      <div
                        key={tutorial.id}
                        onClick={() => onSelect(tutorial.id)}
                        className={cn(
                          "group flex items-start gap-2 rounded-lg p-2 text-left cursor-pointer transition-all border",
                          isSelected
                            ? "border-indigo-300 bg-indigo-50/70 shadow-2xs dark:border-indigo-800 dark:bg-indigo-950/40"
                            : "border-transparent hover:bg-slate-100/70 dark:hover:bg-slate-800/50"
                        )}
                      >
                        {/* Completion Checkbox */}
                        <button
                          type="button"
                          onClick={(e) => toggleCompleted(tutorial.id, e)}
                          title={isCompleted ? "Mark incomplete" : "Mark completed"}
                          className={cn(
                            "mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-colors",
                            isCompleted
                              ? "border-emerald-500 bg-emerald-500 text-white"
                              : "border-slate-300 hover:border-indigo-500 dark:border-slate-600 dark:hover:border-indigo-400"
                          )}
                        >
                          {isCompleted && (
                            <svg
                              xmlns="http://www.w3.org/2000/svg"
                              viewBox="0 0 20 20"
                              fill="currentColor"
                              className="h-3 w-3"
                            >
                              <path
                                fillRule="evenodd"
                                d="M16.704 4.153a.75.75 0 0 1 .143 1.052l-8 10.5a.75.75 0 0 1-1.127.075l-4.5-4.5a.75.75 0 0 1 1.06-1.06l3.894 3.893 7.48-9.817a.75.75 0 0 1 1.05-.143Z"
                                clipRule="evenodd"
                              />
                            </svg>
                          )}
                        </button>

                        {/* Title & Metadata */}
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-1">
                            <span
                              className={cn(
                                "text-xs font-semibold leading-snug line-clamp-1",
                                isSelected
                                  ? "text-indigo-950 dark:text-indigo-200"
                                  : "text-slate-800 dark:text-slate-200"
                              )}
                            >
                              {tutorial.title}
                            </span>
                            <span
                              className={cn(
                                "rounded-sm border px-1 py-0.2 text-[9px] font-mono shrink-0",
                                FAMILY_STYLE[tutorial.family]
                              )}
                            >
                              {FAMILY_BADGE[tutorial.family]}
                            </span>
                          </div>

                          <p className="mt-0.5 line-clamp-1 text-[11px] text-slate-500 dark:text-slate-400">
                            {tutorial.subtitle}
                          </p>

                          {/* Chips: Characters & Read Time */}
                          <div className="mt-1 flex items-center gap-1.5 text-[10px] text-slate-400 dark:text-slate-500">
                            <span>{tutorial.characters.join(" & ")}</span>
                            <span>•</span>
                            <span>{tutorial.readTime}</span>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
