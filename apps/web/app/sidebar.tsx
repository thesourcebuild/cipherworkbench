"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import type { ToolFamily, ToolManifest } from "@ocs/engine";
import { cn } from "@ocs/ui";

export interface SidebarProps {
  manifests: readonly ToolManifest[];
  families: readonly ToolFamily[];
  selectedId: string;
  onSelect: (id: string) => void;
  onCollapse: () => void;
}

const FAMILY_LABEL: Record<ToolFamily, string> = {
  hash: "Hashes",
  crc: "CRC",
  checksum: "Checksums",
  parity: "Parity",
  mac: "MACs",
  kdf: "Key derivation",
  cipher: "Ciphers",
  classical: "Classical",
  asymmetric: "Public key",
  encoding: "Encodings",
  format: "Formats",
};

/**
 * Per-family colours for the badge on each tool.
 *
 * This replaced a security-posture badge -- `modern` / `legacy` / `broken` / `checksum` on every
 * row. That was noise in a list: the posture only matters once you have chosen a tool, where the
 * header states it with the reason attached, and a wall of red "broken" chips beside MD5, MD4, MD2,
 * RC4 and the rest trains people to stop reading badges entirely. The family is what a reader
 * actually needs from a flat, searchable list -- it says why SHA-256 and CRC-32 are different kinds
 * of thing, which is the distinction this app exists to make.
 */
const FAMILY_STYLE: Record<ToolFamily, string> = {
  hash: "border-violet-200 bg-violet-50 text-violet-700 dark:border-violet-900 dark:bg-violet-950/40 dark:text-violet-300",
  crc: "border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950/40 dark:text-sky-300",
  checksum:
    "border-cyan-200 bg-cyan-50 text-cyan-700 dark:border-cyan-900 dark:bg-cyan-950/40 dark:text-cyan-300",
  // Teal: adjacent to the other two error-detection families and distinct from both, which is the
  // relationship -- parity, checksums and CRCs are one idea at three strengths.
  parity:
    "border-teal-200 bg-teal-50 text-teal-700 dark:border-teal-900 dark:bg-teal-950/40 dark:text-teal-300",
  mac: "border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-300",
  kdf: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300",
  cipher:
    "border-rose-200 bg-rose-50 text-rose-700 dark:border-rose-900 dark:bg-rose-950/40 dark:text-rose-300",
  // Stone: next to the ciphers in the list and deliberately the quietest chip in it. A Caesar cipher
  // is encryption in name; a colour as strong as rose would put it on a level with AES-GCM.
  classical:
    "border-stone-300 bg-stone-100 text-stone-600 dark:border-stone-700 dark:bg-stone-900/60 dark:text-stone-300",
  asymmetric:
    "border-indigo-200 bg-indigo-50 text-indigo-700 dark:border-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-300",
  encoding:
    "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300",
  format:
    "border-slate-200 bg-slate-50 text-slate-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300",
};

/**
 * The "you are here" dot on a family or category heading.
 *
 * Green when the selected tool lives under that heading, hollow slate otherwise. It replaced a
 * per-family colour on the family dot, which looked informative and was not: the row badges already
 * carry the family hue, so all a second copy of it did was compete with the one thing a heading
 * genuinely needs to say, which is whether the tool in front of you came from there. Both levels get
 * one, so a collapsed sidebar still shows which family *and* which group you are in.
 *
 * Green rather than the app's blue focus colour, so it cannot be mistaken for keyboard focus, and a
 * border in both states so the dot does not change size when it lights up. The shade is
 * `--color-nav-here`, shared with the switch; it started brighter and read as a row of little lamps
 * shouting over the tool names.
 *
 * A hollow dot also lights on hover of its heading, which is why both headings carry `group`. Hover
 * only, deliberately not `focus-visible`: green is the "you are here" colour and blue is focus, and
 * lighting this one on keyboard focus would collapse the distinction the paragraph above exists to
 * keep.
 */
function HereDot({ active, className }: { active: boolean; className?: string }) {
  return (
    <span
      aria-hidden
      className={cn(
        "h-2 w-2 shrink-0 rounded-full border transition-colors",
        active
          ? "border-(--color-nav-here) bg-(--color-nav-here)"
          : // Lights up on hover of the heading it sits in, which is what makes it read as part of
            // that control rather than an ornament beside it. `group-hover` and not a hover on the
            // dot itself: the pointer is almost never over an 8px circle, and a dot that only lit
            // when you hit it exactly would look broken. The heading's own background lifts at the
            // same time, so a hovered heading is still distinguishable from the selected one.
            "border-slate-300 bg-transparent group-hover:border-(--color-nav-here) group-hover:bg-(--color-nav-here) dark:border-slate-600",
        className,
      )}
    />
  );
}

/** Short forms, so the badge does not crowd the tool name. */
const FAMILY_BADGE: Record<ToolFamily, string> = {
  hash: "hash",
  crc: "CRC",
  checksum: "sum",
  parity: "parity",
  mac: "MAC",
  kdf: "KDF",
  cipher: "cipher",
  classical: "classic",
  asymmetric: "key",
  encoding: "enc",
  format: "fmt",
};

/**
 * Left rail: search, family filter, and the tool list grouped by family and then by category.
 *
 * **Two levels, not one.** The family is the top heading — Checksums, CRC, Hashes, MACs, and so on
 * in `FAMILY_ORDER` — and the categories a family declares (SHA-2, Keccak, Sums, Block checks) are
 * subheadings inside it. Eighty tools in one flat run of categories left "SHA-3" and "Fletcher and
 * Adler" as siblings, which reads as though they are alternatives to each other; they are not, and
 * the family boundary is exactly the distinction this app exists to make.
 *
 * Neither level is alphabetical, deliberately. Someone looking for SHA-384 wants SHA-224/256/512
 * next to it, because the question they are really answering is "which one of these" — an A–Z list
 * would put SHA-384 between SHA-3 and SHA-512 and scatter the family across the letter S. Families
 * are ordered by what their output can be trusted to do (see `FAMILY_ORDER`), and categories keep
 * the order their package declares, which is the order they superseded one another in.
 *
 * A family whose categories add nothing over its own name renders no subheading at all. That is not
 * cosmetic: the CRC family has one category called "CRC", and nesting it under a heading reading
 * "CRC" was a real earlier bug in this file's flat version, where the sidebar showed "CRC-32" inside
 * "CRC-32".
 *
 * Every entry still carries its *family* as a badge, which is redundant beside its own heading and
 * earns its place the moment you scroll or search: search results span families, and the badge is
 * what tells you the CRC-32 and the XOR checksum in front of you are different kinds of answer. It
 * used to carry the security posture instead, which read badly in a list — most of the legacy
 * digests are "broken", so the column became a wall of red that says nothing about the choice in
 * front of you. The posture still exists; it drives the lint rules and the tool header states it
 * with the reason attached.
 */
export function Sidebar({
  manifests,
  families,
  selectedId,
  onSelect,
  onCollapse,
}: SidebarProps) {
  const [search, setSearch] = useState("");
  const [activeFamily, setActiveFamily] = useState<ToolFamily | null>(null);
  /**
   * Collapse state for both levels, in one set, keyed `family:<id>` or `cat:<family>/<label>`.
   *
   * One set rather than two because the two levels never need to be reasoned about separately, and
   * the category key carries its family: two families are free to declare a category of the same
   * name, and an unqualified key would collapse both.
   */
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const searchRef = useRef<HTMLInputElement | null>(null);

  // "/" focuses search, as in every other tool with a list this long.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "/" || event.metaKey || event.ctrlKey) return;
      const target = event.target as HTMLElement | null;
      if (target && /^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return;
      event.preventDefault();
      searchRef.current?.focus();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  const filtered = useMemo(() => {
    let list = [...manifests];
    if (activeFamily) list = list.filter((m) => m.family === activeFamily);
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(
        (m) =>
          m.label.toLowerCase().includes(q) ||
          m.id.toLowerCase().includes(q) ||
          m.summary.toLowerCase().includes(q) ||
          m.category.toLowerCase().includes(q) ||
          m.tags.some((tag) => tag.toLowerCase().includes(q)),
      );
    }
    return list;
  }, [manifests, search, activeFamily]);

  /**
   * Tool count per family, for the filter's option labels.
   *
   * Deliberately over `manifests` rather than `filtered`: the number has to mean "how many tools
   * this family has", not "how many survive the current search" -- the latter would make every
   * option read (0) the moment a search matched nothing, which is exactly when someone reaches for
   * the family filter.
   */
  const familyCounts = useMemo(() => {
    const counts = new Map<ToolFamily, number>();
    for (const manifest of manifests) {
      counts.set(manifest.family, (counts.get(manifest.family) ?? 0) + 1);
    }
    return counts;
  }, [manifests]);

  /**
   * Where the selected tool lives, for the indicator dots.
   *
   * Read from `manifests` rather than from `filtered`: a search or a family filter can hide the
   * selected tool without deselecting it, and the heading it belongs to should still be the one
   * marked when it comes back into view.
   */
  const here = useMemo(
    () => manifests.find((manifest) => manifest.id === selectedId),
    [manifests, selectedId],
  );

  /**
   * The two-level tree: families in `FAMILY_ORDER`, categories in declaration order.
   *
   * Families come from the `families` prop rather than from the order the manifests happen to be
   * concatenated in, so the list and the filter dropdown cannot disagree. Categories keep the order
   * they first appear in `manifests`, which is the order each family package declares — MD before
   * SHA-1 before SHA-2, not alphabetical, because that is the order they were superseded in.
   */
  const groups = useMemo(() => {
    const byFamily = new Map<ToolFamily, Map<string, ToolManifest[]>>();
    for (const manifest of filtered) {
      let categories = byFamily.get(manifest.family);
      if (!categories) {
        categories = new Map();
        byFamily.set(manifest.family, categories);
      }
      const list = categories.get(manifest.category) ?? [];
      list.push(manifest);
      categories.set(manifest.category, list);
    }

    return families
      .filter((family) => byFamily.has(family))
      .map((family) => {
        const entries = [...byFamily.get(family)!.entries()];
        return {
          family,
          count: entries.reduce((total, [, tools]) => total + tools.length, 0),
          /**
           * `null` where a subheading would say nothing the family heading has not.
           *
           * One category means the split is an artefact of the data model rather than a real
           * grouping — CRC is the case, with a single category also called "CRC".
           */
          sections:
            entries.length === 1
              ? [{ label: null, tools: entries[0]![1] }]
              : entries.map(([label, tools]) => ({ label, tools })),
        };
      });
  }, [filtered, families]);

  const toggle = (key: string) =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b border-slate-200 px-3 py-2.5 dark:border-slate-800">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500 dark:text-slate-400">
            Tools
          </p>
          <p className="mt-0.5 text-xs text-slate-400 dark:text-slate-500">
            {manifests.length} algorithms
          </p>
        </div>
        <button
          type="button"
          onClick={onCollapse}
          aria-label="Collapse sidebar"
          title="Collapse sidebar"
          className="rounded-md border border-slate-200 p-1.5 text-slate-500 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:text-slate-400 dark:hover:bg-slate-800"
        >
          <CollapseIcon />
        </button>
      </div>

      <div className="space-y-2 border-b border-slate-200 p-3 dark:border-slate-800">
        <div className="relative">
          <SearchIcon className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            ref={searchRef}
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search  ( / )"
            className="w-full rounded-md border border-slate-300 bg-white py-1.5 pl-8 pr-2 text-xs dark:border-slate-700 dark:bg-slate-950"
          />
        </div>

        {families.length > 1 && (
          <select
            aria-label="Filter by family"
            data-ocs-family=""
            value={activeFamily ?? ""}
            onChange={(event) =>
              setActiveFamily(
                event.target.value === "" ? null : (event.target.value as ToolFamily),
              )
            }
            className="w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 text-xs text-slate-700 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300"
          >
            <option value="">All families ({manifests.length})</option>
            {families.map((family) => (
              <option key={family} value={family}>
                {FAMILY_LABEL[family]} ({familyCounts.get(family) ?? 0})
              </option>
            ))}
          </select>
        )}
      </div>

      <nav className="flex-1 overflow-y-auto p-2">
        {groups.length === 0 && (
          <p className="px-2 py-4 text-xs text-slate-500 dark:text-slate-400">
            Nothing matches “{search}”.
          </p>
        )}
        {groups.map(({ family, count, sections }) => {
          const familyKey = `family:${family}`;
          const familyOpen = !collapsed.has(familyKey);
          return (
            <div key={family} className="mb-2">
              <button
                type="button"
                // Hook for the same reason `data-ocs-tool` exists: a family heading and a category
                // heading can render the same string, so a test cannot select either by text.
                data-ocs-family-group={family}
                onClick={() => toggle(familyKey)}
                aria-expanded={familyOpen}
                className="group flex w-full items-center gap-1.5 rounded px-1.5 py-1.5 text-left text-[11px] font-semibold uppercase tracking-[0.1em] text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
              >
                <ChevronIcon collapsed={!familyOpen} />
                <HereDot active={here?.family === family} />
                {FAMILY_LABEL[family]}
                <span className="ml-auto font-normal normal-case tracking-normal text-slate-400">
                  {count}
                </span>
              </button>

              {familyOpen &&
                sections.map(({ label, tools }) => {
                  if (label === null) {
                    return (
                      <div key="__all">
                        {tools.map((manifest) => (
                          <ToolRow
                            key={manifest.id}
                            manifest={manifest}
                            selected={manifest.id === selectedId}
                            onSelect={onSelect}
                          />
                        ))}
                      </div>
                    );
                  }
                  const categoryKey = `cat:${family}/${label}`;
                  const categoryOpen = !collapsed.has(categoryKey);
                  return (
                    <div key={label} className="mt-1 pl-2">
                      <button
                        type="button"
                        onClick={() => toggle(categoryKey)}
                        aria-expanded={categoryOpen}
                        className="group flex w-full items-center gap-1.5 rounded px-1.5 py-1 text-left text-[10px] font-semibold uppercase tracking-wide text-slate-500 hover:bg-slate-100 dark:hover:bg-slate-800"
                      >
                        <ChevronIcon collapsed={!categoryOpen} />
                        <HereDot active={here?.family === family && here.category === label} />
                        {label}
                        <span className="ml-auto font-normal text-slate-400">
                          {tools.length}
                        </span>
                      </button>
                      {categoryOpen &&
                        tools.map((manifest) => (
                          <ToolRow
                            key={manifest.id}
                            manifest={manifest}
                            selected={manifest.id === selectedId}
                            onSelect={onSelect}
                          />
                        ))}
                    </div>
                  );
                })}
            </div>
          );
        })}
      </nav>
    </div>
  );
}

/**
 * One tool in the list.
 *
 * Extracted only because the tree renders it from two places — inside a category subgroup and
 * directly under a family that has no subgroups. Not a per-tool component: it is driven entirely by
 * a `ToolManifest`, which is the whole reason this app has one sidebar rather than one per family.
 */
function ToolRow({
  manifest,
  selected,
  onSelect,
}: {
  manifest: ToolManifest;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  return (
    <button
      type="button"
      // Stable hook for the desktop smoke test. Needed rather than matching on label text: a
      // heading can render the same string as a tool inside it, and the probe was clicking the
      // collapse toggle instead of selecting the tool.
      data-ocs-tool={manifest.id}
      onClick={() => onSelect(manifest.id)}
      aria-current={selected}
      className={cn(
        "mt-0.5 block w-full rounded-md px-2 py-1.5 text-left transition-colors",
        selected
          ? "bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900"
          : "hover:bg-slate-100 dark:hover:bg-slate-800",
      )}
    >
      <span className="flex items-center gap-1.5">
        <span className="truncate text-xs font-medium">{manifest.label}</span>
        <span
          title={FAMILY_LABEL[manifest.family]}
          className={cn(
            "ml-auto shrink-0 rounded border px-1 text-[9px] font-medium",
            selected ? "border-current opacity-80" : FAMILY_STYLE[manifest.family],
          )}
        >
          {FAMILY_BADGE[manifest.family]}
        </span>
      </span>
      <span
        className={cn(
          "mt-0.5 block truncate text-[11px]",
          selected ? "opacity-70" : "text-slate-500 dark:text-slate-400",
        )}
      >
        {manifest.summary}
      </span>
    </button>
  );
}

function SearchIcon({ className }: { className?: string }) {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      className={className}
    >
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}

function ChevronIcon({ collapsed }: { collapsed: boolean }) {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={cn("shrink-0 transition-transform", collapsed ? "-rotate-90" : "")}
    >
      <polyline points="6 9 12 15 18 9" />
    </svg>
  );
}

function CollapseIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <polyline points="15 18 9 12 15 6" />
    </svg>
  );
}
