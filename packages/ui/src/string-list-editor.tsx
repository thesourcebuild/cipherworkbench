"use client";

import { useId, useState } from "react";
import { Button } from "./button";
import { cn } from "./cn";

export interface StringListEditorProps {
  items: readonly string[];
  onChange: (next: string[]) => void;
  label: string;
  placeholder?: string;
  /** Shown per row, e.g. a byte count. Indexed the same as `items`. */
  itemHints?: readonly (string | undefined)[];
  /** Per-row problem, in the error colour. Indexed the same as `items`. */
  itemProblems?: readonly (string | undefined)[];
  hint?: string;
  /** Right-hand control above the rows -- the encoding selector, for a list of byte strings. */
  trailing?: React.ReactNode;
  maxItems?: number;
  emptyHint?: string;
}

/**
 * An ordered list of values with add, remove and reorder.
 *
 * Modelled on the command generator's editor of the same name, with two additions that this
 * app needs and a command builder does not. Order is editable, because for TupleHash the order
 * of the elements changes the digest -- it is data, not presentation. And each row carries its
 * own hint and problem slot, so a byte count and an "element 3 is not valid hex" can sit against
 * the row they describe rather than in one message about the whole list.
 */
export function StringListEditor({
  items,
  onChange,
  label,
  placeholder,
  itemHints,
  itemProblems,
  hint,
  trailing,
  maxItems,
  emptyHint,
}: StringListEditorProps) {
  const [draft, setDraft] = useState("");
  const id = useId();
  const atCapacity = maxItems !== undefined && items.length >= maxItems;

  const add = () => {
    // Not trimmed, and empty is allowed: a zero-length element is a legitimate tuple member and
    // trimming would silently change the bytes being hashed.
    if (atCapacity) return;
    onChange([...items, draft]);
    setDraft("");
  };

  const removeAt = (index: number) => onChange(items.filter((_, i) => i !== index));
  const updateAt = (index: number, value: string) =>
    onChange(items.map((item, i) => (i === index ? value : item)));

  const move = (index: number, delta: number) => {
    const target = index + delta;
    if (target < 0 || target >= items.length) return;
    const next = [...items];
    const [moved] = next.splice(index, 1);
    next.splice(target, 0, moved!);
    onChange(next);
  };

  const rowClass = cn(
    "min-w-0 flex-1 rounded-md border px-2 py-1.5 font-mono text-xs",
    "border-slate-300 bg-white text-slate-900 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-100",
  );

  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-2">
        <label htmlFor={id} className="text-xs font-medium text-slate-700 dark:text-slate-300">
          {label}
        </label>
        {trailing}
      </div>

      {items.length === 0 && emptyHint && (
        <p className="text-[11px] text-slate-400 dark:text-slate-500">{emptyHint}</p>
      )}

      {items.map((item, index) => (
        <div key={index} className="space-y-0.5">
          <div className="flex items-center gap-1">
            <span className="w-5 shrink-0 text-right text-[10px] tabular-nums text-slate-400">
              {index + 1}
            </span>
            <input
              value={item}
              onChange={(event) => updateAt(index, event.target.value)}
              placeholder={placeholder}
              spellCheck={false}
              className={cn(
                rowClass,
                itemProblems?.[index] && "border-(--color-severity-error)",
              )}
            />
            {/* Order is part of the value for TupleHash, so it has to be editable. */}
            <Button
              size="sm"
              variant="ghost"
              onClick={() => move(index, -1)}
              disabled={index === 0}
              aria-label={`Move element ${index + 1} up`}
              title="Move up"
            >
              &uarr;
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => move(index, 1)}
              disabled={index === items.length - 1}
              aria-label={`Move element ${index + 1} down`}
              title="Move down"
            >
              &darr;
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => removeAt(index)}
              aria-label={`Remove element ${index + 1}`}
              title="Remove"
            >
              &times;
            </Button>
          </div>
          {(itemProblems?.[index] ?? itemHints?.[index]) && (
            <p
              className={cn(
                "pl-6 text-[10px]",
                itemProblems?.[index]
                  ? "text-(--color-severity-error)"
                  : "text-slate-500 dark:text-slate-400",
              )}
            >
              {itemProblems?.[index] ?? itemHints?.[index]}
            </p>
          )}
        </div>
      ))}

      <div className="flex items-center gap-1">
        <span className="w-5 shrink-0" />
        <input
          id={id}
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              add();
            }
          }}
          placeholder={atCapacity ? `At most ${maxItems} elements` : placeholder}
          disabled={atCapacity}
          spellCheck={false}
          className={cn(rowClass, "disabled:opacity-50")}
        />
        <Button size="sm" variant="secondary" onClick={add} disabled={atCapacity}>
          Add
        </Button>
      </div>

      {hint && <p className="text-[11px] text-slate-500 dark:text-slate-400">{hint}</p>}
    </div>
  );
}
