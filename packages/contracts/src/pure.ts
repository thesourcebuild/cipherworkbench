/**
 * Runtime helpers with NO zod import.
 *
 * This separation is load-bearing, not cosmetic. The UI needs `setOption` but
 * never validates anything at runtime — validation happens at trust boundaries
 * (share-link parsing, saved-state loading, the Electron main process). When
 * these helpers lived alongside schema definitions, importing `setOption`
 * pulled the schema module into the module graph, which constructs every zod
 * schema at module evaluation time, which put all of zod in the browser bundle
 * for no benefit.
 *
 * Rule for this file: type-only imports (erased at compile time) are fine;
 * a value import from a schema module is not.
 */
import type { OptionValue, OptionValues } from "./options";

// ── option accessors ────────────────────────────────────────────────────────
// `options` is an open record keyed by a tool's own catalogue id, so all
// reads/writes go through these instead of naming fields directly.

export function optBool(options: OptionValues, id: string): boolean {
  return options[id] === true;
}

export function optString(options: OptionValues, id: string): string | undefined {
  const v = options[id];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

export function optNumber(options: OptionValues, id: string): number | undefined {
  const v = options[id];
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

export function optList(options: OptionValues, id: string): string[] {
  const v = options[id];
  return Array.isArray(v) ? v : [];
}

export function optEnum<T extends string>(
  options: OptionValues,
  id: string,
  allowed: readonly T[],
): T | undefined {
  const v = options[id];
  return typeof v === "string" && (allowed as readonly string[]).includes(v) ? (v as T) : undefined;
}

/**
 * Reads an option with a guaranteed fallback. Most compute paths want this
 * rather than `optEnum(...) ?? "default"` repeated at every call site: a tool's
 * mode/variant option is never legitimately absent, so the fallback belongs
 * next to the read.
 */
export function optEnumOr<T extends string>(
  options: OptionValues,
  id: string,
  allowed: readonly T[],
  fallback: T,
): T {
  return optEnum(options, id, allowed) ?? fallback;
}

export function setOption(
  options: OptionValues,
  id: string,
  value: OptionValue | undefined,
): OptionValues {
  const next = { ...options };
  if (value === undefined || value === false || value === "") delete next[id];
  else next[id] = value;
  return next;
}

export function setOptions(
  options: OptionValues,
  patch: Record<string, OptionValue | undefined>,
): OptionValues {
  return Object.entries(patch).reduce((o, [id, v]) => setOption(o, id, v), options);
}

/** Builds a fresh `OptionValues` from `patch` alone, discarding whatever was already set. */
export function replaceOptions(patch: Record<string, OptionValue | undefined>): OptionValues {
  return setOptions({}, patch);
}
