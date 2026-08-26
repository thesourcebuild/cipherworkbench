/**
 * error    — the tool cannot produce a correct result with these settings, or
 *            will reject them outright (wrong key length, missing IV).
 * insecure — the settings compute fine and are cryptographically unsafe. ECB
 *            mode, a reused GCM nonce, RC4, MD5 for a signature. This is the
 *            level that earns this app its keep over a plain calculator, so it
 *            sits above `warning` rather than being folded into it.
 * warning  — legal, works, and probably not what was intended: unauthenticated
 *            CBC, a PBKDF2 iteration count below the current floor.
 * info     — semantics worth knowing. A CRC is not a hash; SHAKE output length
 *            is yours to choose.
 */
export type DiagnosticLevel = "error" | "insecure" | "warning" | "info";

export const DIAGNOSTIC_LEVEL_ORDER: readonly DiagnosticLevel[] = [
  "error",
  "insecure",
  "warning",
  "info",
];

export interface DiagnosticFix<TSpec = unknown> {
  label: string;
  /** Pure: returns a corrected spec, never mutates. */
  apply: (spec: TSpec) => TSpec;
}

export interface Diagnostic<TSpec = unknown> {
  /** Stable identifier, e.g. "H001". Never reuse a retired code. */
  code: string;
  level: DiagnosticLevel;
  /** One line, shown inline in the diagnostics panel. */
  message: string;
  /** Optional paragraph explaining why. */
  detail?: string;
  /** Option ids this diagnostic points at, so the form can highlight them. */
  optionIds?: string[];
  /** Which spec field it points at, when not an option. Tool-specific field names, so left as a bare string. */
  field?: string;
  fix?: DiagnosticFix<TSpec>;
}

export interface LintRule<TSpec = unknown> {
  code: string;
  /** Returns [] when the rule does not apply. Must be pure. */
  check: (spec: TSpec) => Diagnostic<TSpec>[];
}

export function sortDiagnostics<TSpec>(list: readonly Diagnostic<TSpec>[]): Diagnostic<TSpec>[] {
  return [...list].sort((a, b) => {
    const d =
      DIAGNOSTIC_LEVEL_ORDER.indexOf(a.level) - DIAGNOSTIC_LEVEL_ORDER.indexOf(b.level);
    return d !== 0 ? d : a.code.localeCompare(b.code);
  });
}

/**
 * True when the spec cannot compute at all. Unlike the command-generator this
 * app is modelled on — where an "error" diagnostic still let you copy the text
 * and decide for yourself — an error here genuinely blocks: there is no
 * meaningful output to show for a 13-byte AES key.
 */
export function hasBlockingError<TSpec>(list: readonly Diagnostic<TSpec>[]): boolean {
  return list.some((d) => d.level === "error");
}

/** True when the spec computes but should not be trusted. Drives the result panel's warning banner. */
export function isInsecure<TSpec>(list: readonly Diagnostic<TSpec>[]): boolean {
  return list.some((d) => d.level === "insecure");
}
