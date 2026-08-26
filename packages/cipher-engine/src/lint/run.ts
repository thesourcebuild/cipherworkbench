import type { Diagnostic, LintRule } from "@ocs/contracts/diagnostic";
import { hasBlockingError, isInsecure, sortDiagnostics } from "@ocs/contracts/diagnostic";

export interface LintResult<TSpec = unknown> {
  diagnostics: Diagnostic<TSpec>[];
  /** The settings cannot produce a result — the compute call is suppressed. */
  hasErrors: boolean;
  /** The settings compute fine and should not be trusted; the result panel says so. */
  isInsecure: boolean;
  counts: Record<Diagnostic<TSpec>["level"], number>;
}

export function lint<TSpec>(spec: TSpec, rules: readonly LintRule<TSpec>[]): LintResult<TSpec> {
  const diagnostics: Diagnostic<TSpec>[] = [];

  for (const rule of rules) {
    try {
      diagnostics.push(...rule.check(spec));
    } catch (error) {
      // A broken rule must never take down the whole panel.
      diagnostics.push({
        code: rule.code,
        level: "warning",
        message: `Lint rule ${rule.code} failed to run.`,
        detail: error instanceof Error ? error.message : String(error),
      });
    }
  }

  const sorted = sortDiagnostics(diagnostics);

  return {
    diagnostics: sorted,
    hasErrors: hasBlockingError(sorted),
    isInsecure: isInsecure(sorted),
    counts: {
      error: sorted.filter((d) => d.level === "error").length,
      insecure: sorted.filter((d) => d.level === "insecure").length,
      warning: sorted.filter((d) => d.level === "warning").length,
      info: sorted.filter((d) => d.level === "info").length,
    },
  };
}

/**
 * Apply every diagnostic that offers a mechanical fix, in code order.
 *
 * Note this is one pass, not a fixpoint: applying a fix can surface a new
 * diagnostic (switching AES from ECB to GCM makes the missing-nonce rule fire),
 * and that is deliberate. Looping to convergence would let a pair of rules whose
 * fixes undo each other spin forever, and would hide the second problem behind
 * an automatic answer the user never saw. One pass, then the panel re-lints and
 * shows whatever is left.
 */
export function applyAllFixes<TSpec>(spec: TSpec, rules: readonly LintRule<TSpec>[]): TSpec {
  return lint(spec, rules).diagnostics.reduce(
    (current, d) => (d.fix ? d.fix.apply(current) : current),
    spec,
  );
}
