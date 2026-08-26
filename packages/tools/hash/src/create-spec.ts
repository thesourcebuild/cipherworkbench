import { requireHashAlgorithm } from "./catalogue/algorithm-meta";
import { OPTION_OUTPUT_LENGTH, OPTION_HASH_VARIANT, OPTION_PASSES, SPEC_VERSION } from "./pure";
import type { HashSpec } from "./spec";

/** The canonical default-spec factory. Every builder and test starts here. */
export function createSpec(options?: { algorithm?: string }): HashSpec {
  const algorithm = options?.algorithm ?? "sha256";
  // Fails loudly rather than producing a spec no binding exists for.
  const meta = requireHashAlgorithm(algorithm);
  /**
   * Seed the controls that are selects, because an unseeded select reads "(not set)".
   *
   * The compute path already falls back to these exact values, so this changes no output -- it
   * changes what the form *shows*. Leaving them empty meant opening HAVAL on a Passes dropdown with
   * nothing chosen while the digest underneath was quietly computed at the default, which is the
   * worst of both: it looks broken and it is not.
   *
   * String values, not numbers: a select stores what the DOM gives it, and `value={typeof value ===
   * "string" ? value : ""}` in the options form renders a number as "(not set)" too.
   */
  const seeded: HashSpec["options"] = {};
  if (meta.outputLengths) seeded[OPTION_OUTPUT_LENGTH] = String(meta.outputLen);
  if (meta.passes) seeded[OPTION_PASSES] = String(meta.defaultPasses ?? meta.passes[0]!);
  if (meta.variants) seeded[OPTION_HASH_VARIANT] = meta.defaultVariant ?? meta.variants[0]!.id;

  return {
    specVersion: SPEC_VERSION,
    algorithm,
    options: seeded,
  };
}
