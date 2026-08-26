import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { HASH_ALGORITHM_IDS } from "./catalogue/algorithm-meta";
import { SPEC_VERSION } from "./pure";

/**
 * One digest configuration.
 *
 * `algorithm` is also the tool id — each digest is its own entry in the sidebar
 * rather than one "Hash" tool with a dropdown. That mirrors how people actually
 * arrive here (searching for "sha256", or landing on a link to it) and is what
 * lets a share link and a saved state name a specific algorithm without a
 * second field.
 *
 * Validated at trust boundaries only — share-link parsing and saved-state
 * loading. The UI mutates a spec freely without re-validating on every keystroke.
 */
export const HashSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  algorithm: z.enum(HASH_ALGORITHM_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type HashSpec = z.infer<typeof HashSpec>;
