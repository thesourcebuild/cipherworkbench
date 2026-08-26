import { DEFAULT_HMAC_HASH, DEFAULT_KMAC_VARIANT, requireMacTool } from "./catalogue/tool-meta";
import {
  OPTION_HASH,
  OPTION_OUTPUT_LENGTH,
  OPTION_SKEIN_STATE,
  OPTION_KMAC_VARIANT,
  SPEC_VERSION,
} from "./pure";
import type { MacSpec } from "./spec";

/** The canonical default-spec factory. */
export function createSpec(options?: { variant?: string }): MacSpec {
  const variant = options?.variant ?? "hmac";
  requireMacTool(variant);

  /**
   * Every select this tool renders has to be seeded, or it opens on "(not set)".
   *
   * Skein-MAC's state size was absent from this list for as long as the control was invisible --
   * `variantTag` returned `undefined`, so `isAvailableOn` hid it and the "(not set)" gate never saw
   * it either. Fixing the tag surfaced both at once, which is the usual shape: a control that does
   * not render is also a control nothing checks.
   *
   * String values, not numbers: a select stores what the DOM gives it, and the options form renders a
   * number as "(not set)" just as it renders a missing value that way.
   */
  const base: MacSpec["options"] = {};
  if (variant === "hmac") base[OPTION_HASH] = DEFAULT_HMAC_HASH;
  if (variant === "kmac") base[OPTION_KMAC_VARIANT] = DEFAULT_KMAC_VARIANT;
  // 64 bytes is Skein-512, the state size the designers nominate and the resolver's own default.
  if (variant === "skeinmac") base[OPTION_SKEIN_STATE] = "64";
  // 8 bytes is HighwayHash-64, which is what every tool that prints one without naming a width means.
  if (variant === "highwayhash") base[OPTION_OUTPUT_LENGTH] = "8";

  return { specVersion: SPEC_VERSION, variant, options: base };
}
