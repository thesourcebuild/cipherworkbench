import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { FORMAT_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

/**
 * One format configuration.
 *
 * `variant` is the tool id -- `json`, `url`, `uuid` -- and everything that distinguishes one run from
 * another is an option inside it. Same arrangement as `@ocs/encoding`, for the same reason: minifying
 * JSON and indenting it are one tool with a verb, where SHA-256 and BLAKE3 are two tools.
 */
export const FormatSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(FORMAT_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type FormatSpec = z.infer<typeof FormatSpec>;
