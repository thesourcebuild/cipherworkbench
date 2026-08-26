import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { CLASSICAL_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

/**
 * One classical-cipher configuration.
 *
 * `variant` is the tool id and fully determines which cipher runs, as in the parity and checksum
 * families: the options say how it is parameterised, not which algorithm it is.
 */
export const ClassicalSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(CLASSICAL_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type ClassicalSpec = z.infer<typeof ClassicalSpec>;
