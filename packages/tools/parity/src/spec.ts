import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { PARITY_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

/**
 * One parity configuration.
 *
 * `variant` is the tool id and fully determines the computation, as in the checksum family: the
 * options say which convention, not which algorithm.
 */
export const ParitySpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(PARITY_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type ParitySpec = z.infer<typeof ParitySpec>;
