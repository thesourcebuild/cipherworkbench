import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { CHECK_DIGIT_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

/**
 * One check digit tool configuration.
 */
export const CheckDigitSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(CHECK_DIGIT_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type CheckDigitSpec = z.infer<typeof CheckDigitSpec>;
