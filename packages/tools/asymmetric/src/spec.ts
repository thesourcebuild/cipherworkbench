import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { ASYMMETRIC_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

/** One public-key operation. `variant` is the tool id. */
export const AsymmetricSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(ASYMMETRIC_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type AsymmetricSpec = z.infer<typeof AsymmetricSpec>;
