import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { KDF_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

/** One derivation or verification. `variant` is the tool id. */
export const KdfSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(KDF_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type KdfSpec = z.infer<typeof KdfSpec>;
