import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { CIPHER_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

/** One encryption or decryption. `variant` is the tool id. */
export const CipherSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(CIPHER_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type CipherSpec = z.infer<typeof CipherSpec>;
