import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { MAC_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

/**
 * One MAC configuration. `variant` is the tool id — hmac, kmac, poly1305, cmac — and the
 * key, the underlying hash and the tag length all live in `options`.
 */
export const MacSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(MAC_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type MacSpec = z.infer<typeof MacSpec>;
