import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { CHECKSUM_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

/**
 * One checksum configuration.
 *
 * `variant` is the tool id, and unlike the CRC family it fully determines the algorithm — the
 * options only say how wide the answer is and how the bytes were grouped on their way in.
 */
export const ChecksumSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(CHECKSUM_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type ChecksumSpec = z.infer<typeof ChecksumSpec>;
