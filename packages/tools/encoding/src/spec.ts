import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { ENCODING_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

/**
 * One encoding configuration.
 *
 * `variant` here is the tool id — `hex`, `base64`, `cbor` — and the *alphabet* is an option inside
 * it, which is the opposite of the hash family where the algorithm is the tool. Base64 and
 * base64url are the same tool with a different table; SHA-256 and BLAKE3 are not.
 */
export const EncodingSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(ENCODING_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type EncodingSpec = z.infer<typeof EncodingSpec>;
