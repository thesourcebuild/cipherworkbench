import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { CRC_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

/**
 * One checksum configuration.
 *
 * `variant` is the tool id — `crc32`, `crc16` — and it is also what
 * decides which named models the `model` option offers. Unlike the hash family,
 * where the algorithm *is* the tool, here the tool is a width and the algorithm is
 * one option inside it.
 */
export const CrcSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(CRC_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type CrcSpec = z.infer<typeof CrcSpec>;
