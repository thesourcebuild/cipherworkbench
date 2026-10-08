import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { OPENSSH_TOOL_IDS } from "./catalogue/tool-meta";

export const SPEC_VERSION = 1;

export const OpenSshSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(OPENSSH_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type OpenSshSpec = z.infer<typeof OpenSshSpec>;
