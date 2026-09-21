import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { CERTIFICATE_TOOL_IDS } from "./catalogue/tool-meta";
import { SPEC_VERSION } from "./pure";

export const CertificateSpec = z.object({
  specVersion: z.literal(SPEC_VERSION),
  variant: z.enum(CERTIFICATE_TOOL_IDS as [string, ...string[]]),
  options: OptionValues,
});

export type CertificateSpec = z.infer<typeof CertificateSpec>;
