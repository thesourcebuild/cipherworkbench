import { z } from "zod";
import { OptionValues } from "@ocs/contracts/options";
import { PASSWORD_ARTIFACT_TOOL_IDS } from "./catalogue/tool-meta";

export const PasswordArtifactSpec = z.object({
  specVersion: z.literal(1),
  variant: z.enum(PASSWORD_ARTIFACT_TOOL_IDS),
  options: OptionValues,
});

export type PasswordArtifactSpec = z.infer<typeof PasswordArtifactSpec>;
