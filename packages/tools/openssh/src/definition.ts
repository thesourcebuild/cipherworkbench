import type { ToolDefinition } from "@ocs/engine";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { opensshCatalogue } from "./catalogue/options";
import { OPENSSH_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { OpenSshSpec } from "./spec";
import { describeSpec } from "./explain/describe";
import { computeOpenSsh, opensshInfo } from "./compute";
import { handleSshOptionChange } from "./pure";
import { RULES } from "./lint/rules";

export function opensshToolDefinition(toolId: string): ToolDefinition<OpenSshSpec> {
  const manifest = OPENSSH_MANIFESTS.find((m) => m.id === toolId);
  if (!manifest) {
    throw new Error(`No manifest for OpenSSH tool: ${toolId}`);
  }

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: opensshCatalogue(),
    lintRules: RULES,
    createSpec: () => createSpec({ variant: toolId }),
    specSchema: OpenSshSpec,
    describe: describeSpec,
    info: opensshInfo,
    compute: computeOpenSsh,
    onOptionChange: handleSshOptionChange,
  };
}
