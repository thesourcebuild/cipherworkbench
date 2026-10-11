import type { ToolDefinition, ToolSample } from "@ocs/engine";
import { PASSWORD_ARTIFACT_CATALOGUE } from "./catalogue/options";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { PASSWORD_ARTIFACT_TOOL_IDS, requirePasswordArtifactTool } from "./catalogue/tool-meta";
import { PASSWORD_ARTIFACT_MANIFESTS } from "./manifest";
import { PasswordArtifactSpec } from "./spec";
import {
  computePasswordArtifact,
  computePasswordArtifactFile,
  passwordArtifactInfo,
} from "./compute";
import { OPTION_BITLOCKER_OFFSET, OPTION_TRUECRYPT_BOOT_MODE } from "./catalogue/options";

const SAMPLES: Readonly<Record<string, readonly ToolSample[]>> = {
  "hash-identifier": [
    {
      id: "bcrypt",
      label: "bcrypt record",
      note: "A self-describing bcrypt string with version and cost.",
      text: "$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxZ9K1Cw1nQyXGz4h8eK0iF7m2O",
    },
  ],
  grafana2hashcat: [
    {
      id: "grafana-record",
      label: "Grafana record",
      note: "A 32-byte digest followed by its literal salt.",
      text: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f,YObSoLj55S",
    },
  ],
  gitea2hashcat: [
    {
      id: "gitea-record",
      label: "Gitea record",
      note: "A 16-byte hex salt and 50-byte hex digest, as selected from the user table.",
      text: "000102030405060708090a0b0c0d0e0f:101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041",
    },
  ],
};

export function passwordArtifactToolDefinition(
  toolId: string,
): ToolDefinition<PasswordArtifactSpec> {
  const meta = requirePasswordArtifactTool(toolId);
  const manifest = PASSWORD_ARTIFACT_MANIFESTS.find((candidate) => candidate.id === toolId);
  if (!manifest) throw new Error(`No manifest for password artifact tool: ${toolId}`);
  const defaultOptions: Record<string, string | number | boolean | string[]> = {};
  if (meta.kind === "truecrypt") defaultOptions[OPTION_TRUECRYPT_BOOT_MODE] = false;
  if (meta.kind === "bitlocker") defaultOptions[OPTION_BITLOCKER_OFFSET] = 0;

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: PASSWORD_ARTIFACT_CATALOGUE,
    lintRules: [],
    samples: SAMPLES[toolId] ?? [],
    createSpec: () => ({ specVersion: 1, variant: meta.id, options: { ...defaultOptions } }),
    specSchema: PasswordArtifactSpec,
    describe: () => meta.summary,
    info: passwordArtifactInfo,
    compute: computePasswordArtifact,
    computeFile: computePasswordArtifactFile,
    variantTag: () => meta.kind,
  };
}

export { PASSWORD_ARTIFACT_TOOL_IDS };
export {
  computePasswordArtifact,
  computePasswordArtifactFile,
  passwordArtifactInfo,
} from "./compute";
export { identifyHashArtifact } from "./hash-identifier";
export type {
  HashIdentificationCandidate,
  HashIdentificationConfidence,
} from "./hash-identifier";
export { convertGrafanaToHashcat, convertGiteaToHashcat } from "./converters";
export { PasswordArtifactSpec } from "./spec";
