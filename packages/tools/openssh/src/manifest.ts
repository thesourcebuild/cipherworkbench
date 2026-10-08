import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { OPENSSH_TOOLS, type OpenSshToolMeta } from "./catalogue/tool-meta";

const TEXT_ONLY: readonly OutputEncoding[] = ["utf-8"];

function toManifest(meta: OpenSshToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "openssh",
    category: meta.category,
    tags: [...meta.tags],
    directions: ["forward"],
    summary: meta.summary,
    security: "modern",
    outputEncodings: TEXT_ONLY,
    supportsFile: false,
    readsInput: false,
    supportsVerify: false,
    streaming: false,
  };
}

export const OPENSSH_MANIFESTS: readonly ToolManifest[] = OPENSSH_TOOLS.map(toManifest);
