import type { ToolManifest } from "@ocs/engine";
import { PASSWORD_ARTIFACT_TOOLS } from "./catalogue/tool-meta";

const MAX_ARTIFACT_FILE_BYTES = 4 * 1024 * 1024;

export const PASSWORD_ARTIFACT_MANIFESTS: readonly ToolManifest[] = PASSWORD_ARTIFACT_TOOLS.map(
  (tool) => ({
    id: tool.id,
    label: tool.label,
    family: "password-artifact",
    category: tool.category,
    tags: [...tool.tags],
    summary: tool.summary,
    purpose: tool.kind === "hash-identifier" ? "analysis" : "extraction",
    directions: [],
    outputEncodings: ["utf-8"],
    readsInput: true,
    supportsVerify: false,
    supportsFile: true,
    streaming: false,
    sourcePolicy:
      tool.kind === "hash-identifier" || tool.kind === "grafana" || tool.kind === "gitea"
        ? {
            semantics: "text-artifact" as const,
            maxFileBytes: MAX_ARTIFACT_FILE_BYTES,
            accept: ["text/plain", "text/csv", ".txt", ".csv"],
          }
        : {
            semantics: "file-artifact" as const,
            ...(tool.maxFileBytes === undefined ? {} : { maxFileBytes: tool.maxFileBytes }),
            accept: tool.accept,
          },
  }),
);
