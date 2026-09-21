import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { CERTIFICATE_TOOLS, type CertificateToolMeta } from "./catalogue/tool-meta";

const TEXT_ONLY: readonly OutputEncoding[] = ["utf-8"];
const CONVERTER_ENCODINGS: readonly OutputEncoding[] = ["utf-8", "hex", "base64"];

function toManifest(meta: CertificateToolMeta): ToolManifest {
  const isCreator = meta.id === "cert-creator" || meta.id === "csr-creator";
  return {
    id: meta.id,
    label: meta.label,
    family: "certificates",
    category: meta.category,
    tags: [...meta.tags],
    directions: ["forward"],
    summary: meta.summary,
    security: "modern",
    outputEncodings: meta.id === "cert-converter" || isCreator ? CONVERTER_ENCODINGS : TEXT_ONLY,
    readsInput: !isCreator,
    supportsVerify: false,
    supportsFile: !isCreator,
    streaming: false,
  };
}

export const CERTIFICATES_MANIFESTS: readonly ToolManifest[] = CERTIFICATE_TOOLS.map(toManifest);
