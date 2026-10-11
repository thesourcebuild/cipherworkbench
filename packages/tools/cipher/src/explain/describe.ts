import { requireCipherTool } from "../catalogue/tool-meta";
import { constructionLabel } from "../compute";
import { resolveCipher } from "../resolve";
import type { CipherSpec } from "../spec";

/** One sentence, shown under the tool header: what these exact settings will do. */
export function describeSpec(spec: CipherSpec): string {
  const tool = requireCipherTool(spec.variant);
  const result = resolveCipher(spec);

  if (!result.ok) return `${tool.label} — ${result.problem}`;

  const r = result.resolved;
  if (r.toolId === "cipher-image") {
    const verb = r.direction === "encrypt" ? "Encrypts" : "Decrypts";
    return `${verb} complete BMP pixel-data blocks with AES-${r.key.length * 8}-ECB while preserving the headers and final partial block. Educational only: ECB leaks repeated image patterns.`;
  }
  const name = constructionLabel(r);
  const verb = r.direction === "encrypt" ? "Encrypts" : "Decrypts";

  // Whether the output is authenticated is the single most useful fact about a cipher
  // configuration, so it goes in the sentence rather than only in the badges.
  const authentication = r.aead
    ? r.direction === "encrypt"
      ? ", appending a 16-byte authentication tag"
      : ", verifying the appended authentication tag"
    : " with no authentication";

  const aad = r.aad.length > 0 ? ` over ${r.aad.length} bytes of additional data` : "";

  return `${verb} the input with ${name}${authentication}${aad}.`;
}
