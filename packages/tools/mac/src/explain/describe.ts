import { requireHmacHash, requireMacTool } from "../catalogue/tool-meta";
import { resolveMac } from "../resolve";
import type { MacSpec } from "../spec";

/** One sentence, shown under the tool header: what these exact settings will do. */
export function describeSpec(spec: MacSpec): string {
  const tool = requireMacTool(spec.variant);
  const result = resolveMac(spec);

  if (!result.ok) {
    return `${tool.label} — ${result.problem}`;
  }

  const r = result.resolved;
  const size = `${r.outputLen} bytes (${r.outputLen * 8} bits)`;

  switch (r.toolId) {
    case "hmac": {
      const hash = requireHmacHash(r.hashId);
      const truncated = r.truncateTo === undefined ? "" : `, truncated from ${hash.outputLen}`;
      return `Computes HMAC-${hash.label} with a ${r.key.length}-byte key — ${size}${truncated}.`;
    }
    case "kmac": {
      const label = r.kmacVariant === "kmac256" ? "KMAC256" : "KMAC128";
      const custom =
        r.customization.length === 0
          ? ""
          : ` and customization ${JSON.stringify(new TextDecoder().decode(r.customization))}`;
      return `Computes ${label} with a ${r.key.length}-byte key${custom} — ${size}.`;
    }
    case "poly1305":
      return `Computes a Poly1305 tag — ${size}. The key is single-use.`;
    case "cmac":
      return `Computes AES-${r.key.length * 8}-CMAC — ${size}.`;
    default:
      return `${tool.label} — ${size}.`;
  }
}
