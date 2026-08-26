import { requireKdfTool } from "../catalogue/tool-meta";
import { resolveKdf } from "../resolve";
import type { KdfSpec } from "../spec";

/** One sentence, shown under the tool header: what these exact settings will do. */
export function describeSpec(spec: KdfSpec): string {
  const tool = requireKdfTool(spec.variant);
  const result = resolveKdf(spec);

  if (!result.ok) return `${tool.label} — ${result.problem}`;

  const r = result.resolved;

  if (r.mode === "verify") {
    // In Verify mode the cost settings are irrelevant — they come from the stored hash —
    // so describing them would be actively misleading.
    return `Checks the password against a stored ${tool.label} hash, using the parameters recorded in it.`;
  }

  const size = `${r.keyLength} bytes`;

  switch (r.toolId) {
    case "pbkdf2":
      return `Derives ${size} with PBKDF2-HMAC-${r.hashId.toUpperCase()} over ${r.iterations.toLocaleString()} iterations.`;
    case "hkdf":
      return `Derives ${size} with HKDF-${r.hashId.toUpperCase()} from ${r.ikm.length} bytes of key material.`;
    case "scrypt":
      return `Derives ${size} with scrypt at N=${r.scryptN}, r=${r.scryptR}, p=${r.scryptP}.`;
    case "argon2":
      return `Derives ${size} with ${r.argon2Variant} at ${r.argon2MemoryKib} KiB, t=${r.argon2Time}, p=${r.argon2Parallelism}.`;
    case "bcrypt":
      return `Hashes the password with bcrypt at cost ${r.bcryptCost} — 2^${r.bcryptCost} rounds.`;
    case "bcryptpbkdf":
      return `Derives ${size} with bcrypt-PBKDF over ${r.rounds.toLocaleString()} rounds.`;
    default:
      return `${tool.label} — ${size}.`;
  }
}
