import type { ToolDefinition, ToolFamily, ToolManifest, ToolSpecBase } from "@ocs/engine";
import { ASYMMETRIC_MANIFESTS } from "@ocs/asymmetric/manifests";
import { CHECKSUM_MANIFESTS } from "@ocs/checksum/manifests";
import { CRC_MANIFESTS } from "@ocs/crc/manifests";
import { ENCODING_MANIFESTS } from "@ocs/encoding/manifests";
import { CLASSICAL_MANIFESTS } from "@ocs/classical/manifests";
import { FORMAT_MANIFESTS } from "@ocs/format/manifests";
import { HASH_MANIFESTS } from "@ocs/hash/manifests";
import { CIPHER_MANIFESTS } from "@ocs/cipher/manifests";
import { KDF_MANIFESTS } from "@ocs/kdf/manifests";
import { MAC_MANIFESTS } from "@ocs/mac/manifests";
import { PARITY_MANIFESTS } from "@ocs/parity/manifests";

/**
 * Every tool the app ships, as cheap metadata.
 *
 * Eagerly bundled on purpose: this is what the sidebar renders, and it is only
 * strings. No `@noble` module, no compute path and no zod schema is reachable
 * from here — see the manifest/definition split described in
 * `packages/tools/hash/package.json`.
 */
export const TOOL_MANIFESTS: readonly ToolManifest[] = [
  ...HASH_MANIFESTS,
  ...CRC_MANIFESTS,
  ...CHECKSUM_MANIFESTS,
  ...PARITY_MANIFESTS,
  ...MAC_MANIFESTS,
  ...KDF_MANIFESTS,
  ...CIPHER_MANIFESTS,
  ...CLASSICAL_MANIFESTS,
  ...ASYMMETRIC_MANIFESTS,
  ...ENCODING_MANIFESTS,
  ...FORMAT_MANIFESTS,
];

const BY_ID = new Map(TOOL_MANIFESTS.map((m) => [m.id, m]));

export function getManifest(id: string): ToolManifest | undefined {
  return BY_ID.get(id);
}

export function manifestsInFamily(family: ToolFamily): ToolManifest[] {
  return TOOL_MANIFESTS.filter((m) => m.family === family);
}

/**
 * Distinct families present, in the order they should appear — in the filter menu and, since the
 * sidebar groups by family, in the tool list itself.
 *
 * The order is roughly ascending in what the output can be trusted to do: a CRC catches a burst
 * error, a checksum catches a flipped bit, a hash resists a collision, a MAC resists a forgery, and
 * so on up to public key. That reads as a progression rather than an arbitrary list, and it puts the
 * two families that are *not* cryptographic at the top where they cannot be mistaken for the rest.
 *
 * `crc` leads. It is the larger and more asked-for of the two non-cryptographic families — 22 tools
 * over the whole RevEng catalogue against nine hand-rolled sums — so it is what someone opening this
 * page is most often here for. The previous order put `checksum` first on the reasoning that it is
 * the simpler of the two, which is true and is not the same as being the one to show first.
 */
export const FAMILY_ORDER: readonly ToolFamily[] = [
  "crc",
  "checksum",
  /**
   * Third, and the three non-cryptographic families therefore lead.
   *
   * The order is roughly ascending in what the output can be trusted to do, and a parity bit is the
   * weakest thing in the app -- it notices an odd number of flipped bits in one unit and nothing else.
   * By that rule it belongs first; it is third because `crc` leads for a different and better reason
   * (it is what someone opening this page is most often here for) and splitting the two
   * error-detection families to slot parity between them would put a category boundary where there
   * is none.
   */
  "parity",
  "hash",
  "mac",
  "kdf",
  "cipher",
  /**
   * After `cipher`, which is the descending-trust order the rest of this list follows: a Caesar cipher
   * is the weakest encryption in the app. It sits next to the modern ciphers rather than at the end
   * because that is where somebody looking for a cipher will look.
   */
  "classical",
  "asymmetric",
  "encoding",
  "format",
];

export function presentFamilies(): ToolFamily[] {
  const present = new Set(TOOL_MANIFESTS.map((m) => m.family));
  return FAMILY_ORDER.filter((f) => present.has(f));
}

/**
 * Load a tool's full behaviour on demand.
 *
 * One `case` per family rather than per tool: a family package builds its own
 * definitions from an id, so registering the whole SHA-3 set later is a data
 * change inside `@ocs/hash` with nothing to add here. The dynamic `import()`
 * specifiers must stay literal — a computed specifier defeats the bundler's
 * ability to split them into separate chunks, which is the entire point.
 */
export async function loadTool(id: string): Promise<ToolDefinition<ToolSpecBase>> {
  const manifest = BY_ID.get(id);
  if (!manifest) throw new Error(`Unknown tool id: ${id}`);

  switch (manifest.family) {
    case "hash": {
      const { hashToolDefinition, prepareHashAlgorithm } = await import("@ocs/hash/definition");
      // FSB's matrix table is a 266 KB dynamic import; awaiting it here is what keeps the synchronous
      // `Hasher` and `ToolStream` contracts intact. A no-op for every other algorithm.
      await prepareHashAlgorithm(id);
      // The cast widens the concrete spec type to the shared base. It is sound in
      // the direction that matters — every spec has `specVersion` and `options` —
      // but `specSchema`'s zod type and `createSpec`'s return are invariant, so TS
      // cannot see it. The generic UI only ever hands a spec back to the same tool
      // that produced it, which is what makes this safe in practice.
      return hashToolDefinition(id) as unknown as ToolDefinition<ToolSpecBase>;
    }
    case "crc": {
      const { crcToolDefinition } = await import("@ocs/crc/definition");
      return crcToolDefinition(id) as unknown as ToolDefinition<ToolSpecBase>;
    }
    case "checksum": {
      const { checksumToolDefinition } = await import("@ocs/checksum/definition");
      return checksumToolDefinition(id) as unknown as ToolDefinition<ToolSpecBase>;
    }
    case "mac": {
      const { macToolDefinition } = await import("@ocs/mac/definition");
      return macToolDefinition(id) as unknown as ToolDefinition<ToolSpecBase>;
    }
    case "kdf": {
      const { kdfToolDefinition } = await import("@ocs/kdf/definition");
      return kdfToolDefinition(id) as unknown as ToolDefinition<ToolSpecBase>;
    }
    case "cipher": {
      const { cipherToolDefinition } = await import("@ocs/cipher/definition");
      return cipherToolDefinition(id) as unknown as ToolDefinition<ToolSpecBase>;
    }
    case "asymmetric": {
      const { asymmetricToolDefinition } = await import("@ocs/asymmetric/definition");
      return asymmetricToolDefinition(id) as unknown as ToolDefinition<ToolSpecBase>;
    }
    case "encoding": {
      const { encodingToolDefinition } = await import("@ocs/encoding/definition");
      return encodingToolDefinition(id) as unknown as ToolDefinition<ToolSpecBase>;
    }
    case "parity": {
      const { parityToolDefinition } = await import("@ocs/parity/definition");
      return parityToolDefinition(id) as unknown as ToolDefinition<ToolSpecBase>;
    }
    case "classical": {
      const { classicalToolDefinition } = await import("@ocs/classical/definition");
      return classicalToolDefinition(id) as unknown as ToolDefinition<ToolSpecBase>;
    }
    case "format": {
      const { formatToolDefinition } = await import("@ocs/format/definition");
      return formatToolDefinition(id) as unknown as ToolDefinition<ToolSpecBase>;
    }
  }
}

/**
 * The tool a fresh session opens on.
 *
 * CRC-8, the first tool of the first family, so the page opens on what the sidebar opens on rather
 * than jumping the reader into the middle of the list. It was `sha256`, which is the single most
 * asked-for digest and is four families down.
 *
 * Note what this is not: a claim that CRC-8 is a good default *checksum*. It is `not-a-mac`, and
 * `CRC001` says so the moment the page loads. That is the honest first impression for a tool whose
 * job is telling people the difference — unlike opening on something `broken`, which the test in
 * `tests/registry.test.ts` still forbids.
 */
export const DEFAULT_TOOL_ID = "crc8";
