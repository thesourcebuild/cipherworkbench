/**
 * Parity with PHP's `hash_algos()`, algorithm by algorithm.
 *
 * The same shape as `openssl-parity.test.ts`: transcribe the reference's own list, compute every entry
 * through this app's tools, and require byte-for-byte agreement -- plus a completeness gate, so the
 * claim "everything PHP hashes, this hashes" cannot go stale when PHP adds an algorithm or this repo
 * renames a tool.
 *
 * The expected values are PHP's, extracted from `ext/hash/tests/hash_copy_001.phpt` into
 * `tests/php-hash-vectors.ts`; that test hashes one 25-byte message with every registered algorithm and
 * then the same message plus a second string. Two messages, because a single short one leaves the
 * block-boundary handling of the 32-byte (Snefru, GOST) and 128-byte (HAVAL) block sizes untested.
 *
 * Three of PHP's names are not hash-family tools here and are mapped deliberately:
 *
 *  - `adler32` is a checksum, and lives in the checksum family beside Fletcher.
 *  - `crc32`, `crc32b` and `crc32c` are three of the CRC family's 67 named models -- nothing new is
 *    computed for them here. PHP's `crc32` is the non-reflected BZIP2 variant and `crc32b` the
 *    reflected one every zip file uses, which is a naming trap worth pinning in a test rather than
 *    explaining in a comment. PHP additionally *prints* `crc32` byte-reversed: `PHP_CRC32LEFinal`
 *    emits the same 32-bit value least significant byte first, where `crc32b` and `crc32c` go through
 *    `PHP_CRC32BEFinal`. That is a spelling difference in PHP, not a different checksum, so the
 *    mapping below reverses the bytes rather than this repo growing a second CRC-32.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { OPTION_MODEL } from "@ocs/crc";
import { crcToolDefinition } from "@ocs/crc/definition";
import { checksumToolDefinition } from "@ocs/checksum/definition";
import { hashToolDefinition, prepareHashAlgorithm } from "@ocs/hash/definition";
import { HASH_ALGORITHMS } from "@ocs/hash";
import { encodeHex } from "@ocs/engine";
import { PHP_HASH_VECTORS, PHP_MESSAGE_1, PHP_MESSAGE_2 } from "./php-hash-vectors";

/**
 * Prepare every hash algorithm before anything else runs, exactly as `loadTool()` does.
 *
 * Each algorithm implemented in `@ocs/algos` is a dynamic import of its own module, so a hash tool
 * downloads its own tables and nobody else's -- see the header of `packages/tools/hash/src/bindings.ts`.
 * This file reaches `hashToolDefinition` directly and therefore bypasses the registry, so it has to do
 * what the registry does. The sync accessor throws with a message naming this call rather than
 * returning a zeroed table, which is why a missing prepare fails loudly instead of producing a
 * plausible wrong digest.
 */
beforeAll(async () => {
  await Promise.all(HASH_ALGORITHMS.map((meta) => prepareHashAlgorithm(meta.id)));
}, 60_000);

const fromHex = (hex: string) =>
  hex === ""
    ? new Uint8Array(0)
    : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));

/**
 * How this app provides each name PHP reports.
 *
 * A `string` is a hash-family tool id. The two objects are the deliberate exceptions described above.
 */
type Provider =
  | string
  | { family: "crc"; tool: string; model: string; littleEndian?: boolean }
  | { family: "checksum"; tool: string }
  /**
   * A hash tool that covers a grid, plus the options selecting one cell of it.
   *
   * HAVAL is one tool spanning fifteen functions and Tiger one spanning six, so twenty-one of
   * PHP's names map to a tool *and* a configuration rather than to a tool alone. String values,
   * because these are selects -- see the note on `DigestVector.options`.
   */
  | { family: "hash"; tool: string; options: Readonly<Record<string, string>> };

const PROVIDERS: Record<string, Provider> = {
  md2: "md2",
  md4: "md4",
  md5: "md5",
  sha1: "sha1",
  sha224: "sha224",
  sha256: "sha256",
  sha384: "sha384",
  "sha512/224": "sha512-224",
  "sha512/256": "sha512-256",
  sha512: "sha512",
  "sha3-224": "sha3-224",
  "sha3-256": "sha3-256",
  "sha3-384": "sha3-384",
  "sha3-512": "sha3-512",
  ripemd128: "ripemd128",
  ripemd160: "ripemd160",
  ripemd256: "ripemd256",
  ripemd320: "ripemd320",
  whirlpool: "whirlpool",
  "tiger128,3": { family: "hash", tool: "tiger", options: { outputLength: "16", passes: "3" } },
  "tiger160,3": { family: "hash", tool: "tiger", options: { outputLength: "20", passes: "3" } },
  "tiger192,3": { family: "hash", tool: "tiger", options: { outputLength: "24", passes: "3" } },
  "tiger128,4": { family: "hash", tool: "tiger", options: { outputLength: "16", passes: "4" } },
  "tiger160,4": { family: "hash", tool: "tiger", options: { outputLength: "20", passes: "4" } },
  "tiger192,4": { family: "hash", tool: "tiger", options: { outputLength: "24", passes: "4" } },
  // PHP registers `snefru` and `snefru256` as separate names for one function; asserted below.
  snefru: "snefru",
  snefru256: "snefru",
  gost: "gost94",
  "gost-crypto": "gost94-crypto",
  adler32: { family: "checksum", tool: "adler32" },
  // Same value as CRC-32/BZIP2, printed the other way round -- see the note at the top.
  crc32: { family: "crc", tool: "crc32", model: "CRC-32/BZIP2", littleEndian: true },
  crc32b: { family: "crc", tool: "crc32", model: "CRC-32/ISO-HDLC" },
  crc32c: { family: "crc", tool: "crc32", model: "CRC-32/ISCSI" },
  fnv132: "fnv132",
  fnv1a32: "fnv1a32",
  fnv164: "fnv164",
  fnv1a64: "fnv1a64",
  joaat: "joaat",
  murmur3a: "murmur3a",
  murmur3c: "murmur3c",
  murmur3f: "murmur3f",
  xxh32: "xxh32",
  xxh64: "xxh64",
  xxh3: "xxh3",
  xxh128: "xxh128",
  "haval128,3": { family: "hash", tool: "haval", options: { outputLength: "16", passes: "3" } },
  "haval160,3": { family: "hash", tool: "haval", options: { outputLength: "20", passes: "3" } },
  "haval192,3": { family: "hash", tool: "haval", options: { outputLength: "24", passes: "3" } },
  "haval224,3": { family: "hash", tool: "haval", options: { outputLength: "28", passes: "3" } },
  "haval256,3": { family: "hash", tool: "haval", options: { outputLength: "32", passes: "3" } },
  "haval128,4": { family: "hash", tool: "haval", options: { outputLength: "16", passes: "4" } },
  "haval160,4": { family: "hash", tool: "haval", options: { outputLength: "20", passes: "4" } },
  "haval192,4": { family: "hash", tool: "haval", options: { outputLength: "24", passes: "4" } },
  "haval224,4": { family: "hash", tool: "haval", options: { outputLength: "28", passes: "4" } },
  "haval256,4": { family: "hash", tool: "haval", options: { outputLength: "32", passes: "4" } },
  "haval128,5": { family: "hash", tool: "haval", options: { outputLength: "16", passes: "5" } },
  "haval160,5": { family: "hash", tool: "haval", options: { outputLength: "20", passes: "5" } },
  "haval192,5": { family: "hash", tool: "haval", options: { outputLength: "24", passes: "5" } },
  "haval224,5": { family: "hash", tool: "haval", options: { outputLength: "28", passes: "5" } },
  "haval256,5": { family: "hash", tool: "haval", options: { outputLength: "32", passes: "5" } },
};

async function compute(provider: Provider, message: Uint8Array): Promise<string> {
  if (typeof provider === "string") {
    /**
     * Through `createSpec()` on the definition rather than a family-level constructor, because that is
     * the only route the app itself uses -- and because the three families spell their spec's variant
     * field differently, which a test reaching past the contract would have to know about.
     */
    const tool = hashToolDefinition(provider);
    const result = await tool.compute(tool.createSpec(), message);
    expect(result.error, provider).toBeUndefined();
    return encodeHex(result.bytes!);
  }

  if (provider.family === "hash") {
    // Same route as the plain string case, with the grid cell selected on top of the default spec.
    const tool = hashToolDefinition(provider.tool);
    const base = tool.createSpec();
    const result = await tool.compute(
      { ...base, options: { ...base.options, ...provider.options } },
      message,
    );
    expect(result.error, provider.tool).toBeUndefined();
    return encodeHex(result.bytes!);
  }

  if (provider.family === "crc") {
    const tool = crcToolDefinition(provider.tool);
    const base = tool.createSpec();
    const result = await tool.compute(
      { ...base, options: { ...base.options, [OPTION_MODEL]: provider.model } },
      message,
    );
    expect(result.error, provider.model).toBeUndefined();
    const bytes = provider.littleEndian
      ? Uint8Array.from(result.bytes!).reverse()
      : result.bytes!;
    return encodeHex(bytes);
  }

  const tool = checksumToolDefinition(provider.tool);
  const result = await tool.compute(tool.createSpec(), message);
  expect(result.error, provider.tool).toBeUndefined();
  return encodeHex(result.bytes!);
}

describe("parity with PHP's hash_algos()", () => {
  it("has a provider for every name PHP reports, and no stale ones", () => {
    /**
     * The gate. `PHP_HASH_VECTORS` is generated from php-src, so this fails if PHP grows an algorithm
     * and nothing here answers for it -- and equally if a mapping outlives the tool it points at.
     */
    const phpNames = PHP_HASH_VECTORS.map((v) => v.algo).sort();
    expect(Object.keys(PROVIDERS).sort()).toEqual(phpNames);
    expect(phpNames.length).toBeGreaterThanOrEqual(60);
  });

  it("computes the same digest as PHP for every algorithm, on both messages", async () => {
    const first = fromHex(PHP_MESSAGE_1);
    const second = fromHex(PHP_MESSAGE_2);
    expect(first).toHaveLength(25);
    expect(second.length).toBeGreaterThan(first.length);

    for (const vector of PHP_HASH_VECTORS) {
      const provider = PROVIDERS[vector.algo]!;
      expect(await compute(provider, first), `${vector.algo} (first message)`).toBe(
        vector.first,
      );
      expect(await compute(provider, second), `${vector.algo} (second message)`).toBe(
        vector.second,
      );
    }
  });

  it("agrees that snefru and snefru256 are one function", () => {
    // PHP registers both names against the same implementation. Worth asserting rather than assuming,
    // because the alternative -- a 128-bit Snefru hiding behind one of the names -- is what the naming
    // suggests.
    const a = PHP_HASH_VECTORS.find((v) => v.algo === "snefru")!;
    const b = PHP_HASH_VECTORS.find((v) => v.algo === "snefru256")!;
    expect(a.first).toBe(b.first);
    expect(a.second).toBe(b.second);
  });

  it("keeps PHP's three CRC-32 names straight", () => {
    /**
     * The trap this pins: `crc32` and `crc32b` are different values for the same input, and which is
     * which is the opposite of what most people guess. PHP's `crc32b` is the reflected, zip/PNG/zlib
     * CRC-32; PHP's `crc32` is the non-reflected BZIP2 variant. `crc32c` is Castagnoli.
     */
    const value = (algo: string) => PHP_HASH_VECTORS.find((v) => v.algo === algo)!.first;
    expect(new Set([value("crc32"), value("crc32b"), value("crc32c")]).size).toBe(3);

    // And the byte-order quirk itself: PHP's `crc32` is its `crc32b` sibling's *value* reversed only
    // in how it is printed, so reversing PHP's own crc32 string must not accidentally equal crc32b.
    const reversed = value("crc32").match(/../g)!.reverse().join("");
    expect(reversed).not.toBe(value("crc32b"));
  });

  it("hashes the second message as a genuine continuation of the first", () => {
    // The fixture's own consistency: the second message must start with the first, or the two-message
    // check is not testing block continuation at all.
    expect(PHP_MESSAGE_2.startsWith(PHP_MESSAGE_1)).toBe(true);
  });
});
