import { describe, expect, it } from "vitest";

import { CIPHER_TOOLS } from "../packages/tools/cipher/src/catalogue/tool-meta";
import { acceptedNonceLengths } from "../packages/tools/cipher/src/resolve";
import { HASH_ALGORITHMS } from "../packages/tools/hash/src/catalogue/algorithm-meta";
import { FORMAT_TOOLS } from "../packages/tools/format/src/catalogue/tool-meta";
import { ALL_FORMAT_OPTIONS } from "../packages/tools/format/src/catalogue/options";

/**
 * User-facing prose that states a size, checked against the metadata that decides it.
 *
 * This file exists because of a bug report, and the bug is worth stating because the shape recurs.
 * The random-bytes tool had a hand-written lookup from byte counts to roles -- 12 to "a GCM nonce",
 * 24 to "an XChaCha20 nonce", 64 to "a block-sized HMAC-SHA512 key". Two entries were false (SHA-512's
 * block is 128 bytes, not 64; the 64-byte "Ed25519 keypair" is libsodium's format, not the 32-byte
 * private key this app takes), one was actively harmful (recommending a *random* 96-bit GCM nonce is
 * the mistake `C003` exists to warn about), and all of them were the format family asserting other
 * families' parameters in prose with nothing to check them against.
 *
 * The lookup is gone. What this file guards is the claims that remain, and the principle behind it:
 * **a number in user-facing text must either come from the metadata or be checkable against it.**
 *
 * Deliberately scoped to `summary` strings rather than every `detail`. A summary describes *the tool*,
 * so a size in one is a claim about that tool and can be resolved. Option details legitimately talk
 * about other configurations -- the nonce-length control explains GCM's 96 bits and CBC's full block
 * in the same sentence, correctly -- so scanning those would produce false failures and teach people
 * to weaken the test.
 */

/** `192-bit nonce`, `8-byte nonce`, `32-byte keys`, and the same with "IV". */
const CLAIM = /(\d+)[- ](bit|byte)s?\s+(nonce|iv|key)s?/gi;

interface Claim {
  bytes: number;
  kind: "nonce" | "iv" | "key";
  text: string;
}

function claimsIn(text: string): Claim[] {
  const out: Claim[] = [];
  for (const match of text.matchAll(CLAIM)) {
    const size = Number(match[1]);
    const bytes = match[2]!.toLowerCase() === "bit" ? size / 8 : size;
    out.push({
      bytes,
      kind: match[3]!.toLowerCase() as Claim["kind"],
      text: match[0],
    });
  }
  return out;
}

describe("size claims in cipher summaries", () => {
  /**
   * Every nonce or IV size named in a cipher's summary must be one the tool accepts.
   *
   * This is the exact assertion that would have caught the bug had the claim been made here: 24 bytes
   * really is XChaCha20-Poly1305's nonce, and a test that resolves the number rather than trusting the
   * sentence is what tells the difference between a right claim and a lucky one.
   */
  it("names only nonce lengths the tool actually accepts", () => {
    const problems: string[] = [];
    for (const tool of CIPHER_TOOLS) {
      const accepted = acceptedNonceLengths(tool.id, undefined, tool.defaultParamSet);
      for (const claim of claimsIn(tool.summary)) {
        if (claim.kind === "key") continue;
        if (accepted.length === 0) {
          // A block cipher's IV is one block and comes from the mode, so a bare summary claim about it
          // cannot be resolved without one. None currently makes such a claim; if one starts, it
          // should say which mode.
          problems.push(`${tool.id}: says "${claim.text}" but has no tool-level nonce`);
          continue;
        }
        if (!accepted.includes(claim.bytes)) {
          problems.push(
            `${tool.id}: says "${claim.text}" (${claim.bytes} bytes) but accepts ${accepted.join(", ")}`,
          );
        }
      }
    }
    expect(problems).toEqual([]);
  });

  it("names only key lengths the tool actually accepts", () => {
    const problems: string[] = [];
    for (const tool of CIPHER_TOOLS) {
      for (const claim of claimsIn(tool.summary)) {
        if (claim.kind !== "key") continue;
        const lengths = tool.block
          ? (tool.block.keyLengths ?? [])
          : (tool.shape?.keyLengths ?? []);
        // Tools whose key length is a range or comes from a parameter set are skipped rather than
        // guessed at -- the point is to catch a wrong number, not to invent a rule for every shape.
        if (lengths.length === 0) continue;
        /*
         * DES is a genuine exception rather than a failure, and it is listed rather than accommodated
         * by loosening the rule.
         *
         * Its summary says "56-bit key" and the tool takes 8 bytes, and *both* are right: DES keys are
         * 64 bits of storage carrying 56 bits of key and 8 parity bits, so 56 is the number that
         * describes its strength and 64 is the number you type. Widening the comparison to "within a
         * byte" would have swallowed this and also swallowed a real off-by-one, which is the trade a
         * mechanical check must not make. 3DES is not here because its summary quotes no key size.
         */
        if (tool.id === "des" && claim.bytes === 7) continue;
        if (!lengths.includes(claim.bytes)) {
          problems.push(
            `${tool.id}: says "${claim.text}" (${claim.bytes} bytes) but takes ${lengths.join(", ")}`,
          );
        }
      }
    }
    expect(problems).toEqual([]);
  });

  /** The regex has to actually match something, or both tests above pass by checking nothing. */
  it("finds the claims it is meant to be checking", () => {
    const found = CIPHER_TOOLS.flatMap((tool) => claimsIn(tool.summary));
    expect(found.length, "no size claims found; the pattern has stopped matching").toBeGreaterThan(4);
    // And it resolves the two spellings, since bits and bytes are both used in these summaries.
    expect(claimsIn("a 192-bit nonce")[0]!.bytes).toBe(24);
    expect(claimsIn("an 8-byte nonce")[0]!.bytes).toBe(8);
  });
});

describe("the random tools make no claims they cannot support", () => {
  /**
   * The format family may not assert another family's parameters, and this is the gate.
   *
   * It is a *negative* test, which is unusual here and is the right shape for this: the fix for the
   * reported bug was to delete prose, so what has to hold is that the prose stays deleted. Naming the
   * algorithms rather than matching a size pattern keeps it readable and precise -- these are exactly
   * the words that were wrong.
   */
  const FOREIGN = [
    "GCM",
    "AES-128",
    "AES-192",
    "AES-256",
    "XChaCha20",
    "ChaCha20",
    "HMAC-SHA512",
    "Ed25519",
    "DES key",
    "CBC IV",
  ];

  it("keeps role claims about other families out of the random tools' user-facing text", () => {
    const randomTools = FORMAT_TOOLS.filter((tool) => tool.kind.startsWith("random"));
    expect(randomTools).toHaveLength(2);

    const strings: { where: string; text: string }[] = [];
    for (const tool of randomTools) {
      strings.push({ where: `${tool.id} summary`, text: tool.summary });
      for (const id of tool.exposes) {
        const option = ALL_FORMAT_OPTIONS.find((o) => o.id === id);
        if (!option) continue;
        strings.push({ where: `${tool.id}/${id} summary`, text: option.summary ?? "" });
        strings.push({ where: `${tool.id}/${id} detail`, text: option.detail ?? "" });
      }
    }

    const problems: string[] = [];
    for (const { where, text } of strings) {
      for (const name of FOREIGN) {
        if (text.includes(name)) problems.push(`${where} names ${name}`);
      }
    }
    expect(problems, "a random tool is asserting another family's parameters again").toEqual([]);
  });

  /**
   * And the two numbers the deleted lookup got wrong, pinned so the record cannot rot.
   *
   * Not because anything reads them -- nothing does any more -- but because the comment where the
   * lookup used to be cites both, and a claim about why something was removed should be as checkable
   * as the thing it replaced.
   */
  it("records the two facts the deleted lookup had wrong", () => {
    const sha512 = HASH_ALGORITHMS.find((algorithm) => algorithm.id === "sha512")!;
    // The lookup said 64 bytes was "a block-sized HMAC-SHA512 key". 64 is the *output*; the block is 128.
    expect(sha512.outputLen).toBe(64);
    expect(sha512.blockLen).toBe(128);
    expect(sha512.blockLen).not.toBe(64);

    // And it said 24 bytes was an XChaCha20 nonce, which was true of the size and is worth keeping
    // true: the size claim was right, the mistake was assigning a role to random bytes at all.
    expect(acceptedNonceLengths("xchacha20poly1305", undefined, undefined)).toEqual([24]);
  });
});
