/**
 * Published vectors for RoadRunneR and Lilliput-80, from the designers' own papers.
 *
 * One file, imported by both `tests/algos-lightweight-block4.test.ts` (which drives the
 * implementation directly, in both directions) and `tests/cipher.test.ts` (which drives them through
 * the tool, in ECB, so the catalogue, resolver and bindings are covered too). Neither file restates a
 * value: a tool-level test carrying its own hand-written expectations is how a fabricated vector got
 * into this repo once, and how a wrong one would survive being "fixed" to whatever the code produced.
 *
 * Neither cipher has an oracle. OpenSSL has neither, no dependency in this tree implements either, and
 * Bouncy Castle -- the richest vector source reachable from here -- carries no engine and no test for
 * them. So these values are the whole check, which is why every one of them is also decrypted from the
 * published ciphertext rather than only re-encrypted.
 */

export interface LightweightBlock4Vector {
  /** The tool id, which is also the `RoadRunneRVariant` for the two RoadRunneR rows. */
  readonly tool: string;
  readonly variant?: "64-80" | "64-128";
  readonly key: string;
  readonly plaintext: string;
  readonly ciphertext: string;
}

export const LIGHTWEIGHT_BLOCK4_VECTORS: readonly LightweightBlock4Vector[] = [
  // RoadRunneR, two per key size -- one low-weight key and one full one, from LightSec 2015.
  {
    tool: "roadrunner80",
    variant: "64-80",
    key: "80000000000000000000",
    plaintext: "0000000000000002",
    ciphertext: "4fa25ef264cec6e4",
  },
  {
    tool: "roadrunner80",
    variant: "64-80",
    key: "0123456789abcdef0123",
    plaintext: "fedcba9876543210",
    ciphertext: "328c798a0eb25a3b",
  },
  {
    tool: "roadrunner128",
    variant: "64-128",
    key: "80000000000000000000000000000000",
    plaintext: "0000000000000002",
    ciphertext: "c168c69ac195845e",
  },
  {
    tool: "roadrunner128",
    variant: "64-128",
    key: "0123456789abcdef0123456789abcdef",
    plaintext: "fedcba9876543210",
    ciphertext: "d9df068f59938882",
  },
  // Lilliput-80, from the IEEE Transactions on Computers paper.
  {
    tool: "lilliput",
    key: "3210fedcba9876543210",
    plaintext: "fedcba9876543210",
    ciphertext: "419a5c2c39ae06d9",
  },
];
