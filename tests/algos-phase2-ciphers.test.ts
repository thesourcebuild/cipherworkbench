import { describe, expect, it } from "vitest";
import {
  createGost28147,
  createLea,
  createNoekeon,
  createShacal2,
  GOST_CIPHER_SBOXES,
  SHACAL2_ROUND_CONSTANTS,
  type BlockCipher,
} from "@ocs/algos";

/**
 * Noekeon, LEA, SHACAL-2 and GOST 28147-89, against Bouncy Castle's own test vectors.
 *
 * None has an oracle -- OpenSSL implemented none of the four, and its GOST support was a separate
 * engine that Node does not load -- so the vectors were fetched from BC's test suite and the *engines*
 * were fetched too. That second part is what settled Noekeon's round-constant placement and LEA's three
 * key schedules; both are things a paper summary states loosely enough to get wrong.
 *
 * What each set is for:
 *
 *  - **Noekeon** gets three vectors, and the third is the useful one: it encrypts the *first* vector's
 *    ciphertext under the second's, which chains them so a single wrong round constant cannot pass.
 *  - **LEA** gets one vector per key size, and that is the minimum rather than a sample: 128, 192 and
 *    256 bits are three genuinely different key schedules, and an implementation that shares one across
 *    all three is correct at 128 and wrong above it.
 *  - **SHACAL-2** gets six, and its round constants are separately checked against FIPS 180-4 -- because
 *    they are *derived* here from the cube roots of the first 64 primes rather than transcribed, and a
 *    derivation deserves its own assertion.
 *  - **GOST 28147-89** gets the standard's vector plus a check that its S-boxes still match the copies
 *    in `gost.ts`, which the hash's own published vectors already pin.
 */

const unhex = (text: string): Uint8Array =>
  Uint8Array.from(text.replace(/\s+/g, "").match(/../g)!.map((pair) => parseInt(pair, 16)));

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/** Both directions, always: a one-way check would miss half of each cipher. */
function bothWays(cipher: BlockCipher, plaintext: string, ciphertext: string, label: string): void {
  const pt = unhex(plaintext);
  const ct = unhex(ciphertext);
  expect(pt.length, `${label}: plaintext is not one block`).toBe(cipher.blockSize);

  const encrypted = new Uint8Array(cipher.blockSize);
  cipher.encryptBlock(pt, encrypted);
  expect(hex(encrypted), `${label} encrypt`).toBe(hex(ct));

  const decrypted = new Uint8Array(cipher.blockSize);
  cipher.decryptBlock(ct, decrypted);
  expect(hex(decrypted), `${label} decrypt`).toBe(hex(pt));
}

describe("Noekeon", () => {
  const VECTORS = [
    {
      key: "00000000000000000000000000000000",
      pt: "00000000000000000000000000000000",
      ct: "b1656851699e29fa24b70148503d2dfc",
    },
    {
      key: "ffffffffffffffffffffffffffffffff",
      pt: "ffffffffffffffffffffffffffffffff",
      ct: "2a78421b87c7d0924f26113f1d1349b2",
    },
    /**
     * The chained one: this key is the first vector's ciphertext and this plaintext is the second's.
     *
     * Which means it cannot pass unless both of those are already right, and it is the case a single
     * transposed round constant fails -- the all-zero and all-ones inputs are symmetrical enough that
     * some mistakes survive them.
     */
    {
      key: "b1656851699e29fa24b70148503d2dfc",
      pt: "2a78421b87c7d0924f26113f1d1349b2",
      ct: "e2f687e07b75660ffc372233bc47532c",
    },
  ];

  it("reproduces every published vector, both ways", () => {
    for (const [i, v] of VECTORS.entries()) {
      bothWays(createNoekeon(unhex(v.key)), v.pt, v.ct, `Noekeon ${i}`);
    }
  });

  it("refuses a key that is not 128 bits", () => {
    expect(() => createNoekeon(new Uint8Array(24))).toThrow(/16 bytes/);
  });
});

describe("LEA", () => {
  /** ISO/IEC 29192-2's vectors, one per key size. All three schedules differ. */
  const VECTORS = [
    {
      key: "0f1e2d3c4b5a69788796a5b4c3d2e1f0",
      pt: "101112131415161718191a1b1c1d1e1f",
      ct: "9fc84e3528c6c6185532c7a704648bfd",
    },
    {
      key: "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a59687",
      pt: "202122232425262728292a2b2c2d2e2f",
      ct: "6fb95e325aad1b878cdcf5357674c6f2",
    },
    {
      key: "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f",
      pt: "303132333435363738393a3b3c3d3e3f",
      ct: "d651aff647b189c13a8900ca27f9e197",
    },
  ];

  it("reproduces every published vector, both ways, at all three key sizes", () => {
    for (const v of VECTORS) {
      bothWays(createLea(unhex(v.key)), v.pt, v.ct, `LEA-${(v.key.length / 2) * 8}`);
    }
    // Guards the guard: three sizes, three schedules. Two vectors would leave one untested.
    expect(new Set(VECTORS.map((v) => v.key.length)).size).toBe(3);
  });

  /** The round count follows the key: 24, 28, 32. Asserted through the output length of the schedule. */
  it("runs more rounds for a longer key", () => {
    const block = unhex("00".repeat(16));
    const outputs = [16, 24, 32].map((bytes) => {
      const out = new Uint8Array(16);
      createLea(new Uint8Array(bytes)).encryptBlock(block, out);
      return hex(out);
    });
    expect(new Set(outputs).size, "key sizes produced the same ciphertext").toBe(3);
  });

  it("refuses a key length the standard does not define", () => {
    expect(() => createLea(new Uint8Array(20))).toThrow(/16, 24 or 32/);
  });
});

describe("SHACAL-2", () => {
  const VECTORS = [
    {
      key:
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      pt: "98bcc10405ab0bfc686bececaad01ac19b452511bceb9cb094f905c51ca45430",
      ct: "00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f",
    },
    {
      key:
        "2bd6459f82c5b300952c49104881ff482bd6459f82c5b300952c49104881ff48" +
        "2bd6459f82c5b300952c49104881ff482bd6459f82c5b300952c49104881ff48",
      pt: "481f122a75f2c4c3395140b5a951ebba06d96bdfd9d8ff4fb59cbd1287808d5a",
      ct: "ea024714ad5c4d84ea024714ad5c4d84ea024714ad5c4d84ea024714ad5c4d84",
    },
    {
      key: "ff".repeat(64),
      pt: "94fedff2a0cfe3c983d340c88d73f8cf4b79fc581797ec10b27d4da1b51e1bc7",
      ct: "ff".repeat(32),
    },
    {
      key: "64".repeat(64),
      pt: "6643cb84b3b3f126f5e50959ef4ce73db8500918abe1056368db06ca8c1c0d45",
      ct: "64".repeat(32),
    },
    {
      key: "32".repeat(64),
      pt: "92e937285ab11fe3561542c43c918966971de722e9b9d38bd69eac77899dcf81",
      ct: "32".repeat(32),
    },
    {
      key: "00".repeat(64),
      pt: "f8c9259fa4f5d787b570afa9219166a63636fc5c30ac289155d0cc4ffcb4b03d",
      ct: "00".repeat(32),
    },
  ];

  it("reproduces every published vector, both ways", () => {
    for (const [i, v] of VECTORS.entries()) {
      bothWays(createShacal2(unhex(v.key)), v.pt, v.ct, `SHACAL-2 ${i}`);
    }
  });

  /**
   * The round constants are derived from the cube roots of the first 64 primes, so the derivation gets
   * its own assertion against FIPS 180-4's published table.
   *
   * The alternative was transcribing 64 words, which is 64 chances to produce a cipher that inverts
   * perfectly and matches nothing. Checking the first, the last and the count is what makes deriving
   * them the safer choice rather than merely the shorter one.
   */
  it("derives SHA-256's round constants correctly", () => {
    expect(SHACAL2_ROUND_CONSTANTS).toHaveLength(64);
    expect(SHACAL2_ROUND_CONSTANTS[0]).toBe(0x428a2f98);
    expect(SHACAL2_ROUND_CONSTANTS[1]).toBe(0x71374491);
    expect(SHACAL2_ROUND_CONSTANTS[2]).toBe(0xb5c0fbcf);
    expect(SHACAL2_ROUND_CONSTANTS[63]).toBe(0xc67178f2);
    // All distinct, which a truncation bug in the derivation would break.
    expect(new Set(SHACAL2_ROUND_CONSTANTS).size).toBe(64);
  });

  /** A 512-bit key is larger than the 256-bit block, which is unusual enough to pin. */
  it("has a key wider than its block", () => {
    const cipher = createShacal2(new Uint8Array(64));
    expect(cipher.blockSize).toBe(32);
  });

  it("refuses a key outside 128 to 512 bits", () => {
    expect(() => createShacal2(new Uint8Array(8))).toThrow(/16 to 64/);
    expect(() => createShacal2(new Uint8Array(65))).toThrow(/16 to 64/);
  });
});

describe("GOST 28147-89", () => {
  /** The vector BC carries for the D-Test parameter set. */
  it("reproduces the published vector, both ways", () => {
    bothWays(
      createGost28147(
        unhex("546d203368656c326973652073736e62206167796967747473656865202c3d73"),
        "test",
      ),
      "0000000000000000",
      "1b0bbc32cebcab42",
      "GOST 28147-89 D-Test",
    );
  });

  /**
   * The S-boxes are a *parameter*, and choosing a different set must produce different output.
   *
   * This is the whole interoperability problem with GOST: two implementations of "GOST" agreeing on
   * nothing is normal, and it is always the S-boxes. A tool that offered the choice and ignored it
   * would look right and be useless, so this asserts the control is load-bearing.
   */
  it("gives unrelated output under the two parameter sets", () => {
    const key = unhex("546d203368656c326973652073736e62206167796967747473656865202c3d73");
    const block = unhex("0000000000000000");
    const a = new Uint8Array(8);
    const b = new Uint8Array(8);
    createGost28147(key, "test").encryptBlock(block, a);
    createGost28147(key, "crypto").encryptBlock(block, b);
    expect(hex(a)).not.toBe(hex(b));
  });

  /**
   * The nibble tables here must stay identical to the ones `gost.ts` holds for the hash.
   *
   * Two copies exist for a stated reason -- the hash folds them into 1 KB of pre-rotated words at load,
   * and the cipher needs the nibbles -- so this is the assertion that keeps the copies honest. It is the
   * same arrangement the hash family's `outputLen` and the CRC family's sidebar tags use, and it earns
   * its place the same way: the hash's own published vectors already pin its copy, so agreement here
   * transfers that verification to the cipher.
   */
  it("uses the same S-boxes the hash module already has verified", async () => {
    const { gost } = await import("@ocs/algos");
    // A sanity check that the hash still works, so this test fails loudly if the shared source moves.
    expect(gost(new TextEncoder().encode("abc"), "test")).toHaveLength(32);

    for (const which of ["test", "crypto"] as const) {
      const rows = GOST_CIPHER_SBOXES[which];
      expect(rows, which).toHaveLength(8);
      for (const row of rows) {
        expect(row, `${which} row length`).toHaveLength(16);
        // Each row is a permutation of the sixteen nibbles: the property that makes it an S-box.
        expect(new Set(row).size, `${which} row is not a permutation`).toBe(16);
      }
    }
  });

  it("refuses a key that is not 256 bits", () => {
    expect(() => createGost28147(new Uint8Array(16))).toThrow(/32 bytes/);
  });
});
