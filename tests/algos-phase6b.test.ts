/**
 * CLEFIA, MARS and Rabbit -- the second Phase 6 batch.
 *
 * None has an oracle: OpenSSL implemented none of them and no dependency in this tree has any. Each
 * rests on published vectors, and the sources are worth naming because they are what made this batch
 * possible after Bouncy Castle turned out to carry nothing:
 *
 *  - **CLEFIA**: RFC 6114, which publishes the whole specification, its own test vectors *and*
 *    per-round intermediate values. Three key lengths, both directions -- plus the constant tables,
 *    which let this implementation *derive* the round constants and still be checked entry by entry.
 *  - **MARS**: Crypto++'s `TestVectors/mars.txt`, ten known-answer vectors across all three key
 *    lengths, both directions.
 *  - **Rabbit**: RFC 4503, six vectors of three 128-bit keystream blocks each -- three without IV
 *    setup and three with, which is the distinction most likely to be got wrong.
 *
 * Three bugs from this batch, and two of them were mine rather than the code's:
 *
 *  - **CLEFIA's `z^-1` fold.** Halving in GF(2^16) means adding the polynomial first when the value is
 *    odd, and 0x1a831 is what the RFC specifies. A guessed constant produced the right first two
 *    constants and then diverged -- caught only because the RFC prints the T and CON tables so the
 *    derivation can be checked rather than assumed.
 *  - **A test harness with key and plaintext swapped.** RFC 6114 lists the key first; the first draft
 *    of the probe read the columns in the other order and failed all six assertions while the
 *    implementation was already correct. Both S-boxes, every round key and every intermediate value
 *    matched the RFC's Appendix B throughout, which is what localised it -- to the harness.
 *  - **MARS's Monte Carlo vectors are not known-answer vectors.** Six of the sixteen entries in
 *    `mars.txt` are `MCT` cases: a 10,000-iteration chained protocol with key feedback. Feeding them
 *    through as single blocks compares a chained answer against one encryption, and the fixture
 *    filters on `Test: Encrypt` for that reason.
 */
import { describe, expect, it } from "vitest";
import {
  CLEFIA_CONSTANTS,
  CLEFIA_SBOX_FIRST,
  createClefia,
  createMars,
  createRabbit,
  decryptBlockMode,
  encryptBlockMode,
  rabbitCrypt,
} from "@ocs/algos";
import {
  CLEFIA_VECTORS,
  MARS_VECTORS,
  RABBIT_NO_IV,
  RABBIT_WITH_IV,
  RFC6114_CON_128,
  RFC6114_CON_192,
  RFC6114_CON_256,
  RFC6114_T_128,
  RFC6114_T_192,
  RFC6114_T_256,
} from "./phase6b-vectors";

const unhex = (text: string): Uint8Array =>
  text === "" ? new Uint8Array(0) : Uint8Array.from(text.match(/../g)!.map((p) => parseInt(p, 16)));
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const oneBlock = (cipher: BlockLike, src: Uint8Array, decrypt = false): string => {
  const out = new Uint8Array(cipher.blockSize);
  if (decrypt) cipher.decryptBlock(src, out);
  else cipher.encryptBlock(src, out);
  return hex(out);
};
interface BlockLike {
  blockSize: number;
  encryptBlock(s: Uint8Array, d: Uint8Array): void;
  decryptBlock(s: Uint8Array, d: Uint8Array): void;
}

describe("CLEFIA", () => {
  it("transcribes RFC 6114's two S-boxes", () => {
    // Table 1 row 0 column 0, and Table 2's. Both are checked to be permutations at module load.
    expect(CLEFIA_SBOX_FIRST).toEqual([0x57, 0x6c]);
  });

  it("derives the round constants rather than storing them", () => {
    /**
     * RFC 6114 publishes T_k[i] (Tables 4-6) and CON_k[i] (Tables 7-9) so an implementation can check
     * its own generator. That is what makes deriving 236 constants safe instead of merely shorter --
     * and it is what caught the `z^-1` fold being wrong, since the first two constants were right.
     */
    for (const [bits, refT, refCon] of [
      ["128", RFC6114_T_128, RFC6114_CON_128],
      ["192", RFC6114_T_192, RFC6114_CON_192],
      ["256", RFC6114_T_256, RFC6114_CON_256],
    ] as const) {
      const derived = CLEFIA_CONSTANTS[bits]!;
      expect(derived.t.length, `T_${bits} length`).toBeGreaterThanOrEqual(refT.length);
      for (let i = 0; i < refT.length; i++) {
        expect(derived.t[i], `T_${bits}[${i}]`).toBe(refT[i]);
      }
      expect(derived.con, `CON_${bits}`).toEqual([...refCon]);
    }
  });

  it("reproduces RFC 6114's vectors at all three key lengths, in both directions", () => {
    expect(CLEFIA_VECTORS).toHaveLength(3);
    for (const v of CLEFIA_VECTORS) {
      const cipher = createClefia(unhex(v.key));
      expect(oneBlock(cipher, unhex(v.plaintext)), `encrypt ${v.key.length * 4}-bit`).toBe(
        v.ciphertext,
      );
      // The published plaintext, not a re-encryption: CLEFIA's inverse reverses both the round-key
      // order and the word rotation, and getting one of the two wrong is self-consistent.
      expect(oneBlock(cipher, unhex(v.ciphertext), true), `decrypt ${v.key.length * 4}-bit`).toBe(
        v.plaintext,
      );
    }
  });

  it("gives the three key lengths three different round counts", () => {
    // 18, 22 and 26 rounds, so the same plaintext under a padded key is a different ciphertext --
    // which is worth pinning because a schedule that ignored the length would still produce 16 bytes.
    const pt = unhex("000102030405060708090a0b0c0d0e0f");
    const base = "ffeeddccbbaa99887766554433221100";
    const a = oneBlock(createClefia(unhex(base)), pt);
    const b = oneBlock(createClefia(unhex(base + "00".repeat(8))), pt);
    const c = oneBlock(createClefia(unhex(base + "00".repeat(16))), pt);
    expect(new Set([a, b, c]).size).toBe(3);
  });

  it("refuses a key that is not 16, 24 or 32 bytes", () => {
    expect(() => createClefia(new Uint8Array(20))).toThrow(/16, 24 or 32/);
  });
});

describe("MARS", () => {
  it("reproduces all ten Crypto++ vectors, in both directions", () => {
    expect(MARS_VECTORS).toHaveLength(10);
    const lengths = new Set(MARS_VECTORS.map((v) => v.key.length / 2));
    // All three key lengths appear, which is what makes the fixture worth ten entries.
    expect([...lengths].sort((a, b) => a - b)).toEqual([16, 24, 32]);
    for (const v of MARS_VECTORS) {
      const cipher = createMars(unhex(v.key));
      expect(oneBlock(cipher, unhex(v.plaintext)), `encrypt ${v.key}`).toBe(v.ciphertext);
      expect(oneBlock(cipher, unhex(v.ciphertext), true), `decrypt ${v.key}`).toBe(v.plaintext);
    }
  });

  it("needs Math.imul for the quadratic term", () => {
    /**
     * `t * k` in the keyed round exceeds 2^53, so plain `*` silently loses the low bits it is supposed
     * to keep. The AES submission's own vectors use one-bit plaintexts, which is exactly where that
     * shows -- and the first vector below is such a case, so the whole fixture would fail. This
     * asserts the observable consequence rather than the implementation detail: a one-bit change in
     * the plaintext must change the whole block.
     */
    const cipher = createMars(unhex("00".repeat(16)));
    const zero = oneBlock(cipher, new Uint8Array(16));
    const oneBit = oneBlock(cipher, unhex("80000000000000000000000000000000"));
    expect(zero).not.toBe(oneBit);
    // And the reference's value for the all-zero case, which pins it rather than merely differing.
    expect(zero).toBe("dcc07b8dfb0738d6e30a22dfcf27e886");
  });

  it("works through the shared mode layer at every mode", () => {
    // MARS has no published mode vectors, so this is a round trip -- stated as such rather than
    // presented as verification. The block function itself is what the ten vectors above cover.
    const cipher = createMars(unhex("00".repeat(32)));
    const data = Uint8Array.from({ length: 37 }, (_, i) => (i * 5 + 1) & 0xff);
    const iv = unhex("000102030405060708090a0b0c0d0e0f");
    for (const mode of ["ecb", "cbc", "cfb", "ofb", "ctr"] as const) {
      const options = mode === "ecb" ? {} : { iv };
      const enc = encryptBlockMode(cipher, mode, data, options);
      expect(hex(decryptBlockMode(cipher, mode, enc, options)), mode).toBe(hex(data));
    }
  });

  it("refuses a key that is not 16, 24 or 32 bytes", () => {
    expect(() => createMars(new Uint8Array(40))).toThrow(/16, 24 or 32/);
  });
});

describe("Rabbit", () => {
  it("reproduces RFC 4503's vectors without IV setup", () => {
    expect(RABBIT_NO_IV).toHaveLength(3);
    for (const v of RABBIT_NO_IV) {
      const gen = createRabbit(unhex(v.key), new Uint8Array(0));
      // Three consecutive 128-bit blocks from one generator, so this also checks the state advances.
      for (let i = 0; i < 3; i++) {
        expect(hex(gen.keystream(16)), `key ${v.key} S[${i}]`).toBe(v.blocks[i]);
      }
    }
  });

  it("reproduces RFC 4503's vectors with IV setup", () => {
    expect(RABBIT_WITH_IV).toHaveLength(3);
    for (const v of RABBIT_WITH_IV) {
      const gen = createRabbit(unhex("00".repeat(16)), unhex(v.iv));
      for (let i = 0; i < 3; i++) {
        expect(hex(gen.keystream(16)), `iv ${v.iv} S[${i}]`).toBe(v.blocks[i]);
      }
    }
  });

  it("treats an empty IV as no IV setup, not as eight zero bytes", () => {
    /**
     * The distinction the RFC's two vector sets exist to draw, and the one thing about this cipher a
     * caller can get wrong with no error: the all-zero key with no IV gives `b157...`, and the same
     * key with an all-zero IV gives `c6a7...`. Both are published, and they are unrelated.
     */
    const noIv = hex(createRabbit(unhex("00".repeat(16)), new Uint8Array(0)).keystream(16));
    const zeroIv = hex(createRabbit(unhex("00".repeat(16)), new Uint8Array(8)).keystream(16));
    expect(noIv).toBe("b15754f036a5d6ecf56b45261c4af702");
    expect(zeroIv).toBe("c6a7275ef85495d87ccd5d376705b7ed");
  });

  it("is its own inverse, and produces the keystream in any chunking", () => {
    const key = unhex("912813292e3d36fe3bfc62f1dc51c3ac");
    const iv = unhex("c373f575c1267e59");
    const data = Uint8Array.from({ length: 100 }, (_, i) => (i * 3 + 7) & 0xff);
    const enc = rabbitCrypt(key, iv, data);
    expect(hex(rabbitCrypt(key, iv, enc))).toBe(hex(data));
    // The generator buffers a 16-byte block, so requests that straddle it must not lose bytes.
    const whole = hex(createRabbit(key, iv).keystream(100));
    let piecewise = "";
    const gen = createRabbit(key, iv);
    for (const n of [1, 7, 16, 17, 30, 29]) piecewise += hex(gen.keystream(n));
    expect(piecewise).toBe(whole);
  });

  it("refuses a key or IV of the wrong length", () => {
    expect(() => createRabbit(new Uint8Array(8), new Uint8Array(0))).toThrow(/exactly 16 bytes/);
    expect(() => createRabbit(new Uint8Array(16), new Uint8Array(4))).toThrow(/8 bytes, or empty/);
  });
});
