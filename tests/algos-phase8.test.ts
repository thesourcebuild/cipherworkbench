/**
 * Trivium, KASUMI and Khazad -- the three algorithms that needed a third vector source.
 *
 * Bouncy Castle has none of them and Crypto++ has none of them. **Botan 2.19.3** supplied KASUMI's
 * (and, as a bonus, a second independent set for MISTY1 -- asserted below, because corroborating an
 * algorithm already shipped is nearly free and worth having). **avr-crypto-lib** supplied Trivium's and
 * Khazad's, by mirroring the eSTREAM and NESSIE submission files that `ecrypt.eu.org` no longer serves.
 *
 * No oracle for any of the three. What stands behind each, and the shapes are deliberately different:
 *
 *  - **Trivium**: eSTREAM's verified files at all three IV widths. Each vector checks four windows of
 *    keystream, the last at offset 448 -- so a state that drifted after the first block cannot pass.
 *    Its loading convention was settled by reading a reference after three plausible guesses failed.
 *  - **KASUMI**: three vectors, both directions each. Thin, and stated as thin.
 *  - **Khazad**: NESSIE vectors carrying a ciphertext *and* the result of encrypting 100 and 1,000
 *    times over. The iterated values are the valuable part: they exercise the cipher against its own
 *    output, which catches a fault that a single block cannot reach.
 *
 * Two properties are asserted rather than transcribed, because both are what the designs rest on:
 * Khazad's S-box is derived from sixteen bytes and must be a permutation, and its diffusion matrix must
 * be *involutory* -- H times H is the identity, which is why one circuit serves both directions.
 */
import { describe, expect, it } from "vitest";
import {
  createKasumi,
  createKhazad,
  createMisty1,
  createTrivium,
  KASUMI_SBOX_FIRST,
  KHAZAD_MATRIX,
  KHAZAD_SBOX_FIRST,
  MISTY1_S7_FIRST,
  triviumCrypt,
} from "@ocs/algos";
import { KASUMI_VECTORS, KHAZAD_VECTORS, TRIVIUM_VECTORS } from "./phase8-vectors";

const unhex = (text: string): Uint8Array =>
  text === "" ? new Uint8Array(0) : Uint8Array.from(text.match(/../g)!.map((p) => parseInt(p, 16)));
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

interface BlockLike {
  blockSize: number;
  encryptBlock(s: Uint8Array, d: Uint8Array): void;
  decryptBlock(s: Uint8Array, d: Uint8Array): void;
}
const one = (cipher: BlockLike, src: Uint8Array, decrypt = false): Uint8Array => {
  const out = new Uint8Array(cipher.blockSize);
  if (decrypt) cipher.decryptBlock(src, out);
  else cipher.encryptBlock(src, out);
  return out;
};

describe("Trivium", () => {
  it("reproduces eSTREAM's vectors at all three IV widths", () => {
    let checked = 0;
    for (const [bits, vectors] of Object.entries(TRIVIUM_VECTORS)) {
      expect(vectors.length, `${bits}-bit IV`).toBeGreaterThan(0);
      for (const v of vectors) {
        expect(unhex(v.iv), `${bits}-bit IV length`).toHaveLength(Number(bits) / 8);
        const gen = createTrivium(unhex(v.key), unhex(v.iv));
        const end = Math.max(...v.streams.map((s) => s.from + s.hex.length / 2));
        const ks = gen.keystream(end);
        for (const window of v.streams) {
          const got = hex(ks.subarray(window.from, window.from + window.hex.length / 2));
          expect(got, `IV${bits} key ${v.key} at ${window.from}`).toBe(window.hex);
          checked += 1;
        }
      }
    }
    // Two vectors per width, four windows each.
    expect(checked).toBe(24);
  });

  it("checks a window far enough out to catch a drifting state", () => {
    /**
     * The point of eSTREAM's four-window layout, and the reason the fixture keeps all four rather than
     * just the first: Trivium warms up for 1,152 rounds and then emits. A fault in the feedback taps
     * that happened to agree for the first block would show by offset 448, which is 3,584 rounds in.
     */
    const offsets = Object.values(TRIVIUM_VECTORS)
      .flat()
      .flatMap((v) => v.streams.map((s) => s.from));
    expect(Math.max(...offsets)).toBeGreaterThanOrEqual(448);
  });

  it("is its own inverse, and chunks the keystream without losing bytes", () => {
    const key = unhex("0f62b5085bae0154a7fa");
    const iv = unhex("288ff65dc42b92f960c7");
    const data = Uint8Array.from({ length: 100 }, (_, i) => (i * 3 + 7) & 0xff);
    expect(hex(triviumCrypt(key, iv, triviumCrypt(key, iv, data)))).toBe(hex(data));

    const whole = hex(createTrivium(key, iv).keystream(100));
    const gen = createTrivium(key, iv);
    let piecewise = "";
    for (const n of [1, 7, 16, 17, 30, 29]) piecewise += hex(gen.keystream(n));
    expect(piecewise).toBe(whole);
  });

  it("refuses a key or IV of the wrong length", () => {
    expect(() => createTrivium(new Uint8Array(16), new Uint8Array(10))).toThrow(/exactly 10 bytes/);
    expect(() => createTrivium(new Uint8Array(10), new Uint8Array(6))).toThrow(/4, 8 or 10/);
  });
});

describe("KASUMI", () => {
  it("reproduces Botan's vectors in both directions", () => {
    expect(KASUMI_VECTORS).toHaveLength(3);
    for (const v of KASUMI_VECTORS) {
      const cipher = createKasumi(unhex(v.key));
      expect(hex(one(cipher, unhex(v.plaintext))), `encrypt ${v.key}`).toBe(v.ciphertext);
      // Against the published plaintext, not a re-encryption.
      expect(hex(one(cipher, unhex(v.ciphertext), true)), `decrypt ${v.key}`).toBe(v.plaintext);
    }
  });

  it("does not share MISTY1's S-boxes, though it is derived from MISTY1", () => {
    /**
     * 3GPP replaced both boxes and changed FI when it derived KASUMI. Sharing either with
     * `phase6-ciphers.ts` would give a cipher that inverts perfectly and reproduces nothing -- and the
     * two are near enough that reusing one by mistake is a live risk rather than a hypothetical.
     */
    expect(KASUMI_SBOX_FIRST[0]).not.toBe(MISTY1_S7_FIRST);
    expect(KASUMI_SBOX_FIRST).toEqual([0x36, 0xa7]);

    const key = unhex("00112233445566778899aabbccddeeff");
    const block = unhex("0123456789abcdef");
    expect(hex(one(createKasumi(key), block))).not.toBe(hex(one(createMisty1(key), block)));
  });

  it("corroborates MISTY1 against Botan's own vector, which is a second source", () => {
    // Botan's `misty.vec` opens with the same key and plaintext RFC 2994 uses, and the same answer.
    // Two independent transcriptions agreeing is worth an assertion, and it costs one line.
    const cipher = createMisty1(unhex("00112233445566778899aabbccddeeff"));
    expect(hex(one(cipher, unhex("0123456789abcdef")))).toBe("8b1da5f56ab3d07c");
  });

  it("refuses a key that is not 16 bytes", () => {
    expect(() => createKasumi(new Uint8Array(8))).toThrow(/exactly 16 bytes/);
  });
});

describe("Khazad", () => {
  it("derives its S-box from sixteen bytes, and the result is a permutation", () => {
    /**
     * The permutation property is checked at module load; this pins the first entry so a change to the
     * packed P/Q table fails here rather than only in the vectors. There is no 256-entry table in the
     * implementation at all, which is the strongest form of the derive-don't-transcribe rule.
     */
    expect(KHAZAD_SBOX_FIRST).toBe(0xba);
  });

  it("has an involutory diffusion matrix, which is why one circuit does both directions", () => {
    /**
     * H times H must be the identity over GF(2^8) under 0x11d. Asserted rather than trusted, because
     * the matrix is transcribed and a single wrong nibble would leave encryption correct while making
     * decryption a different function -- exactly the failure a round trip cannot see.
     */
    const mul = (a: number, b: number): number => {
      let r = 0;
      let x = a;
      let y = b;
      while (y !== 0) {
        if ((y & 1) !== 0) r ^= x;
        x = ((x << 1) ^ (x & 0x80 ? 0x11d : 0)) & 0xff;
        y >>= 1;
      }
      return r & 0xff;
    };
    expect(KHAZAD_MATRIX).toHaveLength(8);
    for (let i = 0; i < 8; i++) {
      for (let j = 0; j < 8; j++) {
        let acc = 0;
        for (let k = 0; k < 8; k++) acc ^= mul(KHAZAD_MATRIX[i]![k]!, KHAZAD_MATRIX[k]![j]!);
        expect(acc, `H*H at (${i},${j})`).toBe(i === j ? 1 : 0);
      }
    }
  });

  it("reproduces the NESSIE vectors, including the iterated values", () => {
    /**
     * Every fifteenth of 450, which spans all four NESSIE sets -- stated because a fixture that
     * silently sampled would read as full coverage. The iterated values are what make each row worth
     * more than a single block: encrypting the result 1,000 times over drives the cipher through its
     * own output, which reaches faults a one-shot vector cannot.
     */
    expect(KHAZAD_VECTORS).toHaveLength(30);
    for (const v of KHAZAD_VECTORS) {
      const cipher = createKhazad(unhex(v.key));
      expect(hex(one(cipher, unhex(v.plaintext))), `encrypt ${v.key}`).toBe(v.ciphertext);
      expect(hex(one(cipher, unhex(v.ciphertext), true)), `decrypt ${v.key}`).toBe(v.plaintext);

      let block = unhex(v.plaintext);
      for (let i = 1; i <= 1000; i++) {
        block = one(cipher, block);
        if (i === 100) expect(hex(block), `${v.key} iterated 100`).toBe(v.iterated100);
      }
      expect(hex(block), `${v.key} iterated 1000`).toBe(v.iterated1000);
    }
  });

  it("refuses a key that is not 16 bytes", () => {
    expect(() => createKhazad(new Uint8Array(8))).toThrow(/exactly 16 bytes/);
  });
});
