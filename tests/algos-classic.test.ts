/**
 * RC2, IDEA, CAST5, SEED, Twofish, Serpent and Kuznyechik against published vectors.
 *
 * Seven ciphers, none of which has an oracle in this tree. OpenSSL 3 has four of them -- RC2, IDEA,
 * CAST5 and SEED -- in its *legacy* provider, which Node does not load and cannot be made to load
 * from JavaScript; Twofish and Serpent it never implemented; and its GOST support lives in a separate
 * engine. So published vectors are the whole check, and the sources are named per algorithm below.
 *
 * Every table in these implementations was **parsed out of its specification by script**, never
 * transcribed: RC2's `PITABLE` and CAST5's eight 1 KB S-boxes from the RFCs, SEED's two S-boxes from
 * RFC 4269 appendix A.1, Kuznyechik's `Pi` from RFC 7801's decimal listing, Twofish's two
 * permutations from the reference implementation, and Serpent's S-boxes from the submission's own
 * `SBoxDecimalTable`. Between them that is about 10 KB of constants; a single mistyped entry in any of
 * them gives a cipher that keys, encrypts, decrypts, round-trips and reproduces nothing.
 *
 * What is *derived* rather than stored is worth knowing too, because it is where the load-time checks
 * are: SEED's four 32-bit SS-boxes come from its two 8-bit ones, Twofish's MDS matrix from its two
 * permutations, Kuznyechik's inverse substitution and linear layer from the forward ones, and
 * Serpent's inverse S-boxes from the forward ones. All four assert the permutation property they rely
 * on, which is what a derivation gets instead of a second table to compare against.
 */
import { describe, expect, it } from "vitest";
import {
  createCast5,
  createIdea,
  createKuznyechik,
  createRc2,
  createSeed,
  createSerpent,
  createTwofish,
  SEED_SS0_FIRST,
  decryptBlockMode,
  encryptBlockMode,
  type BlockCipher,
} from "@ocs/algos";

const fromHex = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/** One block through a cipher, as hex, in either direction. */
function block(cipher: BlockCipher, hex: string, forward = true): string {
  const out = new Uint8Array(cipher.blockSize);
  const src = fromHex(hex);
  if (forward) cipher.encryptBlock(src, out);
  else cipher.decryptBlock(src, out);
  return toHex(out);
}

describe("RC2 (RFC 2268)", () => {
  /**
   * All eight of RFC 2268's vectors, which is the whole published set.
   *
   * They are chosen to exercise the awkward part: the effective key length is a *separate* parameter
   * from the key, so the same 8-byte key appears twice with 63 and 64 effective bits and produces
   * unrelated output, and the same 16-byte key appears with 64 and 128. A 1-byte key and a 33-byte
   * key cover both ends of the range.
   */
  const VECTORS: readonly { keyLen: number; effective: number; key: string; plaintext: string; ciphertext: string }[] = [
    { keyLen: 8, effective: 63, key: "0000000000000000", plaintext: "0000000000000000", ciphertext: "ebb773f993278eff" },
    { keyLen: 8, effective: 64, key: "ffffffffffffffff", plaintext: "ffffffffffffffff", ciphertext: "278b27e42e2f0d49" },
    { keyLen: 8, effective: 64, key: "3000000000000000", plaintext: "1000000000000001", ciphertext: "30649edf9be7d2c2" },
    { keyLen: 1, effective: 64, key: "88", plaintext: "0000000000000000", ciphertext: "61a8a244adacccf0" },
    { keyLen: 7, effective: 64, key: "88bca90e90875a", plaintext: "0000000000000000", ciphertext: "6ccf4308974c267f" },
    { keyLen: 16, effective: 64, key: "88bca90e90875a7f0f79c384627bafb2", plaintext: "0000000000000000", ciphertext: "1a807d272bbe5db1" },
    { keyLen: 16, effective: 128, key: "88bca90e90875a7f0f79c384627bafb2", plaintext: "0000000000000000", ciphertext: "2269552ab0f85ca6" },
    { keyLen: 33, effective: 129, key: "88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e", plaintext: "0000000000000000", ciphertext: "5b78d3a43dfff1f1" },
  ];

  it("reproduces all eight of the RFC's vectors, in both directions", () => {
    for (const v of VECTORS) {
      expect(v.key.length / 2, "the vector's own key length").toBe(v.keyLen);
      const cipher = createRc2(fromHex(v.key), v.effective);
      const label = `${v.keyLen}-byte key, ${v.effective} effective bits`;
      expect(block(cipher, v.plaintext), label).toBe(v.ciphertext);
      expect(block(cipher, v.ciphertext, false), `${label} inverse`).toBe(v.plaintext);
    }
  });

  it("treats the effective key length as a real parameter, not a hint", () => {
    // The same key and plaintext under 64 and 128 effective bits, from the vectors above: unrelated
    // output. This is the property that makes RC2 output differ between tools that default it
    // differently -- OpenSSL uses the key length in bits, which is what this implementation defaults to.
    const key = fromHex("88bca90e90875a7f0f79c384627bafb2");
    expect(block(createRc2(key, 64), "0000000000000000")).toBe("1a807d272bbe5db1");
    expect(block(createRc2(key, 128), "0000000000000000")).toBe("2269552ab0f85ca6");
    expect(block(createRc2(key), "0000000000000000")).toBe("2269552ab0f85ca6");
  });

  it("names its limits", () => {
    expect(() => createRc2(new Uint8Array(0))).toThrow(/1 to 128 bytes/);
    expect(() => createRc2(new Uint8Array(129))).toThrow(/129/);
    expect(() => createRc2(new Uint8Array(8), 0)).toThrow(/1 to 1024 bits/);
  });
});

describe("IDEA", () => {
  // Bouncy Castle's published vectors: two blocks under one key, plus a second plaintext.
  const KEY = "00112233445566778899aabbccddeeff";

  it("reproduces Bouncy Castle's vectors", () => {
    const cipher = createIdea(fromHex(KEY));
    const cases: readonly [string, string][] = [
      ["0001020304050607", "ed732271a7b39f47"],
      ["08090a0b0c0d0e0f", "5b4b2b6719f194bf"],
      ["f0f1f2f3f4f5f6f7", "b8bc6ed5c899265d"],
      ["f8f9fafbfcfdfeff", "2bcfad1fc6d4287d"],
    ];
    for (const [plaintext, expected] of cases) {
      expect(block(cipher, plaintext), plaintext).toBe(expected);
      expect(block(cipher, expected, false), `${plaintext} inverse`).toBe(plaintext);
    }
  });

  it("inverts by undoing each step, which the forward vectors say nothing about", () => {
    /**
     * IDEA does not decrypt with the same subkeys reversed -- the multiplicative ones would have to
     * become inverses in GF(65537) and the additive ones negations. This implementation skips that
     * table and undoes the operations in reverse order instead, so the inverse direction shares no
     * arithmetic with the forward one and needs its own check. The published vectors above assert it
     * per vector; this asserts the property that made it worth doing that way.
     */
    const cipher = createIdea(fromHex(KEY));
    const message = fromHex("0123456789abcdef");
    const sealed = new Uint8Array(8);
    const opened = new Uint8Array(8);
    cipher.encryptBlock(message, sealed);
    cipher.decryptBlock(sealed, opened);
    expect(toHex(opened)).toBe(toHex(message));
    expect(toHex(sealed)).not.toBe(toHex(message));
  });

  it("takes exactly a 16-byte key", () => {
    expect(() => createIdea(new Uint8Array(8))).toThrow(/16 bytes/);
  });
});

describe("CAST5 (RFC 2144)", () => {
  it("reproduces all three of the RFC's vectors, covering both round counts", () => {
    /**
     * 128-, 80- and 40-bit keys. The middle and short ones matter more than they look: RFC 2144
     * section 2.5 says a key of 80 bits or fewer uses *twelve* rounds rather than sixteen, so these
     * three vectors check two different constructions.
     */
    const cases: readonly [string, string, string][] = [
      ["0123456712345678234567893456789a", "0123456789abcdef", "238b4fe5847e44b2"],
      ["01234567123456782345", "0123456789abcdef", "eb6a711a2c02271b"],
      ["0123456712", "0123456789abcdef", "7ac816d16e9b302e"],
    ];
    for (const [key, plaintext, expected] of cases) {
      const cipher = createCast5(fromHex(key));
      const label = `${key.length / 2}-byte key`;
      expect(block(cipher, plaintext), label).toBe(expected);
      expect(block(cipher, expected, false), `${label} inverse`).toBe(plaintext);
    }
  });

  it("switches round count at exactly 80 bits", () => {
    // 10 bytes is 12 rounds, 11 bytes is 16 -- so padding a 10-byte key with a zero byte changes the
    // cipher rather than leaving it alone, which is the surprising part.
    const short = createCast5(fromHex("01234567123456782345"));
    const padded = createCast5(fromHex("0123456712345678234500"));
    expect(block(short, "0123456789abcdef")).not.toBe(block(padded, "0123456789abcdef"));
  });

  it("names its key range", () => {
    expect(() => createCast5(new Uint8Array(4))).toThrow(/5 to 16 bytes/);
    expect(() => createCast5(new Uint8Array(17))).toThrow(/17/);
  });
});

describe("SEED (RFC 4269)", () => {
  it("reproduces all four of the RFC's vectors", () => {
    const cases: readonly [string, string, string][] = [
      ["00000000000000000000000000000000", "000102030405060708090a0b0c0d0e0f", "5ebac6e0054e166819aff1cc6d346cdb"],
      ["000102030405060708090a0b0c0d0e0f", "00000000000000000000000000000000", "c11f22f20140505084483597e4370f43"],
      ["4706480851e61be85d74bfb3fd956185", "83a2f8a288641fb9a4e9a5cc2f131c7d", "ee54d13ebcae706d226bc3142cd40d4a"],
      ["28dbc3bc49ffd87dcfa509b11d422be7", "b41e6be2eba84a148e2eed84593c5ec7", "9b9b7bfcd1813cb95d0b3618f40f5122"],
    ];
    for (const [key, plaintext, expected] of cases) {
      const cipher = createSeed(fromHex(key));
      expect(block(cipher, plaintext), key.slice(0, 8)).toBe(expected);
      expect(block(cipher, expected, false), `${key.slice(0, 8)} inverse`).toBe(plaintext);
    }
  });

  it("derives the SS-boxes correctly, checked against the RFC's own listing", () => {
    /**
     * The four 32-bit SS-boxes are computed from the two 8-bit ones at load, so nothing checks them
     * except the vectors -- unless a published SS value is asserted directly, which is what this is.
     * RFC 4269 appendix A.2 lists `SS0[0]` as `0x2989a1a8`, and it decomposes visibly: `S0[0]` is
     * `0xa9`, and `0xa9 & 0xfc`, `& 0xf3`, `& 0xcf`, `& 0x3f` are `a8`, `a1`, `89`, `29` -- the four
     * bytes of that word, least significant first.
     *
     * Getting the mask rotation backwards was the actual first-attempt bug here, and it produced a
     * cipher that inverted perfectly and reproduced none of the four vectors above.
     */
    expect(SEED_SS0_FIRST).toBe(0x2989a1a8);
    // The module throws at load if its derived table disagrees, so importing the constant at all is
    // the assertion; this pins the published value so the check cannot be quietly relaxed.
    expect(0xa9 & 0xfc).toBe(0xa8);
    expect(0xa9 & 0xf3).toBe(0xa1);
    expect(0xa9 & 0xcf).toBe(0x89);
    expect(0xa9 & 0x3f).toBe(0x29);
  });

  it("takes exactly a 16-byte key", () => {
    expect(() => createSeed(new Uint8Array(24))).toThrow(/16 bytes/);
  });
});

describe("Twofish", () => {
  // Bouncy Castle's vectors: one per key size, over the same plaintext.
  const INPUT = "000102030405060708090a0b0c0d0e0f";

  it("reproduces Bouncy Castle's vectors at all three key sizes", () => {
    const cases: readonly [string, string][] = [
      ["000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ef0272c42db838bcf7b07af0ec30f38"],
      ["000102030405060708090a0b0c0d0e0f1011121314151617", "95accc625366547617f8be4373d10cd7"],
      ["000102030405060708090a0b0c0d0e0f", "9fb63337151be9c71306d159ea7afaa4"],
    ];
    for (const [key, expected] of cases) {
      const cipher = createTwofish(fromHex(key));
      const label = `${(key.length / 2) * 8}-bit key`;
      expect(block(cipher, INPUT), label).toBe(expected);
      expect(block(cipher, expected, false), `${label} inverse`).toBe(INPUT);
    }
  });

  it("builds different S-boxes per key, which is the design", () => {
    // Twofish's S-boxes are key-dependent, so two keys differing in one bit give unrelated output --
    // and the *same* key must give the same output twice, which a stale expansion would break.
    const a = createTwofish(fromHex("00".repeat(16)));
    const b = createTwofish(fromHex("01" + "00".repeat(15)));
    expect(block(a, INPUT)).not.toBe(block(b, INPUT));
    expect(block(a, INPUT)).toBe(block(a, INPUT));
  });

  it("names its key sizes", () => {
    expect(() => createTwofish(new Uint8Array(20))).toThrow(/16, 24 or 32 bytes/);
  });
});

describe("Serpent", () => {
  it("reproduces Bouncy Castle's vectors", () => {
    const cases: readonly [string, string, string][] = [
      ["00000000000000000000000000000000", "00000000000000000000000000000000", "3620b17ae6a993d09618b8768266bae9"],
      ["80000000000000000000000000000000", "00000000000000000000000000000000", "264e5481eff42a4606abda06c0bfda3d"],
      ["d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9", "d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9", "20ea07f19c8e93fda30f6b822ad5d486"],
      ["000000000000000000000000000000000000000000008000", "00000000000000000000000000000000", "40520018c4ac2bba285aeeb9bcb58755"],
      ["0000000000000000000000000000000000000000000000000000000000000000", "00000000000000000000000000000001", "ad86de83231c3203a86ae33b721eaa9f"],
    ];
    for (const [key, plaintext, expected] of cases) {
      const cipher = createSerpent(fromHex(key));
      const label = `${(key.length / 2) * 8}-bit key`;
      expect(block(cipher, plaintext), label).toBe(expected);
      expect(block(cipher, expected, false), `${label} inverse`).toBe(plaintext);
    }
  });

  it("pads a short key with a one bit, so zero-extending it is not the same", () => {
    /**
     * The property Bouncy Castle's first and fifth vectors happen to pin: an all-zero 128-bit key and
     * an all-zero 256-bit key give different ciphertexts, because the shorter one gets a `1` bit
     * appended before the zero padding. An implementation that padded with zeros alone would agree
     * with itself and disagree with everything else.
     */
    const short = createSerpent(fromHex("00".repeat(16)));
    const long = createSerpent(fromHex("00".repeat(32)));
    expect(block(short, "00".repeat(16))).not.toBe(block(long, "00".repeat(16)));
  });

  it("names its key sizes", () => {
    expect(() => createSerpent(new Uint8Array(20))).toThrow(/16, 24 or 32 bytes/);
  });
});

describe("Kuznyechik (RFC 7801)", () => {
  const KEY = "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef";

  it("reproduces RFC 7801's test example", () => {
    const cipher = createKuznyechik(fromHex(KEY));
    expect(block(cipher, "1122334455667700ffeeddccbbaa9988")).toBe(
      "7f679d90bebc24305a468d42b9d4edcd",
    );
  });

  it("reproduces the RFC's decryption example, which is a separate check", () => {
    /**
     * Not merely the inverse of the line above: RFC 7801 gives the decryption path its own worked
     * example, and this implementation's inverse linear layer is *derived* from the forward one rather
     * than tabulated separately -- so this is the assertion that says the derivation is right.
     */
    const cipher = createKuznyechik(fromHex(KEY));
    expect(block(cipher, "7f679d90bebc24305a468d42b9d4edcd", false)).toBe(
      "1122334455667700ffeeddccbbaa9988",
    );
  });

  it("takes exactly a 32-byte key", () => {
    expect(() => createKuznyechik(new Uint8Array(16))).toThrow(/32 bytes/);
  });
});

describe("the seven new ciphers through the shared mode layer", () => {
  it("round-trip in every mode at a length that is not a whole block", () => {
    // 21 bytes: a multiple of neither 8 nor 16, so the padded modes exercise PKCS#7 and the stream
    // modes their partial final block.
    const message = new Uint8Array(21).fill(0x5a);
    const factories: readonly [string, () => BlockCipher][] = [
      ["rc2", () => createRc2(fromHex("0123456789abcdef"))],
      ["idea", () => createIdea(fromHex("00".repeat(16)))],
      ["cast5", () => createCast5(fromHex("0123456789abcdef01234567"))],
      ["seed", () => createSeed(fromHex("00".repeat(16)))],
      ["twofish", () => createTwofish(fromHex("11".repeat(32)))],
      ["serpent", () => createSerpent(fromHex("22".repeat(16)))],
      ["kuznyechik", () => createKuznyechik(fromHex("33".repeat(32)))],
    ];

    for (const [name, make] of factories) {
      const size = make().blockSize;
      const iv = new Uint8Array(size).fill(0x44);
      for (const mode of ["ecb", "cbc", "cfb", "ofb", "ctr"] as const) {
        const options = mode === "ecb" ? {} : { iv };
        const sealed = encryptBlockMode(make(), mode, message, options);
        const opened = decryptBlockMode(make(), mode, sealed, options);
        expect(toHex(opened), `${name}/${mode}`).toBe(toHex(message));
      }
    }
  });

  it("does not mutate the source block, as the BlockCipher contract requires", () => {
    // The bug noble's `unsafe.encryptBlock` caused for AES: an in-place cipher destroys a counter
    // block, which is right for CTR's first block and wrong for every one after it.
    const ciphers = [
      createRc2(fromHex("0123456789abcdef")),
      createIdea(fromHex("00".repeat(16))),
      createCast5(fromHex("0123456789abcdef01234567")),
      createSeed(fromHex("00".repeat(16))),
      createTwofish(fromHex("11".repeat(32))),
      createSerpent(fromHex("22".repeat(16))),
      createKuznyechik(fromHex("33".repeat(32))),
    ];
    for (const cipher of ciphers) {
      const src = new Uint8Array(cipher.blockSize).fill(0x11);
      const before = toHex(src);
      cipher.encryptBlock(src, new Uint8Array(cipher.blockSize));
      expect(toHex(src)).toBe(before);
      cipher.decryptBlock(src, new Uint8Array(cipher.blockSize));
      expect(toHex(src)).toBe(before);
    }
  });
});
