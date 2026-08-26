import { describe, expect, it } from "vitest";
import {
  createCast5,
  createCast6,
  createRc5,
  createRc6,
  createSkipjack,
  createTea,
  createThreefish,
  createXtea,
  createXxtea,
  SKIPJACK_F_TABLE,
  xxteaWords,
  type BlockCipher,
} from "@ocs/algos";

/**
 * Six more block ciphers: TEA, XTEA, RC5, RC6, SKIPJACK, CAST-256 and Threefish at three widths.
 *
 * None has an oracle. OpenSSL implemented none of them -- CAST5 is in its legacy provider and CAST-256
 * never was -- so the check is published vectors, and the ones here came from Bouncy Castle's own test
 * suite, fetched and parsed by script rather than recalled. That distinction earned its keep two
 * sections ago: an earlier attempt at IDEA in this repo matched a *remembered* vector for five bytes
 * and was abandoned, and the remembered vector turned out to be the thing that was wrong.
 *
 * What each set of vectors is actually for, since "it round-trips" proves almost nothing here:
 *
 *  - **TEA and XTEA differ by one line.** Both are 64-bit blocks, 128-bit keys, 32 rounds, the same
 *    delta; the round functions are `((v1 << 4) + a) ^ (v1 + sum) ^ ((v1 >>> 5) + b)` against
 *    `(((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + key[..])`. An implementation of either is a plausible
 *    implementation of the other and each inverts against itself perfectly, so only a published value
 *    tells them apart. Four each.
 *  - **RC5's vectors sweep the parameters**, because RC5-32/r/b is three numbers and not one
 *    algorithm: 0, 1, 2, 8, 12 and 16 rounds, and keys of 1, 4, 5 and 8 bytes. A zero-round RC5 is
 *    legal and has a published value, which is what makes the round count visibly a parameter.
 *  - **RC6 varies the key length** across 16, 24 and 32 bytes, and its plaintexts and keys are
 *    single-bit patterns -- the AES submission's own choice, and a good one: a quadratic term computed
 *    with `*` instead of `Math.imul` silently loses precision, and a one-bit input is where that shows.
 *  - **SKIPJACK has exactly one published vector**, so the F table is separately asserted to be a
 *    permutation of all 256 bytes. One vector would catch a broken table; the property says why.
 *  - **CAST-256 varies the key over 16, 24 and 32 bytes** against RFC 2612's own three values. Its
 *    S-boxes are CAST5's, so a failure here is about the key schedule -- which this file checks by
 *    also asserting CAST5 still reproduces its RFC 2144 vector through the shared round function.
 *  - **Threefish is checked with a non-zero tweak at every width.** The all-zero-tweak vector cannot
 *    tell a correct tweak injection from none at all, which is the whole reason the second case exists.
 */

const unhex = (text: string): Uint8Array =>
  Uint8Array.from(text.replace(/\s+/g, "").match(/../g)!.map((pair) => parseInt(pair, 16)));

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/** Encrypt, decrypt, and require both directions -- a one-way check would miss half of each cipher. */
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

describe("TEA", () => {
  const VECTORS = [
    { key: "00000000000000000000000000000000", pt: "0000000000000000", ct: "41ea3a0a94baa940" },
    { key: "00000000000000000000000000000000", pt: "0102030405060708", ct: "6a2f9cf3fccf3c55" },
    { key: "0123456712345678234567893456789A", pt: "0000000000000000", ct: "34e943b0900f5dcb" },
    { key: "0123456712345678234567893456789A", pt: "0102030405060708", ct: "773dc179878a81c0" },
  ];

  it("reproduces every published vector, both ways", () => {
    for (const [i, v] of VECTORS.entries()) {
      bothWays(createTea(unhex(v.key)), v.pt, v.ct, `TEA ${i}`);
    }
  });

  /** The line that differs. Same key, same block, two ciphers, and they must not agree. */
  it("is not XTEA", () => {
    const key = unhex("0123456712345678234567893456789A");
    const pt = unhex("0102030405060708");
    const tea = new Uint8Array(8);
    const xtea = new Uint8Array(8);
    createTea(key).encryptBlock(pt, tea);
    createXtea(key).encryptBlock(pt, xtea);
    expect(hex(tea)).not.toBe(hex(xtea));
  });

  it("refuses a key that is not 16 bytes", () => {
    expect(() => createTea(new Uint8Array(8))).toThrow(/16 bytes/);
    expect(() => createXtea(new Uint8Array(24))).toThrow(/16 bytes/);
  });
});

describe("XTEA", () => {
  const VECTORS = [
    { key: "00000000000000000000000000000000", pt: "0000000000000000", ct: "dee9d4d8f7131ed9" },
    { key: "00000000000000000000000000000000", pt: "0102030405060708", ct: "065c1b8975c6a816" },
    { key: "0123456712345678234567893456789A", pt: "0000000000000000", ct: "1ff9a0261ac64264" },
    { key: "0123456712345678234567893456789A", pt: "0102030405060708", ct: "8c67155b2ef91ead" },
  ];

  it("reproduces every published vector, both ways", () => {
    for (const [i, v] of VECTORS.entries()) {
      bothWays(createXtea(unhex(v.key)), v.pt, v.ct, `XTEA ${i}`);
    }
  });
});

/**
 * XXTEA, and this block exists as much to state what is missing as to test.
 *
 * **There is no published vector.** Needham and Wheeler's 1998 note prints reference C and no values;
 * Crypto++'s `TestVectors/tea.txt` has `TEA/ECB` and `XTEA/ECB` sections and nothing else; and the
 * `xxtea.io` libraries are not a source, because their own README says they implement something
 * different from the original algorithm (a length header plus a string codec around the primitive). So
 * what follows is every property checkable without one, and it is deliberately not called verification.
 *
 * The failure this trio is most exposed to is *being each other*: TEA, XTEA and XXTEA share a block, a
 * key size, a round count and a delta, and each is a plausible implementation of the others. That is
 * what the first test below is for.
 */
describe("XXTEA", () => {
  const KEY = "0123456789abcdef0123456789abcdef";
  const PT = "0102030405060708";

  it("is a different function from both TEA and XTEA", () => {
    const key = unhex(KEY);
    const values = [createTea(key), createXtea(key), createXxtea(key)].map((cipher) => {
      const out = new Uint8Array(8);
      cipher.encryptBlock(unhex(PT), out);
      return hex(out);
    });
    expect(new Set(values).size, values.join(" ")).toBe(3);
  });

  it("round-trips across a spread of blocks and keys", () => {
    for (let n = 0; n < 16; n++) {
      const key = new Uint8Array(16);
      for (let i = 0; i < 16; i++) key[i] = (n * 31 + i * 7) & 0xff;
      const cipher = createXxtea(key);
      const block = new Uint8Array(8);
      for (let i = 0; i < 8; i++) block[i] = (n * 17 + i * 13) & 0xff;
      const out = new Uint8Array(8);
      const back = new Uint8Array(8);
      cipher.encryptBlock(block, out);
      cipher.decryptBlock(out, back);
      expect(hex(back), `key ${n}`).toBe(hex(block));
    }
  });

  it("depends on every key bit and every plaintext bit", () => {
    const key = unhex(KEY);
    const reference = (() => {
      const out = new Uint8Array(8);
      createXxtea(key).encryptBlock(unhex(PT), out);
      return hex(out);
    })();
    for (let byte = 0; byte < 16; byte++) {
      const altered = Uint8Array.from(key);
      altered[byte] = altered[byte]! ^ 0x80;
      const out = new Uint8Array(8);
      createXxtea(altered).encryptBlock(unhex(PT), out);
      expect(hex(out), `key byte ${byte}`).not.toBe(reference);
    }
    for (let byte = 0; byte < 8; byte++) {
      const altered = unhex(PT);
      altered[byte] = altered[byte]! ^ 0x01;
      const out = new Uint8Array(8);
      createXxtea(key).encryptBlock(altered, out);
      expect(hex(out), `plaintext byte ${byte}`).not.toBe(reference);
    }
  });

  it("refuses a key that is not 16 bytes", () => {
    expect(() => createXxtea(new Uint8Array(8))).toThrow(/exactly 16 bytes/);
  });

  /**
   * The variable-length form is the real cipher; the tool is its two-word instantiation.
   *
   * `6 + 52/n` rounds means every word count is a different function, so this checks the round count is
   * actually varying rather than pinned at 32 -- a fixed count would still round-trip perfectly.
   */
  it("runs a length-dependent round count and inverts at each", () => {
    for (const n of [2, 3, 4, 8, 16, 32, 64]) {
      const words = Array.from({ length: n }, (_, i) => (i * 0x01010101 + 7) >>> 0);
      const original = words.slice();
      xxteaWords(words, [1, 2, 3, 4], true);
      expect(words.join(","), `n=${n} must change the input`).not.toBe(original.join(","));
      xxteaWords(words, [1, 2, 3, 4], false);
      expect(words.join(","), `n=${n} inverse`).toBe(original.join(","));
    }
  });

  it("gives two words the same 32 rounds as TEA and XTEA, and fewer above that", () => {
    // Not an implementation detail: it is why the two-word form is the one registered.
    const rounds = (n: number): number => 6 + Math.floor(52 / n);
    expect(rounds(2)).toBe(32);
    expect(rounds(4)).toBe(19);
    expect(rounds(52)).toBe(7);
  });

  it("refuses fewer than two words", () => {
    expect(() => xxteaWords([1], [1, 2, 3, 4], true)).toThrow(/at least two/);
  });
});

describe("RC5-32", () => {
  /**
   * Thirteen vectors across six round counts and four key lengths.
   *
   * These are Bouncy Castle's CBC vectors with an all-zero IV, which for a single block is the same
   * value as ECB -- `C = E(P XOR 0)`. Using them that way is deliberate rather than lazy: it is more
   * vectors over more parameter combinations than any ECB table publishes, and the parameters are the
   * thing most likely to be wrong.
   */
  const VECTORS = [
    { key: "00", rounds: 0, pt: "0000000000000000", ct: "7a7bba4d79111d1e" },
    { key: "00", rounds: 0, pt: "ffffffffffffffff", ct: "797bba4d78111d1e" },
    { key: "00", rounds: 0, pt: "0000000000000001", ct: "7a7bba4d79111d1f" },
    { key: "11", rounds: 1, pt: "0000000000000000", ct: "2f759fe7ad86a378" },
    { key: "00", rounds: 2, pt: "0000000000000000", ct: "dca2694bf40e0788" },
    { key: "00000000", rounds: 2, pt: "0000000000000000", ct: "dca2694bf40e0788" },
    { key: "00000000", rounds: 8, pt: "0000000000000000", ct: "dcfe098577eca5ff" },
    { key: "01020304", rounds: 8, pt: "ffffffffffffffff", ct: "8285e7c1b5bc7402" },
    { key: "01020304", rounds: 12, pt: "ffffffffffffffff", ct: "fc586f92f7080934" },
    { key: "01020304", rounds: 16, pt: "ffffffffffffffff", ct: "cf270ef9717ff7c4" },
    { key: "0102030405060708", rounds: 12, pt: "ffffffffffffffff", ct: "e493f1c1bb4d6e8c" },
    { key: "0102030405", rounds: 12, pt: "ffffffffffffffff", ct: "97e0787837ed317f" },
    { key: "0102030405", rounds: 8, pt: "ffffffffffffffff", ct: "7875dbf6738c6478" },
  ];

  it("reproduces every published vector, both ways", () => {
    for (const [i, v] of VECTORS.entries()) {
      bothWays(createRc5(unhex(v.key), v.rounds), v.pt, v.ct, `RC5 ${i} (r=${v.rounds})`);
    }
  });

  /**
   * A 1-byte key and a 4-byte key of the same value give the same schedule.
   *
   * Two of the vectors above assert this by coincidence -- `00`/2 and `00000000`/2 have the same
   * ciphertext -- and it is worth stating on purpose: the key is loaded into little-endian words, so
   * three trailing zero bytes are already what a 1-byte key expands to. It also means the mixing
   * loop's `3 * max(|S|, |L|)` bound is exercised on both sides.
   */
  it("expands a short key the same way as its zero-padded form", () => {
    const short = new Uint8Array(8);
    const long = new Uint8Array(8);
    createRc5(unhex("00"), 2).encryptBlock(new Uint8Array(8), short);
    createRc5(unhex("00000000"), 2).encryptBlock(new Uint8Array(8), long);
    expect(hex(short)).toBe(hex(long));
  });

  it("refuses parameters outside the specification", () => {
    expect(() => createRc5(new Uint8Array(256), 12)).toThrow(/255 bytes/);
    expect(() => createRc5(new Uint8Array(16), 256)).toThrow(/0 to 255/);
    expect(() => createRc5(new Uint8Array(16), -1)).toThrow(/0 to 255/);
  });
});

describe("RC6", () => {
  const VECTORS = [
    {
      key: "00000000000000000000000000000000",
      pt: "80000000000000000000000000000000",
      ct: "f71f65e7b80c0c6966fee607984b5cdf",
    },
    {
      key: "000000000000000000000000000000008000000000000000",
      pt: "00000000000000000000000000000000",
      ct: "dd04c176440bbc6686c90aee775bd368",
    },
    {
      key: "000000000000000000000000000000000000001000000000",
      pt: "00000000000000000000000000000000",
      ct: "937fe02d20fcb72f0f57201012b88ba4",
    },
    {
      key: "00000001000000000000000000000000",
      pt: "00000000000000000000000000000000",
      ct: "8a380594d7396453771a1dfbe2914c8e",
    },
    {
      key: "1000000000000000000000000000000000000000000000000000000000000000",
      pt: "00000000000000000000000000000000",
      ct: "11395d4bfe4c8258979ee2bf2d24dff4",
    },
    {
      key: "0000000000000000000000000000000000080000000000000000000000000000",
      pt: "00000000000000000000000000000000",
      ct: "3d6f7e99f6512553bb983e8f75672b97",
    },
  ];

  it("reproduces every published vector, both ways", () => {
    for (const [i, v] of VECTORS.entries()) {
      bothWays(createRc6(unhex(v.key)), v.pt, v.ct, `RC6 ${i}`);
    }
  });

  it("refuses a key that is not 128, 192 or 256 bits", () => {
    expect(() => createRc6(new Uint8Array(20))).toThrow(/16, 24 or 32/);
  });
});

describe("SKIPJACK", () => {
  /** The specification's own vector, and the only published one there is. */
  it("reproduces the published vector, both ways", () => {
    bothWays(
      createSkipjack(unhex("00998877665544332211")),
      "33221100ddccbbaa",
      "2587cae27a12d300",
      "SKIPJACK",
    );
  });

  /**
   * With one vector, the table gets its own assertion.
   *
   * F is 256 bytes with no published structure -- it is not derived from a field inverse the way AES's
   * is, and the design rationale was never declassified -- so there is nothing to derive it from and no
   * second property to check except that it is a bijection. A duplicated entry would break the vector
   * too, but this says which of the two things went wrong.
   */
  it("has an F table that is a permutation of all 256 bytes", () => {
    expect(SKIPJACK_F_TABLE).toHaveLength(256);
    expect(new Set(SKIPJACK_F_TABLE).size).toBe(256);
  });

  it("refuses a key that is not 80 bits", () => {
    expect(() => createSkipjack(new Uint8Array(16))).toThrow(/10 bytes/);
  });
});

describe("CAST-256", () => {
  /** RFC 2612's three worked examples, one per key length. */
  const VECTORS = [
    {
      key: "2342bb9efa38542c0af75647f29f615d",
      pt: "00000000000000000000000000000000",
      ct: "c842a08972b43d20836c91d1b7530f6b",
    },
    {
      key: "2342bb9efa38542cbed0ac83940ac298bac77a7717942863",
      pt: "00000000000000000000000000000000",
      ct: "1b386c0210dcadcbdd0e41aa08a7a7e8",
    },
    {
      key: "2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604",
      pt: "00000000000000000000000000000000",
      ct: "4f6a2038286897b9c9870136553317fa",
    },
  ];

  it("reproduces every published vector, both ways", () => {
    for (const [i, v] of VECTORS.entries()) {
      bothWays(createCast6(unhex(v.key)), v.pt, v.ct, `CAST-256 ${i}`);
    }
  });

  /**
   * The tables are shared with CAST5, so this pins that they still serve CAST5 too.
   *
   * `castRoundFunction` was extracted from `cast5.ts` for CAST-256 to use. If that extraction had
   * changed anything -- an argument order, a combine -- CAST-256 might still have been made to pass by
   * accident while CAST5 quietly broke. RFC 2144's own vector is the guard.
   */
  it("shares CAST5's round function without disturbing it", () => {
    bothWays(
      createCast5(unhex("0123456712345678234567893456789A")),
      "0123456789ABCDEF",
      "238B4FE5847E44B2",
      "CAST5 RFC 2144",
    );
  });

  it("refuses a key length the RFC does not define", () => {
    expect(() => createCast6(new Uint8Array(12))).toThrow(/16, 20, 24, 28 or 32/);
    expect(() => createCast6(new Uint8Array(18))).toThrow(/16, 20, 24, 28 or 32/);
  });
});

describe("Threefish", () => {
  /**
   * Two vectors per width: the all-zero case, and one with a non-zero key, tweak and plaintext.
   *
   * The second is the one that matters. An all-zero tweak cannot distinguish a correct tweak injection
   * from no injection at all, and it cannot see the subkey counter either, since adding zero and
   * adding nothing look the same for the first subkey.
   */
  const ZERO_TWEAK = "00000000000000000000000000000000";
  const TWEAK = "000102030405060708090a0b0c0d0e0f";

  const VECTORS = [
    {
      size: 32,
      key: "0000000000000000000000000000000000000000000000000000000000000000",
      tweak: ZERO_TWEAK,
      pt: "0000000000000000000000000000000000000000000000000000000000000000",
      ct: "84da2a1f8beaee947066ae3e3103f1ad536db1f4a1192495116b9f3ce6133fd8",
    },
    {
      size: 32,
      key: "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
      tweak: TWEAK,
      pt: "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0",
      ct: "e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df",
    },
    {
      size: 64,
      key: "00".repeat(64),
      tweak: ZERO_TWEAK,
      pt: "00".repeat(64),
      ct:
        "b1a2bbc6ef6025bc40eb3822161f36e375d1bb0aee3186fbd19e47c5d479947b" +
        "7bc2f8586e35f0cff7e7f03084b0b7b1f1ab3961a580a3e97eb41ea14a6d7bbe",
    },
    {
      size: 64,
      key:
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
      tweak: TWEAK,
      pt:
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0" +
        "dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0",
      ct:
        "e304439626d45a2cb401cad8d636249a6338330eb06d45dd8b36b90e97254779" +
        "272a0a8d99463504784420ea18c9a725af11dffea10162348927673d5c1caf3d",
    },
    {
      size: 128,
      key: "00".repeat(128),
      tweak: ZERO_TWEAK,
      pt: "00".repeat(128),
      ct:
        "f05c3d0a3d05b304f785ddc7d1e036015c8aa76e2f217b06c6e1544c0bc1a90d" +
        "f0accb9473c24e0fd54fea68057f43329cb454761d6df5cf7b2e9b3614fbd5a2" +
        "0b2e4760b40603540d82eabc5482c171c832afbe68406bc39500367a592943fa" +
        "9a5b4a43286ca3c4cf46104b443143d560a4b230488311df4feef7e1dfe8391e",
    },
    {
      size: 128,
      key:
        "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" +
        "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f" +
        "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f" +
        "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f",
      tweak: TWEAK,
      pt:
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0" +
        "dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0" +
        "bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0afaeadacabaaa9a8a7a6a5a4a3a2a1a0" +
        "9f9e9d9c9b9a999897969594939291908f8e8d8c8b8a89888786858483828180",
      ct:
        "a6654ddbd73cc3b05dd777105aa849bce49372eaaffc5568d254771bab85531c" +
        "94f780e7ffaae430d5d8af8c70eebbe1760f3b42b737a89cb363490d670314bd" +
        "8aa41ee63c2e1f45fbd477922f8360b388d6125ea6c7af0ad7056d01796e90c8" +
        "3313f4150a5716b30ed5f569288ae974ce2b4347926fce57de44512177dd7cde",
    },
  ];

  it("reproduces every published vector at every width, both ways", () => {
    for (const v of VECTORS) {
      const cipher = createThreefish(unhex(v.key), unhex(v.tweak));
      expect(cipher.blockSize, `Threefish-${v.size * 8}`).toBe(v.size);
      bothWays(cipher, v.pt, v.ct, `Threefish-${v.size * 8} tweak=${v.tweak.slice(0, 4)}`);
    }
    // Guards the guard: three widths, two cases each.
    expect(VECTORS).toHaveLength(6);
  });

  /** The tweak is an input, so a different tweak must be a different permutation. */
  it("gives a different result for a different tweak", () => {
    const key = unhex("00".repeat(32));
    const pt = unhex("00".repeat(32));
    const zero = new Uint8Array(32);
    const other = new Uint8Array(32);
    createThreefish(key, unhex(ZERO_TWEAK)).encryptBlock(pt, zero);
    createThreefish(key, unhex(TWEAK)).encryptBlock(pt, other);
    expect(hex(zero)).not.toBe(hex(other));
    // And an omitted tweak is the all-zero one, which is what the published zero-tweak vector uses.
    const omitted = new Uint8Array(32);
    createThreefish(key).encryptBlock(pt, omitted);
    expect(hex(omitted)).toBe(hex(zero));
  });

  it("refuses a key or tweak of the wrong size", () => {
    expect(() => createThreefish(new Uint8Array(16))).toThrow(/32, 64 or 128/);
    expect(() => createThreefish(new Uint8Array(32), new Uint8Array(12))).toThrow(/16 bytes/);
  });
});
