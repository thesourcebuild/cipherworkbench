/**
 * HAVAL, Snefru and GOST R 34.11-94, against php-src's dedicated tests for each.
 *
 * All three are here because PHP's `hash_algos()` lists them and none has a second implementation in
 * this project's dependency tree. PHP is therefore the reference, and these are its own published
 * expectations: `haval.phpt` covers all fifteen HAVAL variants at three messages, `snefru.phpt` five
 * messages either side of the 32-byte block, and `gost.phpt` six messages under each of the two
 * parameter sets.
 *
 * `tests/php-parity.test.ts` additionally checks all three against PHP on two further messages, along
 * with every other algorithm PHP offers. What this file adds is the block-boundary spread and the
 * structural properties that pin the parts of each design most easily got wrong.
 */
import { describe, expect, it } from "vitest";
import {
  createGost,
  createHaval,
  createSnefru,
  gost,
  haval,
  HAVAL_OUTPUT_LENS,
  HAVAL_PASSES,
  snefru,
} from "@ocs/algos";

const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const ascii = (text: string) => new TextEncoder().encode(text);

/** php-src ext/hash/tests/haval.phpt, keyed by `bits,passes` exactly as PHP names them. */
const HAVAL_EMPTY: Record<string, string> = {
  "128,3": "c68f39913f901f3ddf44c707357a7d70",
  "160,3": "d353c3ae22a25401d257643836d7231a9a95f953",
  "192,3": "e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e",
  "224,3": "c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d",
  "256,3": "4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17",
  "128,4": "ee6bbf4d6a46a679b3a856c88538bb98",
  "160,4": "1d33aae1be4146dbaaca0b6e70d7a11f10801525",
  "192,4": "4a8372945afa55c7dead800311272523ca19d42ea47b72da",
  "224,4": "3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e",
  "256,4": "c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b",
  "128,5": "184b8482a0c050dca54b59c7f05bf5dd",
  "160,5": "255158cfc1eed1a7be7c55ddd64d9790415b933b",
  "192,5": "4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85",
  "224,5": "4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e",
  "256,5": "be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330",
};

/** The same file's `"abc"` block. */
const HAVAL_ABC: Record<string, string> = {
  "128,3": "9e40ed883fb63e985d299b40cda2b8f2",
  "160,3": "b21e876c4d391e2a897661149d83576b5530a089",
  "192,3": "a7b14c9ef3092319b0e75e3b20b957d180bf20745629e8de",
  "224,3": "5bc955220ba2346a948d2848eca37bdd5eca6ecca7b594bd32923fab",
  "256,3": "8699f1e3384d05b2a84b032693e2b6f46df85a13a50d93808d6874bb8fb9e86c",
  "128,4": "6f2132867c9648419adcd5013e532fa2",
  "160,4": "77aca22f5b12cc09010afc9c0797308638b1cb9b",
  "192,4": "7e29881ed05c915903dd5e24a8e81cde5d910142ae66207c",
  "224,4": "124c43d2ba4884599d013e8c872bfea4c88b0b6bf6303974cbe04e68",
  "256,4": "8f409f1bb6b30c5016fdce55f652642261575bedca0b9533f32f5455459142b5",
  "128,5": "d054232fe874d9c6c6dc8e6a853519ea",
  "160,5": "ae646b04845e3351f00c5161d138940e1fa0c11c",
  "192,5": "d12091104555b00119a8d07808a3380bf9e60018915b9025",
  "224,5": "8081027a500147c512e5f1055986674d746d92af4841abeb89da64ad",
  "256,5": "976cd6254c337969e5913b158392a2921af16fca51f5601d486e0a9de01156e7",
};

const parse = (key: string): [number, number] => {
  const [bits, passes] = key.split(",").map(Number) as [number, number];
  return [passes, bits / 8];
};

describe("HAVAL", () => {
  it("matches all fifteen variants for the empty message", () => {
    expect(Object.keys(HAVAL_EMPTY)).toHaveLength(15);
    for (const [key, expected] of Object.entries(HAVAL_EMPTY)) {
      const [passes, outputLen] = parse(key);
      expect(toHex(haval(new Uint8Array(0), passes, outputLen)), key).toBe(expected);
    }
  });

  it('matches all fifteen variants for "abc"', () => {
    for (const [key, expected] of Object.entries(HAVAL_ABC)) {
      const [passes, outputLen] = parse(key);
      expect(toHex(haval(ascii("abc"), passes, outputLen)), key).toBe(expected);
    }
  });

  it("is parameterized by output length rather than truncated", () => {
    /**
     * The tailoring function, asserted where it shows. HAVAL folds the 256-bit state down with a
     * length-specific arrangement of bit fields, so no shorter digest is a prefix of a longer one --
     * and an implementation that truncated instead would still pass a single-length test.
     */
    const message = ascii("tailoring");
    const long = haval(message, 5, 32);
    for (const shorter of [16, 20, 24, 28]) {
      expect(toHex(haval(message, 5, shorter)), `${shorter} bytes`).not.toBe(
        toHex(long.subarray(0, shorter)),
      );
    }
  });

  it("is parameterized by pass count too", () => {
    // The round functions' argument permutation differs per pass count, so 4-pass HAVAL is not 5-pass
    // HAVAL stopped early. The published vectors above already prove this; this says it out loud.
    const message = ascii("passes");
    const digests = HAVAL_PASSES.map((passes) => toHex(haval(message, passes, 32)));
    expect(new Set(digests).size).toBe(3);
  });

  it("streams to the same digest as one shot, around its 128-byte block", () => {
    const message = new Uint8Array(400);
    for (let i = 0; i < message.length; i++) message[i] = (i * 31 + 17) & 0xff;

    for (const passes of HAVAL_PASSES) {
      const expected = toHex(haval(message, passes, 32));
      for (const size of [1, 7, 117, 118, 127, 128, 129, 256, 399]) {
        const h = createHaval(passes, 32);
        for (let at = 0; at < message.length; at += size) {
          h.update(message.subarray(at, Math.min(at + size, message.length)));
        }
        expect(toHex(h.digest()), `${passes} passes in ${size}s`).toBe(expected);
      }
    }
  });

  it("crosses the 118-byte padding threshold correctly", () => {
    /**
     * HAVAL pads to 118 mod 128 and then appends ten bytes. A message of exactly 118 bytes therefore
     * needs a *whole* extra block of padding, which is the branch a shorter test never reaches.
     */
    for (const length of [117, 118, 119, 246]) {
      const message = new Uint8Array(length).fill(0x61);
      const h = createHaval(5, 32);
      h.update(message.subarray(0, 50));
      h.update(message.subarray(50));
      expect(toHex(h.digest()), `${length} bytes`).toBe(toHex(haval(message, 5, 32)));
    }
  });

  it("rejects a pass count or length it does not have", () => {
    expect(HAVAL_PASSES).toEqual([3, 4, 5]);
    expect(HAVAL_OUTPUT_LENS).toEqual([16, 20, 24, 28, 32]);
    expect(() => createHaval(2, 32)).toThrow(/3, 4 or 5 passes/);
    expect(() => createHaval(5, 30)).toThrow(/16, 20, 24, 28 or 32/);
  });
});

describe("Snefru", () => {
  it("matches php-src's snefru.phpt", () => {
    // The last three cross the 32-byte block boundary at 62, 63 and 64 bytes.
    expect(toHex(snefru(new Uint8Array(0)))).toBe(
      "8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881",
    );
    expect(toHex(snefru(ascii("The quick brown fox jumps over the lazy dog")))).toBe(
      "674caa75f9d8fd2089856b95e93a4fb42fa6c8702f8980e11d97a142d76cb358",
    );
    expect(toHex(snefru(ascii("a".repeat(62))))).toBe(
      "94682bc46e5fbb8417e2f3e10ed360484048d946bb8cbb0ea4cad2700dbeaab0",
    );
    expect(toHex(snefru(ascii("a".repeat(63))))).toBe(
      "c54c602ac46383716ee7200a76c9c90a7b435bbe31d13f04e0b00a7ea5c347fa",
    );
    expect(toHex(snefru(ascii("a".repeat(64))))).toBe(
      "7a8539c59e192e8d70b1ab82aa86a1b54560d42020bda4e00ddd6d048fe3bcaa",
    );
  });

  it("distinguishes a message from the same message plus a zero byte", () => {
    // Snefru has no padding byte -- a short final block is zero-filled -- so the *only* thing that
    // separates these two is the length field folded in at the end. If that were missing, they would
    // collide, and nothing else in the suite would notice.
    expect(toHex(snefru(ascii("a")))).not.toBe(toHex(snefru(Uint8Array.of(0x61, 0))));
  });

  it("streams to the same digest as one shot", () => {
    const message = new Uint8Array(200);
    for (let i = 0; i < message.length; i++) message[i] = (i * 19 + 3) & 0xff;
    const expected = toHex(snefru(message));
    for (const size of [1, 5, 31, 32, 33, 64, 199]) {
      const h = createSnefru();
      for (let at = 0; at < message.length; at += size) {
        h.update(message.subarray(at, Math.min(at + size, message.length)));
      }
      expect(toHex(h.digest()), `chunks of ${size}`).toBe(expected);
    }
  });
});

describe("GOST R 34.11-94", () => {
  it("matches php-src's gost.phpt with the test S-boxes", () => {
    const cases: [string, string][] = [
      ["", "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d"],
      [
        "The quick brown fox jumps over the lazy dog",
        "77b7fa410c9ac58a25f49bca7d0468c9296529315eaca76bd1a10f376d1f4294",
      ],
      [
        "The quick brown fox jumps over the lazy cog",
        "a3ebc4daaab78b0be131dab5737a7f67e602670d543521319150d2e14eeec445",
      ],
      ["a".repeat(31), "03840d6348763f11e28e7b1ecc4da0cdf7f898fa555b928ef684c6c5b8f46d9f"],
      ["a".repeat(32), "fd1b746d9397e78edd311baef391450434271e02816caa37680d6d7381c79d4e"],
      ["a".repeat(33), "715e59cdc8ebde9fdf0fe2a2e811b3bf7f48209a01505e467d2cd2aa2bbb5ecf"],
    ];
    for (const [message, expected] of cases) {
      expect(toHex(gost(ascii(message), "test")), JSON.stringify(message.slice(0, 20))).toBe(
        expected,
      );
    }
  });

  it("matches php-src's gost.phpt with the CryptoPro S-boxes", () => {
    const cases: [string, string][] = [
      ["", "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0"],
      [
        "The quick brown fox jumps over the lazy dog",
        "9004294a361a508c586fe53d1f1b02746765e71b765472786e4770d565830a76",
      ],
      [
        "The quick brown fox jumps over the lazy cog",
        "a93124f5bf2c6d83c3bbf722bc55569310245ca5957541f4dbd7dfaf8137e6f2",
      ],
      ["a".repeat(31), "8978e06b0ecf54ea81ec51ca4e02bcb4eb390b3f04cb5f65ee8de195ffae591b"],
      ["a".repeat(32), "e121e3740ae94ca6d289e6d653ff31695783efff3dd960417a1098a0130fa720"],
      ["a".repeat(33), "d3e8f22d9762a148ddfc84a6043d97a608604dae7c05baee72b55f559d03dd74"],
    ];
    for (const [message, expected] of cases) {
      expect(toHex(gost(ascii(message), "crypto")), JSON.stringify(message.slice(0, 20))).toBe(
        expected,
      );
    }
  });

  it("gives unrelated digests for the two parameter sets", () => {
    // Same construction, different S-boxes. The two are not variants of one output.
    const message = ascii("parameter sets");
    expect(toHex(gost(message, "test"))).not.toBe(toHex(gost(message, "crypto")));
  });

  it("distinguishes a message from the same message plus a zero byte", () => {
    // As with Snefru: no padding byte, so only the final length compression separates these.
    expect(toHex(gost(ascii("a")))).not.toBe(toHex(gost(Uint8Array.of(0x61, 0))));
  });

  it("streams to the same digest as one shot", () => {
    const message = new Uint8Array(200);
    for (let i = 0; i < message.length; i++) message[i] = (i * 23 + 5) & 0xff;
    for (const variant of ["test", "crypto"] as const) {
      const expected = toHex(gost(message, variant));
      for (const size of [1, 5, 31, 32, 33, 64, 199]) {
        const h = createGost(variant);
        for (let at = 0; at < message.length; at += size) {
          h.update(message.subarray(at, Math.min(at + size, message.length)));
        }
        expect(toHex(h.digest()), `${variant} in ${size}s`).toBe(expected);
      }
    }
  });
});
