import { describe, expect, it } from "vitest";

import { MORUS_TAG_LEN, MORUS_VARIANTS, morusOpen, morusSeal, type MorusVariant } from "../packages/algos/src/index";
import { MORUS_VECTORS } from "./morus-vectors";

const unhex = (t: string): Uint8Array =>
  t === "" ? new Uint8Array(0) : Uint8Array.from((t.match(/../g) ?? []).map((p) => parseInt(p, 16)));
const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

/**
 * MORUS, and this file is as much about the *status* of its coverage as about the values.
 *
 * There is **no published known-answer file**. What follows is a cross-check between two independent
 * implementations of the CAESAR v2 specification: `packages/algos/src/morus.ts` is a port of the
 * designers' own `ref/encrypt.c` from the SUPERCOP tree, and the expected values come from
 * `SparkDustJoe/PyMORUS`, separately written in Python by a different author. See
 * `tests/morus-vectors.ts` for why SUPERCOP's own `checksumsmall` is not usable here.
 *
 * That is real evidence and it is not a KAT. Do not relabel it.
 */

/** The parameter set a vector belongs to, from its word width and key length. */
const variantFor = (v: (typeof MORUS_VECTORS)[number]): MorusVariant =>
  v.words === "32" ? "640-128" : v.key.length === 64 ? "1280-256" : "1280-128";

describe("MORUS", () => {
  it("agrees with PyMORUS on all 27 cross-check vectors", () => {
    expect(MORUS_VECTORS).toHaveLength(27);
    for (const [index, v] of MORUS_VECTORS.entries()) {
      const variant = variantFor(v);
      const { ciphertext, tag } = morusSeal(
        variant,
        unhex(v.key),
        unhex(v.nonce),
        unhex(v.associatedData),
        unhex(v.plaintext),
      );
      expect(hex(ciphertext), `case ${index} ${variant} ciphertext`).toBe(v.ciphertext);
      expect(hex(tag), `case ${index} ${variant} tag`).toBe(v.tag);
    }
  });

  it("covers all three parameter sets", () => {
    const covered = new Set(MORUS_VECTORS.map(variantFor));
    expect([...covered].sort()).toEqual(["1280-128", "1280-256", "640-128"]);
    expect(Object.keys(MORUS_VARIANTS).sort()).toEqual(["1280-128", "1280-256", "640-128"]);
  });

  it("opens every vector it sealed, and rejects a flipped tag bit", () => {
    for (const v of MORUS_VECTORS) {
      const variant = variantFor(v);
      const key = unhex(v.key);
      const nonce = unhex(v.nonce);
      const ad = unhex(v.associatedData);
      const opened = morusOpen(variant, key, nonce, ad, unhex(v.ciphertext), unhex(v.tag));
      expect(opened, `${variant} must open`).not.toBeNull();
      expect(hex(opened!), variant).toBe(v.plaintext);
      const bad = unhex(v.tag);
      bad[0] = bad[0]! ^ 1;
      expect(morusOpen(variant, key, nonce, ad, unhex(v.ciphertext), bad), variant).toBeNull();
    }
  });

  /**
   * **MORUS-1280-128 with key K is exactly MORUS-1280-256 with key K||K.**
   *
   * The 128-bit variant fills its 256-bit register by *repeating* the key rather than zero-extending it,
   * so the two are the same computation whenever the longer key happens to be a doubled short one. This
   * is a property of the design, and it is pinned because it looks exactly like two parameter sets wired
   * to one implementation -- it broke the AEAD uniqueness test in `tests/cipher.test.ts`, which was
   * building an all-`0x11` key and therefore hitting it by accident.
   *
   * The second half of the test is the part that makes it a property rather than a bug: with a key whose
   * halves differ, the two sets disagree.
   */
  it("makes 1280-128 equal 1280-256 under a doubled key, and differ otherwise", () => {
    const nonce = new Uint8Array(16).fill(0x22);
    const message = new Uint8Array(40).fill(0x5a);
    const short = new Uint8Array(16);
    for (let i = 0; i < 16; i++) short[i] = (i * 11 + 1) & 0xff;

    const doubled = new Uint8Array(32);
    doubled.set(short);
    doubled.set(short, 16);
    const a = morusSeal("1280-128", short, nonce, new Uint8Array(0), message);
    const b = morusSeal("1280-256", doubled, nonce, new Uint8Array(0), message);
    expect(hex(a.ciphertext)).toBe(hex(b.ciphertext));
    expect(hex(a.tag)).toBe(hex(b.tag));

    // A 256-bit key whose halves differ is not reachable from any 128-bit key.
    const uneven = Uint8Array.from(doubled);
    uneven[31] = uneven[31]! ^ 1;
    const c = morusSeal("1280-256", uneven, nonce, new Uint8Array(0), message);
    expect(hex(c.tag)).not.toBe(hex(a.tag));
  });

  /**
   * 640-128 and 1280-128 take the same key, nonce and tag lengths and are different ciphers.
   *
   * The Kalyna hazard: a binding that inferred the set from the key length would produce a plausible
   * answer for one and a wrong one for the other, with the right number of output bytes in both.
   */
  it("gives 640-128 and 1280-128 the same lengths and different output", () => {
    expect(MORUS_VARIANTS["640-128"].keyLen).toBe(MORUS_VARIANTS["1280-128"].keyLen);
    expect(MORUS_VARIANTS["640-128"].nonceLen).toBe(MORUS_VARIANTS["1280-128"].nonceLen);
    // And the blocks differ, which is what makes them different functions.
    expect(MORUS_VARIANTS["640-128"].blockLen).toBe(16);
    expect(MORUS_VARIANTS["1280-128"].blockLen).toBe(32);
    const key = new Uint8Array(16).fill(0x33);
    const nonce = new Uint8Array(16).fill(0x44);
    const message = new Uint8Array(48).fill(0x55);
    const a = morusSeal("640-128", key, nonce, new Uint8Array(0), message);
    const b = morusSeal("1280-128", key, nonce, new Uint8Array(0), message);
    expect(hex(a.tag)).not.toBe(hex(b.tag));
  });

  it("round-trips at every length across both block sizes", () => {
    for (const variant of Object.keys(MORUS_VARIANTS) as MorusVariant[]) {
      const params = MORUS_VARIANTS[variant];
      const key = new Uint8Array(params.keyLen).fill(0x77);
      const nonce = new Uint8Array(params.nonceLen).fill(0x88);
      for (const length of [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65]) {
        const message = new Uint8Array(length);
        for (let i = 0; i < length; i++) message[i] = (i * 13 + 5) & 0xff;
        const ad = new Uint8Array(length % 7);
        const { ciphertext, tag } = morusSeal(variant, key, nonce, ad, message);
        expect(ciphertext, `${variant} at ${length}`).toHaveLength(length);
        expect(tag).toHaveLength(MORUS_TAG_LEN);
        const opened = morusOpen(variant, key, nonce, ad, ciphertext, tag);
        expect(hex(opened ?? new Uint8Array(0)), `${variant} at ${length}`).toBe(hex(message));
      }
    }
  });

  it("refuses the wrong key or nonce length, naming the set", () => {
    expect(() => morusSeal("640-128", new Uint8Array(32), new Uint8Array(16), new Uint8Array(0), new Uint8Array(0)))
      .toThrow(/MORUS-640-128's key is exactly 16 bytes/);
    expect(() => morusSeal("1280-256", new Uint8Array(16), new Uint8Array(16), new Uint8Array(0), new Uint8Array(0)))
      .toThrow(/MORUS-1280-256's key is exactly 32 bytes/);
    expect(() => morusSeal("640-128", new Uint8Array(16), new Uint8Array(12), new Uint8Array(0), new Uint8Array(0)))
      .toThrow(/nonce is exactly 16 bytes/);
  });
});
