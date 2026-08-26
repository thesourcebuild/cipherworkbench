/**
 * Deoxys-II-256-128 -- a CAESAR winner, and the first tweakable-block-cipher AEAD in this repo.
 *
 * No oracle. OpenSSL never implemented Deoxys and nothing in this tree has it, so what stands behind
 * it is two sets of vectors that are different *kinds* of evidence rather than two of the same kind:
 *
 *  - **The designers' own eight**, from `Deoxys-II-256-128-official-20190608.json`. They walk the grid
 *    that matters -- each region present or absent, ending on a block boundary or one byte past it --
 *    which is where a two-region, four-domain-prefix mode goes wrong.
 *  - **An independent implementation's gapless sweep**, 0 to 255 bytes, from Oasis's Go code. Two
 *    implementations sharing no line of source agreeing at every length is what covers the lengths the
 *    official eight do not name, and it is the only thing here that could catch a padding rule that
 *    happened to be right at 32 and 33.
 *
 * Three properties are asserted rather than transcribed, because each is a place a self-consistent
 * implementation would still be wrong: the round constants are powers of `x` in AES's field, the round
 * function *is* AES's (so the S-box and matrix are the ones four other vector sets already pin), and
 * the tweak is what separates the two directions rather than the key.
 */
import { describe, expect, it } from "vitest";
import {
  AES_SBOX,
  aesRound,
  deoxysBcEncrypt,
  deoxysDeriveKeys,
  deoxysIIOpen,
  deoxysIISeal,
} from "@ocs/algos";
import { DEOXYS_OFFICIAL, DEOXYS_SWEEP, DEOXYS_SWEEP_INPUT } from "./deoxys-vectors";

const unhex = (text: string): Uint8Array =>
  text === "" ? new Uint8Array(0) : Uint8Array.from(text.match(/../g)!.map((p) => parseInt(p, 16)));
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

describe("Deoxys-II-256-128", () => {
  it("reproduces all eight of the designers' vectors", () => {
    expect(DEOXYS_OFFICIAL).toHaveLength(8);
    for (const v of DEOXYS_OFFICIAL) {
      const sealed = deoxysIISeal(unhex(v.key), unhex(v.nonce), unhex(v.message), unhex(v.ad));
      expect(hex(sealed), `${v.name} seal`).toBe(v.sealed);
      const opened = deoxysIIOpen(unhex(v.key), unhex(v.nonce), unhex(v.sealed), unhex(v.ad));
      expect(hex(opened), `${v.name} open`).toBe(v.message);
    }
  });

  it("covers the block boundary in both regions, which is what those eight are for", () => {
    /**
     * Stated as an assertion rather than left in a comment: if somebody trims the fixture, the reason
     * the eight were worth keeping should fail rather than quietly go away. A region of exactly 32
     * bytes takes two full blocks and no padding block; 33 takes two plus a padded third under a
     * different domain prefix, and getting that backwards is right for fifteen lengths in sixteen.
     */
    const adLengths = DEOXYS_OFFICIAL.map((v) => v.ad.length / 2);
    const msgLengths = DEOXYS_OFFICIAL.map((v) => v.message.length / 2);
    for (const n of [0, 32, 33]) {
      expect(adLengths, `associated data of ${n}`).toContain(n);
      expect(msgLengths, `message of ${n}`).toContain(n);
    }
  });

  it("agrees with an independent implementation at every length from 0 to 255", () => {
    const key = unhex(DEOXYS_SWEEP_INPUT.key);
    const nonce = unhex(DEOXYS_SWEEP_INPUT.nonce);
    const message = unhex(DEOXYS_SWEEP_INPUT.message);
    const ad = unhex(DEOXYS_SWEEP_INPUT.ad);
    expect(DEOXYS_SWEEP).toHaveLength(256);

    // Collected rather than asserted per row: 256 `expect` calls inside a loop is most of the runtime.
    const wrong: number[] = [];
    for (let n = 0; n < 256; n++) {
      const sealed = deoxysIISeal(key, nonce, message.subarray(0, n), ad.subarray(0, n));
      if (hex(sealed) !== DEOXYS_SWEEP[n]) wrong.push(n);
    }
    expect(wrong).toEqual([]);
  });

  it("round-trips, and refuses a tag that has been touched", () => {
    const key = unhex(DEOXYS_SWEEP_INPUT.key);
    const nonce = unhex(DEOXYS_SWEEP_INPUT.nonce);
    const message = Uint8Array.from({ length: 100 }, (_, i) => (i * 5 + 1) & 0xff);
    const ad = Uint8Array.from({ length: 20 }, (_, i) => i);

    const sealed = deoxysIISeal(key, nonce, message, ad);
    expect(hex(deoxysIIOpen(key, nonce, sealed, ad))).toBe(hex(message));

    // Every byte of the tag, because the comparison is over all sixteen and a loop bound could be short.
    for (let i = 0; i < 16; i++) {
      const damaged = Uint8Array.from(sealed);
      damaged[sealed.length - 16 + i] = damaged[sealed.length - 16 + i]! ^ 1;
      expect(() => deoxysIIOpen(key, nonce, damaged, ad), `tag byte ${i}`).toThrow(/does not match/);
    }
    // And a changed associated data byte, which never reaches the ciphertext at all.
    const otherAd = Uint8Array.from(ad);
    otherAd[0] = otherAd[0]! ^ 1;
    expect(() => deoxysIIOpen(key, nonce, sealed, otherAd)).toThrow(/does not match/);
  });

  it("is nonce-misuse resistant in the way the mode claims", () => {
    /**
     * Two different messages under one key and nonce must not share a keystream. That is the property
     * the two-pass design exists for, and it is testable without a published value: under a counter
     * mode the XOR of two ciphertexts would be the XOR of the two plaintexts, and here it is not.
     */
    const key = unhex(DEOXYS_SWEEP_INPUT.key);
    const nonce = unhex(DEOXYS_SWEEP_INPUT.nonce);
    const a = new Uint8Array(32).fill(0xaa);
    const b = new Uint8Array(32).fill(0xbb);
    const ca = deoxysIISeal(key, nonce, a).subarray(0, 32);
    const cb = deoxysIISeal(key, nonce, b).subarray(0, 32);

    const ctXor = Uint8Array.from(ca, (v, i) => v ^ cb[i]!);
    const ptXor = Uint8Array.from(a, (v, i) => v ^ b[i]!);
    expect(hex(ctXor)).not.toBe(hex(ptXor));

    // And the same message twice does give the same output -- the one thing a repeated nonce leaks.
    expect(hex(deoxysIISeal(key, nonce, a))).toBe(hex(deoxysIISeal(key, nonce, a)));
  });

  it("derives its round constants from AES's field, and its rounds are AES's rounds", () => {
    /**
     * Both halves of one check, because an all-zero key makes the tweakey schedule transparent: both
     * LFSRs fix zero, so every subtweakey *is* that round's constant -- `1, 2, 4, 8` then `RCON[i]`
     * four times then eight zeros. So the seventeen constants can be read straight out of the public
     * API and compared against `xtime` iterated from the 0x2f seed, and the block cipher can be
     * compared against a sixteen-round `aesRound` chain built from them.
     *
     * That second comparison is the one that matters most. It pins the round *count*, and that the
     * last round mixes columns -- which AES's does not, and which no round trip could see -- and it
     * makes the S-box behind Deoxys-II the one AES's own vectors, ARIA's three appendix vectors,
     * SHAvite-3's KATs, Groestl's KATs and ECHO's KATs all already check. A failure in the vectors
     * above therefore points at the tweakey schedule rather than at a table.
     */
    expect(AES_SBOX[0]).toBe(0x63);
    expect(AES_SBOX[1]).toBe(0x7c);

    const xtime = (x: number): number => ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff;
    const constants: number[] = [];
    for (let i = 0, v = 0x2f; i <= 16; i++, v = xtime(v)) constants.push(v);

    const derived = deoxysDeriveKeys(new Uint8Array(32));
    expect(derived).toHaveLength(17);
    derived.forEach((round, i) => {
      const expected = new Uint8Array(16);
      expected.set([1, 2, 4, 8]);
      expected.fill(constants[i]!, 4, 8);
      expect(hex(round), `round constant ${i}`).toBe(hex(expected));
    });

    // Sixteen rounds over the same subtweakeys, written out here rather than imported.
    const input = Uint8Array.from({ length: 16 }, (_, i) => i * 17);
    let a = Uint8Array.from(input, (v, i) => v ^ derived[0]![i]!);
    let b = new Uint8Array(16);
    for (let round = 1; round <= 16; round++) {
      aesRound(a, derived[round]!, b);
      const swap = a;
      a = b;
      b = swap;
    }
    expect(hex(deoxysBcEncrypt(derived, new Uint8Array(16), input))).toBe(hex(a));
  });

  it("separates the tag pass from the encryption pass by the tweak alone", () => {
    /**
     * The domain prefix lives in the top nibble of the tweak's first byte, so absorbing a block as
     * associated data and absorbing the same block as message must give different results. A mode that
     * dropped the prefix would still authenticate and would accept an attacker moving bytes between
     * the two regions, which no round trip can see.
     */
    const key = unhex(DEOXYS_SWEEP_INPUT.key);
    const nonce = unhex(DEOXYS_SWEEP_INPUT.nonce);
    const block = new Uint8Array(16).fill(0x5a);
    const asAd = deoxysIISeal(key, nonce, new Uint8Array(0), block);
    const asMsg = deoxysIISeal(key, nonce, block, new Uint8Array(0));
    expect(hex(asAd)).not.toBe(hex(asMsg.subarray(16)));
  });

  it("refuses a key, nonce or sealed message of the wrong length", () => {
    expect(() => deoxysIISeal(new Uint8Array(16), new Uint8Array(15), new Uint8Array(0))).toThrow(
      /exactly 32 bytes/,
    );
    expect(() => deoxysIISeal(new Uint8Array(32), new Uint8Array(16), new Uint8Array(0))).toThrow(
      /exactly 15 bytes/,
    );
    expect(() => deoxysIIOpen(new Uint8Array(32), new Uint8Array(15), new Uint8Array(15))).toThrow(
      /at least 16 bytes/,
    );
  });
});
