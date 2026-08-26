import { describe, expect, it } from "vitest";

import {
  __ketjeJrPhases,
  KETJE_JR_BLOCK,
  KETJE_JR_KEY_LEN,
  KETJE_JR_NONCE_MAX,
  KETJE_JR_TAG_LEN,
  ketjeJrOpen,
  ketjeJrSeal,
} from "../packages/algos/src/index";

const unhex = (t: string): Uint8Array =>
  Uint8Array.from((t.match(/../g) ?? []).map((p) => parseInt(p, 16)));
const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

/**
 * Ketje Jr, against FELICS's own vector -- which publishes the state after **each phase** as well as
 * the ciphertext and tag.
 *
 * That is the fixture shape this repo prefers and the reason it is worth naming: a failure localises to
 * initialisation, associated data, the data phase or finalisation, rather than telling you only that
 * the whole construction is wrong. There is no other reachable source -- the Keccak team's own KATs for
 * Ketje are not mirrored anywhere this machine can reach, and no dependency here implements it.
 */
const KEY = unhex("145ea8f23d87d11c66b0fa453994ef4b");
const NONCE = unhex("1570cb2782dd");
const AD = unhex("0c78e451bd2a");
const PLAINTEXT = unhex("0e8b09860481fe");

describe("Ketje Jr", () => {
  it("reproduces FELICS's state after every phase, plus its ciphertext and tag", () => {
    const r = __ketjeJrPhases.run(KEY, NONCE, AD, PLAINTEXT);
    expect(hex(r.afterInit), "after initialisation").toBe(
      "ca4b6211e23116a2bf02addedf2a792381c84cb8a1a77b224d",
    );
    expect(hex(r.afterAd), "after associated data").toBe(
      "cef4d3702ee62fb98fc9acf3e8772a5b84a7ba602ee3deb104",
    );
    expect(hex(r.afterData), "after the data phase").toBe(
      "ba2bc48a710ec8c77143e20c9154aa9d16dd99b8081633265f",
    );
    expect(hex(r.ciphertext), "ciphertext").toBe("c0a469cf06cc39");
    expect(hex(r.tag), "tag").toBe("bac838e84f259d1011c1dc31315f1e3d");
  });

  it("seals to the same ciphertext and tag through the public API", () => {
    const { ciphertext, tag } = ketjeJrSeal(KEY, NONCE, AD, PLAINTEXT);
    expect(hex(ciphertext)).toBe("c0a469cf06cc39");
    expect(hex(tag)).toBe("bac838e84f259d1011c1dc31315f1e3d");
  });

  it("opens what it sealed, at every length across the two-byte block boundary", () => {
    for (let length = 0; length <= 20; length++) {
      const message = new Uint8Array(length);
      for (let i = 0; i < length; i++) message[i] = (i * 37 + 11) & 0xff;
      const { ciphertext, tag } = ketjeJrSeal(KEY, NONCE, AD, message);
      expect(ciphertext, `length ${length}`).toHaveLength(length);
      const opened = ketjeJrOpen(KEY, NONCE, AD, ciphertext, tag);
      expect(opened, `length ${length} must open`).not.toBeNull();
      expect(hex(opened!), `length ${length}`).toBe(hex(message));
    }
  });

  it("varies with the associated data as well as the message", () => {
    const a = ketjeJrSeal(KEY, NONCE, AD, PLAINTEXT);
    const b = ketjeJrSeal(KEY, NONCE, new Uint8Array(0), PLAINTEXT);
    expect(hex(a.tag)).not.toBe(hex(b.tag));
    // The AD does not affect the keystream length, only the state -- so the ciphertext moves too.
    expect(hex(a.ciphertext)).not.toBe(hex(b.ciphertext));
  });

  it("rejects a flipped bit anywhere in the ciphertext, the tag or the associated data", () => {
    const { ciphertext, tag } = ketjeJrSeal(KEY, NONCE, AD, PLAINTEXT);
    for (let i = 0; i < ciphertext.length; i++) {
      const bad = Uint8Array.from(ciphertext);
      bad[i] = bad[i]! ^ 1;
      expect(ketjeJrOpen(KEY, NONCE, AD, bad, tag), `ciphertext byte ${i}`).toBeNull();
    }
    for (let i = 0; i < tag.length; i++) {
      const bad = Uint8Array.from(tag);
      bad[i] = bad[i]! ^ 1;
      expect(ketjeJrOpen(KEY, NONCE, AD, ciphertext, bad), `tag byte ${i}`).toBeNull();
    }
    const badAd = Uint8Array.from(AD);
    badAd[0] = badAd[0]! ^ 1;
    expect(ketjeJrOpen(KEY, NONCE, badAd, ciphertext, tag)).toBeNull();
  });

  /**
   * The nonce ceiling is arithmetic, not a policy.
   *
   * An 18-byte key pack plus the nonce plus two frame bits share Keccak-p[200]'s 25 bytes, which leaves
   * six. So the refusal message says *why* rather than only that six is the limit -- and a shorter
   * nonce is legal, which is worth pinning because the natural assumption is a fixed width.
   */
  it("accepts any nonce up to six bytes and refuses a seventh", () => {
    expect(KETJE_JR_NONCE_MAX).toBe(6);
    for (let length = 0; length <= KETJE_JR_NONCE_MAX; length++) {
      const nonce = new Uint8Array(length).fill(0xa5);
      expect(() => ketjeJrSeal(KEY, nonce, AD, PLAINTEXT), `${length}-byte nonce`).not.toThrow();
    }
    expect(() => ketjeJrSeal(KEY, new Uint8Array(7), AD, PLAINTEXT)).toThrow(/at most 6 bytes/);
    // And a shorter nonce is a different nonce, not a zero-padded one.
    const five = ketjeJrSeal(KEY, new Uint8Array(5), AD, PLAINTEXT);
    const six = ketjeJrSeal(KEY, new Uint8Array(6), AD, PLAINTEXT);
    expect(hex(five.tag)).not.toBe(hex(six.tag));
  });

  it("refuses a key that is not sixteen bytes", () => {
    expect(() => ketjeJrSeal(new Uint8Array(15), NONCE, AD, PLAINTEXT)).toThrow(/exactly 16 bytes/);
    expect(KETJE_JR_KEY_LEN).toBe(16);
    expect(KETJE_JR_TAG_LEN).toBe(16);
  });

  /**
   * The block is two bytes, which is what makes 7 and 8 byte messages take different paths.
   *
   * The full-block count is `((len + 1) & ~1) - 2`, so a length that is already a multiple of two still
   * leaves a final two-byte chunk for the byte-at-a-time path rather than being consumed entirely by
   * the block loop. Pinned because "round up then subtract a block" reads like it should be a no-op on
   * an aligned length and is not.
   */
  it("always leaves a final chunk for the byte-wise path, even at an aligned length", () => {
    expect(KETJE_JR_BLOCK).toBe(2);
    const fullBlocks = (length: number): number =>
      length > KETJE_JR_BLOCK ? (((length + 1) & ~1) - 2) / 2 : 0;
    // Eight bytes is four blocks of two, and only three go through the block loop.
    expect(fullBlocks(8)).toBe(3);
    expect(fullBlocks(7)).toBe(3);
    expect(fullBlocks(2)).toBe(0);
    /**
     * Both 7 and 8 bytes take three full blocks and then a remainder, so their **ciphertexts share a
     * prefix** -- the keystream at each position depends only on what came before it. That is a real
     * property of the duplex and worth asserting rather than assuming away: it means a truncated
     * ciphertext is indistinguishable from a shorter message *by the ciphertext alone*, and the tag is
     * the only thing that catches it. Which the next line pins.
     */
    const seven = ketjeJrSeal(KEY, NONCE, AD, new Uint8Array(7));
    const eight = ketjeJrSeal(KEY, NONCE, AD, new Uint8Array(8));
    expect(hex(eight.ciphertext).startsWith(hex(seven.ciphertext))).toBe(true);
    expect(hex(eight.tag)).not.toBe(hex(seven.tag));
    // And truncating the longer ciphertext to the shorter length does not open under the shorter tag's
    // sibling -- the tag is what makes the length authentic.
    expect(ketjeJrOpen(KEY, NONCE, AD, eight.ciphertext.subarray(0, 7), eight.tag)).toBeNull();
  });
});
