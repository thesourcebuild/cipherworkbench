import { describe, expect, it } from "vitest";

import {
  createGimliHash,
  createPhotonHash,
  createQuark,
  gimliHash,
  photonHash,
  QUARK_INSTANCES,
  quark,
  requireQuarkInstance,
} from "../packages/algos/src/index";
import { PRESENT_SBOX } from "../packages/algos/src/present";
import { GIMLI_VECTORS, katMessage } from "./gimli-vectors";

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (text: string): Uint8Array =>
  Uint8Array.from((text.match(/../g) ?? []).map((p) => parseInt(p, 16)));

/**
 * GIMLI-Hash, Quark and PHOTON: three lightweight sponges with no oracle anywhere in this tree.
 *
 * What stands behind each is different, and stated rather than left implied:
 *
 *  - **GIMLI** has 1,025 published known-answer records, from `rweather/lightweight-crypto`'s
 *    `GIMLI-24-HASH.txt`. That is the richest source of the three by a wide margin, and it is what
 *    settled *which* GIMLI-Hash this is -- see the note on the padding conventions below.
 *  - **Quark** has one published digest per instance -- the empty message -- but it has four
 *    instances, and the authors' own reference is where they come from. FELICS independently
 *    publishes u-Quark's post-initialisation and post-update *states*, so the permutation is pinned
 *    by two implementations that share no code.
 *  - **PHOTON** has FELICS's two vectors, which also publish per-phase intermediate states. Its
 *    tables are all derived, and each derivation is checked against the reference's own values --
 *    which is a stronger check on those than any digest could be.
 */
describe("GIMLI-Hash", () => {
  /**
   * The empty message is the row that matters most here, and it is why it is asserted on its own.
   *
   * Two GIMLI-Hash conventions are in circulation. This one pads `0x01` at the position and `0x01`
   * into byte 47 -- the top of the *capacity*. FELICS's suite writes `0x1f` at the position and
   * `0x80` at byte 15, the end of the *rate*, which is a different function: neither reproduces the
   * other's vectors at any length. The submission's is implemented; this pins it.
   */
  it("reproduces the submission's digest of the empty message", () => {
    expect(hex(gimliHash(new Uint8Array(0)))).toBe(
      "27ae20e95fbc2bf01e972b0015eea431c20fc8818f25bc6dbe66232230db352f",
    );
  });

  it("does not agree with FELICS's variant convention", () => {
    // FELICS's own vector for the 16-byte message 0x00112233...ff. If this ever started passing,
    // the padding would have silently changed to the other convention.
    expect(hex(gimliHash(unhex("00112233445566778899aabbccddeeff")))).not.toBe(
      "a990831f5b29528eb35f13f8cf86e8a6e7125617d664165842c72ead797fa3ff",
    );
  });

  it.each(GIMLI_VECTORS)("matches the known-answer record at $length bytes", ({ length, digest }) => {
    expect(hex(gimliHash(katMessage(length)))).toBe(digest);
  });

  /**
   * Streaming, at chunk sizes either side of the 16-byte rate.
   *
   * GIMLI pads unconditionally, so unlike the NIST lightweight sponges in `lwc-hash.ts` it never has
   * to hold a block back -- but a chunk boundary landing exactly on a rate boundary is still where an
   * absorb loop goes wrong, so the lengths sweep across several multiples of 16.
   */
  it.each([1, 3, 7, 15, 16, 17, 32, 33, 64])("streams identically at a chunk size of %i", (chunk) => {
    for (const length of [0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 64, 100]) {
      const message = katMessage(length);
      const h = createGimliHash();
      for (let at = 0; at < message.length; at += chunk) {
        h.update(message.subarray(at, Math.min(at + chunk, message.length)));
      }
      expect(hex(h.digest()), `length ${length} in ${chunk}-byte chunks`).toBe(hex(gimliHash(message)));
    }
  });

  it("extends rather than restarting for a longer digest", () => {
    // A sponge squeeze, so 64 bytes begins with the 32-byte digest.
    const short = gimliHash(katMessage(40), 32);
    const long = gimliHash(katMessage(40), 64);
    expect(hex(long.subarray(0, 32))).toBe(hex(short));
  });

  it("refuses a non-positive digest length", () => {
    expect(() => createGimliHash(0)).toThrow(/positive/);
  });
});

describe("Quark", () => {
  /**
   * The authors' own published digests, from `veorq/Quark`'s `main.c`.
   *
   * One message each, and four instances -- which is the coverage that matters, because the four
   * differ in every tap set, both register lengths, the round count, the rate and the IV. There is no
   * shared code path a single instance could vouch for.
   */
  const PUBLISHED: Record<string, string> = {
    "u-quark": "126b75bcab23144750d08ba313bbd800a4",
    "d-quark": "82c7f380e231578e2ff4c2a402e18bf37aea8477298d",
    "s-quark": "03256214b92e811c321ae86bab4b0e7ae9c22c42882fccde8c22bff6a0a1d6f1",
    "c-quark":
      "1cb9770ee7c25fa9dce2c9464578337c69c7e26cb4f1bdf44869f1a93639f1f360b888975ff9ffee880d2c499108a27a",
  };

  it.each(QUARK_INSTANCES)(
    "$label reproduces the designers' digest of the empty message",
    (instance) => {
      expect(hex(quark(instance.id, new Uint8Array(0)))).toBe(PUBLISHED[instance.id]);
    },
  );

  it("covers every registered instance", () => {
    expect(QUARK_INSTANCES.map((i) => i.id).sort()).toEqual(Object.keys(PUBLISHED).sort());
  });

  /**
   * FELICS's u-Quark intermediate states, which are the only independent check on the permutation.
   *
   * Its harness omits the padding bit entirely, so its final digest is not a Quark digest and is not
   * asserted -- but its post-initialisation and post-absorb states are produced by a second
   * implementation that shares no code with the authors' reference, and reproducing them is what
   * separates "our permutation is right" from "our permutation and our sponge are consistently
   * wrong".
   */
  it("reproduces FELICS's independently produced u-Quark states", () => {
    const h = createQuark("u-quark");
    expect(hex(h.snapshot())).toBe("d8daca44414a099719c80aa3af065644db");
    h.update(Uint8Array.of(0x11));
    expect(hex(h.snapshot())).toBe("51356f5196c933b698de02eed5ff04ed47");
  });

  it("declares an IV and register widths that fill each state", () => {
    for (const instance of QUARK_INSTANCES) {
      expect(instance.iv.length / 2, instance.label).toBe(instance.width);
      expect(instance.nlen * 2, instance.label).toBe(instance.width * 8);
      // The reference's "indices up to i+59, for 8x parallelizibility" is what licenses running
      // eight rounds at once, so the slack is asserted rather than assumed.
      const taps = [instance.f, instance.g, instance.h].join(" ^ ");
      let widest = 0;
      for (const factor of taps.split(/[\^&]/)) {
        const text = factor.trim();
        if (text.startsWith("X") || text.startsWith("Y")) widest = Math.max(widest, Number(text.slice(1)));
      }
      expect(instance.nlen - widest, `${instance.label} X/Y slack`).toBeGreaterThanOrEqual(8);
    }
  });

  it.each([1, 2, 3, 5, 8, 16])("streams identically at a chunk size of %i", (chunk) => {
    for (const instance of QUARK_INSTANCES) {
      // Short messages only: u-Quark's rate is one byte and it spends 544 rounds on each.
      const message = katMessage(11);
      const h = createQuark(instance.id);
      for (let at = 0; at < message.length; at += chunk) {
        h.update(message.subarray(at, Math.min(at + chunk, message.length)));
      }
      expect(hex(h.digest()), `${instance.label} in ${chunk}-byte chunks`).toBe(
        hex(quark(instance.id, message)),
      );
    }
  });

  /**
   * The absorb reads a byte least-significant bit first while the IV and the squeeze read
   * most-significant first. Making those agree is the natural tidy-up and it is wrong, so the
   * asymmetry gets an assertion of its own: reversing one message byte must change the digest.
   */
  it("absorbs a byte least-significant bit first", () => {
    const forward = quark("u-quark", Uint8Array.of(0b0000_0001));
    const reversed = quark("u-quark", Uint8Array.of(0b1000_0000));
    expect(hex(forward)).not.toBe(hex(reversed));
  });

  it("gives each instance its own digest width", () => {
    for (const instance of QUARK_INSTANCES) {
      expect(quark(instance.id, Uint8Array.of(1)).length, instance.label).toBe(instance.width);
    }
    // And the widths are all different, so a resolver that ignored the instance would be visible.
    const widths = QUARK_INSTANCES.map((i) => i.width);
    expect(new Set(widths).size).toBe(widths.length);
  });

  it("refuses an unknown instance", () => {
    expect(() => createQuark("x-quark")).toThrow(/unknown instance/);
    expect(() => requireQuarkInstance("x-quark")).toThrow(/unknown instance/);
  });
});

describe("PHOTON-128/16/16", () => {
  /** FELICS's two vectors. Two messages of different lengths, one of them odd. */
  it.each([
    ["1122", "b2397568e1e3e1279a1bbe8fd75dac5a"],
    ["ab", "c9d65587abc08242fe107c1fa01f70aa"],
  ])("matches FELICS's digest of %s", (message, digest) => {
    expect(hex(photonHash(unhex(message)))).toBe(digest);
  });

  /**
   * The S-box is PRESENT's, which is the strongest thing that can be said about it: PRESENT's own
   * RFC-grade vectors and LED's already pin those sixteen nibbles, so a PHOTON failure points at the
   * diffusion layer rather than at the substitution.
   */
  it("uses PRESENT's S-box unchanged", () => {
    expect([...PRESENT_SBOX]).toEqual([12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2]);
  });

  it.each([1, 2, 3, 4, 7, 16])("streams identically at a chunk size of %i", (chunk) => {
    for (const length of [0, 1, 2, 3, 4, 5, 15, 16, 17, 32, 33, 64]) {
      const message = katMessage(length);
      const h = createPhotonHash();
      for (let at = 0; at < message.length; at += chunk) {
        h.update(message.subarray(at, Math.min(at + chunk, message.length)));
      }
      expect(hex(h.digest()), `length ${length} in ${chunk}-byte chunks`).toBe(hex(photonHash(message)));
    }
  });

  /**
   * A padding block is absorbed unconditionally, so a message whose length is already a multiple of
   * the 2-byte rate still gets a whole extra block. An implementation that padded only when there was
   * a remainder would be correct for every odd length and wrong for every even one.
   */
  it("pads a rate-aligned message with a whole block", () => {
    expect(hex(photonHash(unhex("1122")))).not.toBe(hex(photonHash(unhex("112280"))));
    // And a trailing zero is distinguishable from nothing, which a padless sponge would fail.
    expect(hex(photonHash(unhex("1122")))).not.toBe(hex(photonHash(unhex("112200"))));
  });

  it("is not PHOTON-Beetle's permutation", () => {
    // Both are called PHOTON and they are different functions -- 6x6 nibbles against 8x8. Worth an
    // assertion because the family name invites the assumption.
    expect(photonHash(unhex("1122")).length).toBe(16);
  });
});
