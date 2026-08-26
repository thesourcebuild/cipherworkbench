import { describe, expect, it } from "vitest";
import { createMd6, md6, md6Rounds, MD6_LEAF_BYTES, MD6_OUTPUT_LENS } from "@ocs/algos";

/**
 * MD6, against values from Rivest's own reference implementation.
 *
 * There is no oracle: OpenSSL never implemented MD6, no dependency in this tree has it, and NIST's KAT
 * files for the SHA-3 round-1 submissions are not mirrored anywhere reachable from here. So what stands
 * in is the shape this repo already accepted for Tiger2 -- values from an implementation that can be
 * corroborated independently. Two things make it stronger than that precedent:
 *
 *  - The algorithm was **derived from the reference C**, fetched and read (`md6_compress.c` and
 *    `md6_mode.c`), rather than recalled from a paper summary. The node layout, the control word's bit
 *    fields and the tail-not-head trim are all things a summary omits, and all three are places where a
 *    wrong guess gives a hash that is perfectly self-consistent.
 *  - The vectors come from **three independent sources**: a table covering six digest sizes at five
 *    message lengths, a second implementation whose one MD6-256 value is kept separately below because
 *    it shares nothing with the first, and a third reference supplied *after* this implementation was
 *    written, by somebody who had not seen it -- which is the one kind of vector that cannot have been
 *    fitted to, and the reason it is worth naming as its own source rather than folding in.
 *
 * The message lengths build a *different tree each time*, which is the property no other hash here has:
 * 0 and 3 bytes are a single leaf that is also the root, 1,000 bytes is two leaves under one parent,
 * and 8,192 bytes is sixteen leaves under four parents under one root -- three levels, and the
 * pass-through case where the top level holds a single child and is not compressed at all.
 */

const hex = (bytes: Uint8Array) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const ascii = (text: string) => new TextEncoder().encode(text);
const seq = (n: number) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = i & 0xff;
  return out;
};

interface Vector {
  label: string;
  bits: number;
  input: Uint8Array;
  hex: string;
}

const VECTORS: readonly Vector[] = [
  // ── the empty message: one leaf, which is also the root ──
  { label: "empty/128", bits: 128, input: new Uint8Array(0), hex: "032f75b3ca02a393196a818328bd32e8" },
  { label: "empty/160", bits: 160, input: new Uint8Array(0), hex: "f325ee93c54cfaacd7b9007e1cf8904680993b18" },
  {
    label: "empty/224",
    bits: 224,
    input: new Uint8Array(0),
    hex: "d2091aa2ad17f38c51ade2697f24cafc3894c617c77ffe10fdc7abcb",
  },
  {
    label: "empty/256",
    bits: 256,
    input: new Uint8Array(0),
    hex: "bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca",
  },
  {
    label: "empty/384",
    bits: 384,
    input: new Uint8Array(0),
    hex:
      "b0bafffceebe856c1eff7e1ba2f539693f828b532ebf60ae9c16cbc34990204" +
      "01b942ac25b310b2227b2954ccacc2f1f",
  },
  {
    label: "empty/512",
    bits: 512,
    input: new Uint8Array(0),
    hex:
      "6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f" +
      "8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0f8e0c0",
  },

  // ── "abc" ──
  { label: "abc/128", bits: 128, input: ascii("abc"), hex: "8db50d79cf42fe7d1807ebaa15329c61" },
  { label: "abc/160", bits: 160, input: ascii("abc"), hex: "b5c2d6a7ce6be0c18c9a38b17a0db705c81ab6b5" },
  {
    label: "abc/224",
    bits: 224,
    input: ascii("abc"),
    hex: "510c30e4202a5cdd8a4f2ae9beebb6f5988128897937615d52e6d228",
  },
  {
    label: "abc/256",
    bits: 256,
    input: ascii("abc"),
    hex: "230637d4e6845cf0d092b558e87625f03881dd53a7439da34cf3b94ed0d8b2c5",
  },
  {
    label: "abc/384",
    bits: 384,
    input: ascii("abc"),
    hex:
      "e2c6d31dd8872cbd5a1207481cdac581054d13a4d4fe6854331cd8cf3e7cbafb" +
      "addd6e2517972b8ff57cdc4806d09190",
  },
  {
    label: "abc/512",
    bits: 512,
    input: ascii("abc"),
    hex:
      "00918245271e377a7ffb202b90f3bda5477d8feab12d8a3a8994ebc55fe6e74c" +
      "a8341520032eeea3fdef892f2882378f636212af4b2683ccf80bf025b7d9b457",
  },

  // ── the pangram ──
  {
    label: "fox/128",
    bits: 128,
    input: ascii("The quick brown fox jumps over the lazy dog"),
    hex: "7b428f5ec47e0174faf31dc7c89590c6",
  },
  {
    label: "fox/256",
    bits: 256,
    input: ascii("The quick brown fox jumps over the lazy dog"),
    hex: "977592608c45c9923340338450fdcccc21a68888e1e6350e133c5186cd9736ee",
  },
  {
    label: "fox/512",
    bits: 512,
    input: ascii("The quick brown fox jumps over the lazy dog"),
    hex:
      "dcba0c6593fbd83a0f5f148588baa79530579c1f5e7f19d500fe282d137bff465" +
      "106f25c9f0619b4082a730683d5f58311c0c1913068e91b0ebdf9ace3ff5b9e",
  },

  // ── 1,000 bytes: two leaves under one parent ──
  { label: "1000a/128", bits: 128, input: ascii("a".repeat(1000)), hex: "8f67b4e518ef8abfb1b72e5991cd1b30" },
  {
    label: "1000a/256",
    bits: 256,
    input: ascii("a".repeat(1000)),
    hex: "ff7c492a5b92f45bbf62acc81738e8aae8d1cc87a2be9173da0630b107815d76",
  },
  {
    label: "1000a/512",
    bits: 512,
    input: ascii("a".repeat(1000)),
    hex:
      "4c74e18466da05ac0050f33634088059598297b87022ce22e6b7adcf257b1c37" +
      "8d8cc53c121bb02fec3678b2fd53ad625cea17a202621aa97022efaa1acd1fde",
  },

  // ── 8,192 bytes: sixteen leaves, four parents, one root -- three levels ──
  { label: "8192seq/128", bits: 128, input: seq(8192), hex: "edaf821142ee4c45fef33d2600d7e158" },
  {
    label: "8192seq/256",
    bits: 256,
    input: seq(8192),
    hex: "2a40338156df221b18b20e4003f51f61284cacd01935e9e87414e6ae40a6bd25",
  },
  {
    label: "8192seq/512",
    bits: 512,
    input: seq(8192),
    hex:
      "a9d0a1262f13414b9d48448e1e534cd47cbd40ffffdb8dc882619c747a284a46" +
      "2a7ff4fbb27180a390d182801a9722b3f1c7d04ef5ce90bb553446c286b97ccb",
  },

  // ── digest sizes that are not whole bytes, which exercise the trim's shift ──
  { label: "empty/8", bits: 8, input: new Uint8Array(0), hex: "3e" },
  { label: "empty/17", bits: 17, input: new Uint8Array(0), hex: "9a0900" },
  { label: "empty/100", bits: 100, input: new Uint8Array(0), hex: "3e2b7d765cc7cef3bda7228790" },
  { label: "abc/8", bits: 8, input: ascii("abc"), hex: "e8" },
  { label: "abc/100", bits: 100, input: ascii("abc"), hex: "13c4cfbd2a58de21ae166c6160" },
];

/**
 * Two further sources, each independent of the table above and of each other.
 *
 * The independence is the point: three implementations that share no code agreeing on values is much
 * stronger evidence than any one of them, and it is what stands in for the KAT files nobody mirrors.
 * Kept as their own array rather than folded in, so the provenance stays visible.
 *
 * The "Progressive" set is the most valuable kind of vector this repo can carry: it was supplied
 * against a reference *after* this implementation was written, by somebody who had not seen it, so it
 * cannot have been fitted to. All three sizes matched first time.
 *
 * Note that the input has no trailing newline. Adding one gives an unrelated digest, so a value
 * transcribed out of a tool that appends one reads as a failure here rather than
 * as the transcription it is -- which is the single most common way a hash comparison goes wrong, and
 * the reason this says so rather than leaving it implicit.
 */
const OTHER_SOURCES: readonly Vector[] = [
  {
    label: "md6 FTW/256 (independent port)",
    bits: 256,
    input: ascii("md6 FTW"),
    hex: "7bfaa624f661a683be2a3b2007493006a30a7845ee1670e499927861a8e74cce",
  },
  {
    label: "Progressive/128 (third reference)",
    bits: 128,
    input: ascii("Progressive"),
    hex: "08d59da8b9afce97cd91876a06c74d1b",
  },
  {
    label: "Progressive/256 (third reference)",
    bits: 256,
    input: ascii("Progressive"),
    hex: "470c33fd30ceef8d331df45bed88f36bd1e5a0610d80da7280d860e82f4bcab2",
  },
  {
    label: "Progressive/512 (third reference)",
    bits: 512,
    input: ascii("Progressive"),
    hex:
      "8cf89011b1d71259f6e2be38eadc50c70a8b11728d58ed685c89ea39162ef196" +
      "19ea850ae7e8b91a342cfa987d29d89fd0e5560f78cd0864e2c72ff39128c23c",
  },
];

describe("MD6", () => {
  it("reproduces every vector from the reference implementation", () => {
    const bad: string[] = [];
    for (const v of VECTORS) {
      const got = hex(md6(v.input, v.bits));
      if (got !== v.hex) bad.push(`${v.label}: got ${got} want ${v.hex}`);
    }
    expect(bad, "vectors that did not match").toEqual([]);
    // Guards the guard: 26 vectors, over six digest sizes and five message lengths.
    expect(VECTORS).toHaveLength(26);
  });

  it("agrees with two further, unrelated references", () => {
    for (const v of OTHER_SOURCES) expect(hex(md6(v.input, v.bits)), v.label).toBe(v.hex);
    // Three sizes from the third reference plus one from the second: four values, three sources.
    expect(OTHER_SOURCES).toHaveLength(4);
  });

  /**
   * A trailing newline changes everything, asserted so nobody debugs a transcription as a bug.
   *
   * The commonest way a hash comparison goes wrong: a value copied out of a tool that appended a
   * newline, or typed into a box that did. All three sizes must differ for the two inputs.
   */
  it("gives an unrelated digest for the same text with a trailing newline", () => {
    for (const bits of [128, 256, 512]) {
      expect(hex(md6(ascii("Progressive"), bits)), String(bits)).not.toBe(
        hex(md6(ascii("Progressive\n"), bits)),
      );
    }
  });

  /**
   * `r = 40 + d/4`, so the round count is part of the answer.
   *
   * MD6-512 runs 168 rounds where MD6-128 runs 72. Two implementations disagreeing about this produce
   * unrelated output at the same length, which is why it is asserted rather than left as a detail
   * buried in the compression loop.
   */
  it("derives the round count from the digest size", () => {
    expect(md6Rounds(128)).toBe(72);
    expect(md6Rounds(256)).toBe(104);
    expect(md6Rounds(512)).toBe(168);
  });

  /**
   * Streaming equals one-shot, at chunk sizes that land either side of a leaf boundary.
   *
   * This matters more here than for any other hash in the repo, because MD6's tree *shape* depends on
   * the input length, and a full leaf cannot be compressed until the next byte proves it is not the
   * last one -- a leaf that turns out to end the message has to be compressed as the root instead. 512
   * and 513 are the two lengths that go wrong differently.
   */
  it("streams to the same digest at every chunk size", () => {
    for (const bits of [128, 256, 512]) {
      for (const length of [0, 1, 511, 512, 513, 1024, 2048, 8192]) {
        const input = seq(length);
        const expected = hex(md6(input, bits));
        for (const size of [1, 7, 64, 511, 512, 513, 1000, 100_000]) {
          const h = createMd6(bits);
          for (let at = 0; at < input.length; at += size) h.update(input.subarray(at, at + size));
          expect(hex(h.digest()), `d=${bits} len=${length} chunks=${size}`).toBe(expected);
        }
      }
    }
  });

  /** A leaf is 512 bytes, and the tree grows at multiples of it. Stated rather than implied. */
  it("puts 512 bytes in a leaf", () => {
    expect(MD6_LEAF_BYTES).toBe(512);
  });

  /**
   * Every length across the first two leaf boundaries gives a distinct digest.
   *
   * A tree hash can go wrong by building the wrong *shape* -- one leaf too many, a parent taking three
   * children instead of four -- and the symptom is two different messages hashing to the same value.
   * Sweeping the boundaries and requiring every answer to be new is what catches that; no fixed vector
   * at a single length can.
   */
  it("gives a distinct digest for every length across the leaf boundaries", () => {
    const seen = new Map<string, number>();
    for (let length = 0; length <= 1100; length++) {
      const digest = hex(md6(seq(length), 128));
      const previous = seen.get(digest);
      expect(previous, `length ${length} collides with ${previous}`).toBeUndefined();
      seen.set(digest, length);
    }
    expect(seen.size).toBe(1101);
  });

  it("offers exactly the three sizes the tool registers", () => {
    expect(MD6_OUTPUT_LENS).toEqual([16, 32, 64]);
  });

  it("refuses a digest size outside 1 to 512 bits", () => {
    expect(() => createMd6(0)).toThrow(/1 to 512/);
    expect(() => createMd6(513)).toThrow(/1 to 512/);
    expect(() => createMd6(128.5)).toThrow(/1 to 512/);
  });

  it("refuses to be updated after digesting", () => {
    const h = createMd6(256);
    h.update(ascii("abc"));
    h.digest();
    expect(() => h.update(ascii("more"))).toThrow(/after digest/);
  });
});
