import { describe, expect, it } from "vitest";
import { ripemd160 } from "@noble/hashes/legacy.js";
import {
  createRipemd128,
  createRipemd160ForTesting,
  createRipemd256,
  createRipemd320,
} from "@ocs/algos";

/**
 * The three RIPEMD widths `@noble/hashes` does not carry, checked two ways.
 *
 * **Against noble, via RIPEMD-160.** `@ocs/algos` implements all four widths from one parameterised
 * core, and RIPEMD-160 is built from that core purely so this file can require it to equal noble's
 * independent implementation. One assertion then covers the message schedule, both rotation tables,
 * both constant tables, all five round functions, the five-word step and the cross-add
 * finalisation -- nearly every surface where a transcription error could hide. It earned its place
 * immediately: the first version of the core produced a correct RIPEMD-128 and a wrong RIPEMD-160,
 * and this is what said so.
 *
 * **Against the published table**, for what noble cannot cover: each width's own finalisation, and
 * for the doubled widths the lane swap. All nine inputs from Antoon Bosselaers' RIPEMD page, whose
 * table is the canonical source every other implementation cites. The million-byte case is there
 * because it is the only one that exercises multi-block processing at length.
 *
 * The bug those two halves caught between them is worth recording. RIPEMD's register rotation
 * advances one slot per step, so sixteen steps leave a five-word lane one slot out of phase and a
 * four-word lane exactly in phase. The doubled variants swap one word between lanes *by slot* after
 * each round -- so only RIPEMD-320 has both a phase shift and a swap, and only RIPEMD-320 was
 * wrong. RIPEMD-128, RIPEMD-160 and RIPEMD-256 all passed while it was broken.
 */

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const run = (
  make: () => { update(c: Uint8Array): void; digest(): Uint8Array },
  text: string,
) => {
  const h = make();
  h.update(new TextEncoder().encode(text));
  return hex(h.digest());
};

const INPUTS = [
  "",
  "a",
  "abc",
  "message digest",
  "abcdefghijklmnopqrstuvwxyz",
  "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  "1234567890".repeat(8),
  "a".repeat(1_000_000),
];

const EXPECTED: Record<string, string[]> = {
  "128": [
    "cdf26213a150dc3ecb610f18f6b38b46",
    "86be7afa339d0fc7cfc785e72f578d33",
    "c14a12199c66e4ba84636b0f69144c77",
    "9e327b3d6e523062afc1132d7df9d1b8",
    "fd2aa607f71dc8f510714922b371834e",
    "a1aa0689d0fafa2ddc22e88b49133a06",
    "d1e959eb179c911faea4624c60c5c702",
    "3f45ef194732c2dbb2c4a2c769795fa3",
    "4a7f5723f954eba1216c9d8f6320431f",
  ],
  "256": [
    "02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
    "f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925",
    "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65",
    "87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e",
    "649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133",
    "3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f",
    "5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8",
    "06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd",
    "ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978",
  ],
  "320": [
    "22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
    "ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d",
    "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d",
    "3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197",
    "cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009",
    "d034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac",
    "ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4",
    "557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42",
    "bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66",
  ],
};

describe("the generic core against noble's RIPEMD-160", () => {
  it("reproduces it exactly, which validates the shared machinery", () => {
    for (const text of [
      "",
      "a",
      "abc",
      "message digest",
      "abcdefghijklmnopqrstuvwxyz",
      // Longer than one block, so the chaining is covered too.
      "x".repeat(1000),
    ]) {
      const data = new TextEncoder().encode(text);
      const engine = createRipemd160ForTesting();
      engine.update(data);
      expect(hex(engine.digest()), text.slice(0, 20)).toBe(hex(ripemd160(data)));
    }
  });
});

for (const [variant, make] of [
  ["128", createRipemd128],
  ["256", createRipemd256],
  ["320", createRipemd320],
] as const) {
  it(`RIPEMD-${variant} matches all 9 published vectors`, () => {
    INPUTS.forEach((text, i) => {
      const label = text.length > 24 ? `${text.slice(0, 20)}… (${text.length})` : `"${text}"`;
      expect(run(make, text), `RIPEMD-${variant} ${label}`).toBe(EXPECTED[variant]![i]);
    });
  });
}
