/**
 * The SHA-3 competition candidates, against the competition's own known-answer vectors.
 *
 * Ten algorithms: Groestl, JH, CubeHash, Luffa, Fugue, SHAvite-3, Shabal, ECHO, Hamsi and SIMD. With
 * Skein, BLAKE and Keccak already in the tree that is **all five finalists and eleven designs in
 * total** -- every candidate this repo set out to implement. What remains unimplemented from the
 * second round is nothing: ECHO, Hamsi and SIMD were the last three, and they closed it.
 *
 * None has an oracle. OpenSSL implements none of them, and no dependency in this tree does either. So
 * the check is 720 published vectors -- ten algorithms, four output lengths each, eighteen message
 * lengths -- taken from sphlib's test data, which carries the competition's own KATs. See
 * `tests/sha3-candidate-kat.ts` for how they were extracted. Shabal-192 is the one length in this
 * file with no KAT array behind it; its single published value is asserted separately below.
 *
 * Four bugs this file caught, all of them the kind that leaves a hash perfectly self-consistent:
 *
 *  - **Groestl's Q round constant.** The specification says every byte takes 0xff *except* the last
 *    row, which takes `(col * 0x10) XOR 0xff XOR round`. Applying both -- the obvious misreading --
 *    failed all 72 Groestl vectors and nothing else.
 *  - **JH's padding of block-aligned messages.** A message whose length is a multiple of 64 bytes gets
 *    one padding block; everything else gets two. Using two throughout passed 60 of 72 vectors and
 *    failed exactly the lengths 0, 64 and 128, which is why those three are in the fixture.
 *  - **The `AES_SBOX` reuse.** Groestl's S-box *is* Rijndael's, so it comes from `aes-round.ts`'s
 *    derived table. Four independent vector sets now check one table -- Groestl's, SHAvite-3's,
 *    ECHO's and Fugue's -- which is the same arrangement ARIA and AEGIS already have.
 *  - **A privately derived AES S-box.** ECHO's first draft derived the table itself and produced
 *    `SBOX[1] = 0x63`, because the multiplicative inverse needs `p[(255 - l[a]) % 255]` rather than
 *    `p[255 - l[a]]`. It failed all 72 ECHO vectors, which is why ECHO imports `aesRound` instead of
 *    computing anything: a table already pinned by three vector sets cannot be got wrong privately.
 */
import { describe, expect, it } from "vitest";
import {
  createCubehash,
  createEcho,
  createGroestl,
  createHamsi,
  createJh,
  createFugue,
  createLuffa,
  createShabal,
  createShavite,
  createSimd,
  cubehash,
  echo,
  groestl,
  fugue,
  hamsi,
  jh,
  luffa,
  shabal,
  shavite,
  simd,
} from "@ocs/algos";
import { FUGUE_MIX } from "@ocs/algos";
import { SHA3_CANDIDATE_KAT } from "./sha3-candidate-kat";

const fromHex = (hex: string) =>
  hex === "" ? new Uint8Array(0) : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

type Digest = (outputLen: 28 | 32 | 48 | 64, message: Uint8Array) => Uint8Array;
type Streaming = (outputLen: 28 | 32 | 48 | 64) => {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
};

const ALGORITHMS: readonly { name: string; digest: Digest; stream: Streaming }[] = [
  { name: "groestl", digest: groestl, stream: createGroestl },
  { name: "jh", digest: jh, stream: createJh },
  { name: "cubehash", digest: cubehash, stream: createCubehash },
  { name: "luffa", digest: luffa, stream: createLuffa },
  { name: "fugue", digest: fugue, stream: createFugue },
  { name: "shavite", digest: shavite, stream: createShavite },
  // Shabal's own type admits 24 as well; the KAT arrays cover only the four shared lengths.
  { name: "shabal", digest: shabal, stream: createShabal },
  { name: "echo", digest: echo, stream: createEcho },
  { name: "hamsi", digest: hamsi, stream: createHamsi },
  { name: "simd", digest: simd, stream: createSimd },
];

const LENGTHS = [28, 32, 48, 64] as const;

describe("the SHA-3 competition candidates", () => {
  for (const { name, digest } of ALGORITHMS) {
    it(`reproduces every ${name} vector at all four output lengths`, () => {
      let checked = 0;
      for (const outputLen of LENGTHS) {
        const bits = String(outputLen * 8);
        const vectors = SHA3_CANDIDATE_KAT[name]![bits]!;
        expect(vectors.length, `${name}/${bits} vector count`).toBe(18);
        for (const vector of vectors) {
          const message = fromHex(vector.message);
          expect(toHex(digest(outputLen, message)), `${name}-${bits} len=${message.length}`).toBe(
            vector.digest,
          );
          checked += 1;
        }
      }
      expect(checked, `${name} total`).toBe(72);
    });
  }

  it("reproduces the one published Shabal-192 value", () => {
    /**
     * The competition data has no 192-bit KAT array -- the reference checks that length against a
     * single value of its own, over a 102-byte sentence rather than the pseudorandom pool. It is the
     * only published vector covering Shabal-192's initial values, so a wrong word among those 44
     * would show up here and nowhere else.
     */
    const message = new TextEncoder().encode(
      "abcdefghijklmnopqrstuvwxyz-0123456789-ABCDEFGHIJKLM" +
        "NOPQRSTUVWXYZ-0123456789-abcdefghijklmnopqrstuvwxyz",
    );
    expect(message.length).toBe(102);
    expect(toHex(shabal(24, message))).toBe("690fae79226d95760ae8fdb4f58c0537111756557d307b15");
  });

  it("covers the lengths that actually distinguish the padding rules", () => {
    /**
     * The fixture's lengths are chosen, not sampled. 0, 64 and 128 are the block-aligned cases JH
     * treats specially; 55, 56 and 63 straddle the point where a length field stops fitting in the
     * final block; 127, 128 and 129 do the same for Groestl's 128-byte long-variant block.
     */
    const lengths = SHA3_CANDIDATE_KAT.jh!["256"]!.map((v) => v.message.length / 2);
    for (const boundary of [0, 63, 64, 65, 127, 128, 129]) {
      expect(lengths, `length ${boundary}`).toContain(boundary);
    }
  });

  it("gives the same answer through the incremental interface, in awkward chunk sizes", () => {
    /**
     * Seven of the ten buffer rather than compressing per chunk -- their paddings carry a total count,
     * so nothing can be finalised early. ECHO, Hamsi and SIMD genuinely stream, and that is the case
     * this test earns its place on: a real block loop can drop or double-count a chunk in a way a
     * buffered implementation cannot, and the chunk sizes below cross Hamsi's 4-byte block, SIMD's 64
     * and ECHO's 192.
     */
    const message = fromHex(SHA3_CANDIDATE_KAT.groestl!["256"]![17]!.message);
    expect(message.length).toBe(255);

    for (const { name, digest, stream } of ALGORITHMS) {
      for (const outputLen of LENGTHS) {
        for (const chunk of [1, 7, 64, 100]) {
          const hasher = stream(outputLen);
          for (let at = 0; at < message.length; at += chunk) {
            hasher.update(message.subarray(at, Math.min(at + chunk, message.length)));
          }
          expect(toHex(hasher.digest()), `${name}/${outputLen}/${chunk}`).toBe(
            toHex(digest(outputLen, message)),
          );
        }
      }
      // And an empty stream matches the empty one-shot.
      expect(toHex(stream(32).digest()), `${name} empty`).toBe(toHex(digest(32, new Uint8Array(0))));
    }
  });

  it("gives each output length its own answer rather than truncating -- except Luffa", () => {
    /**
     * Groestl, JH and CubeHash bind the digest length into the initial state -- the first two through
     * the IV, CubeHash through the first word of its pre-round state -- so a 224-bit digest is *not*
     * the first 28 bytes of the 256-bit one, and someone truncating by hand gets a wrong answer with
     * no error.
     *
     * Luffa is the exception and it is worth stating rather than working around: Luffa-224 and
     * Luffa-256 use the same three lanes and the same initial values, and the shorter one simply
     * emits seven words where the longer emits eight. So there Luffa-224 *is* the truncation. The
     * 384- and 512-bit variants are different functions again, because they add lanes.
     */
    const message = fromHex("00010203");
    for (const { name, digest } of ALGORITHMS) {
      const short = toHex(digest(28, message));
      const long = toHex(digest(32, message));
      if (name === "luffa") {
        expect(short, name).toBe(long.slice(0, short.length));
        // And the wider variants are not truncations of each other, since the lane count differs.
        expect(toHex(digest(48, message)).slice(0, 64)).not.toBe(toHex(digest(64, message)).slice(0, 64));
        continue;
      }
      expect(short, name).not.toBe(long.slice(0, short.length));
    }
  });

  it("derives Fugue's SuperMix tables from the AES S-box", () => {
    /**
     * Fugue is normally shipped with four 1 KB lookup tables. They are not arbitrary: entry `x` is the
     * word `(S[x], S[x], S[x]*7, S[x]*4)` in GF(2^8) under AES's polynomial, and the other three
     * tables are that rotated one, two and three bytes right. So nothing is stored, and this asserts
     * the two properties the derivation rests on -- the reference's own first entries, and the
     * rotation relationship between the four.
     */
    expect(FUGUE_MIX).toHaveLength(4);
    // mixtab0[0] and [1] as the reference prints them.
    expect(FUGUE_MIX[0]![0]!.toString(16)).toBe("63633297");
    expect(FUGUE_MIX[0]![1]!.toString(16)).toBe("7c7c6feb");
    for (let x = 0; x < 256; x++) {
      const base = FUGUE_MIX[0]![x]!;
      for (let table = 1; table < 4; table++) {
        const rotated = ((base >>> (8 * table)) | (base << (32 - 8 * table))) >>> 0;
        expect(FUGUE_MIX[table]![x], `table ${table} at ${x}`).toBe(rotated);
      }
    }
  });

  it("covers each new candidate's block-aligned case with a published value", () => {
    /**
     * ECHO, Hamsi and SIMD all branch on "is the final block empty", and all three do something
     * different there: ECHO zeroes the counter that keys its AES rounds, SIMD skips the tail
     * compression entirely, and Hamsi's small variant still runs three blocks because its length field
     * spans two of them. The branch fires exactly when the message length is a multiple of the block
     * size -- and the fixture's zero-length row is such a message for every one of them, which is what
     * makes that row load-bearing rather than a formality.
     *
     * Above zero the fixture reaches the boundary for Hamsi (4 and 8 bytes: 32, 64, 128, 200) and SIMD
     * (64 bytes: 64, 128), but not for ECHO-224/256, whose block is 192. The 255-byte row exercises
     * ECHO's full-block path with a 63-byte tail; a message of exactly 192 bytes is checked only for
     * self-consistency below, and that gap is stated rather than papered over.
     */
    const lengths = SHA3_CANDIDATE_KAT.echo!["256"]!.map((v) => v.message.length / 2);
    expect(lengths).toContain(0);
    for (const boundary of [32, 64, 128, 200]) expect(lengths).toContain(boundary);

    const block = new Uint8Array(192);
    for (let i = 0; i < block.length; i++) block[i] = (i * 7 + 1) & 0xff;
    const oneShot = toHex(echo(32, block));
    const streamed = createEcho(32);
    streamed.update(block.subarray(0, 192));
    expect(toHex(streamed.digest())).toBe(oneShot);
    // And it is not the same as the empty digest, which a counter left unzeroed could produce.
    expect(oneShot).not.toBe(toHex(echo(32, new Uint8Array(0))));
  });

  it("keeps Hamsi-384 and Hamsi-512 separate functions", () => {
    /**
     * Worth its own assertion because Hamsi-384 is the one output in this file that is a *selection*
     * rather than a prefix: it emits h[0], h[1], h[3], h[4], h[5], h[6], h[8], h[9], h[10], h[12],
     * h[13], h[15], skipping four words of a sixteen-word state. That selection is checked by the 72
     * KAT vectors and by nothing else -- an implementation taking the first twelve would agree with
     * itself and with nothing in existence. What is asserted here is the weaker property the vectors
     * cannot state on their own, which is that the two lengths are separate functions: they differ in
     * their initial values as well as in which words come out, so not even the first word matches.
     */
    const message = new TextEncoder().encode("Hamsi-384 skips four words");
    const short = toHex(hamsi(48, message));
    const long = toHex(hamsi(64, message));
    expect(short.slice(0, 8)).not.toBe(long.slice(0, 8));
    expect(short).not.toBe(long.slice(0, short.length));
  });

  it("keeps SIMD's length block separate from its message blocks", () => {
    /**
     * SIMD has no padding byte at all: a short final block is zero-filled, and the bit count gets a
     * block of its own compressed with a different twist table. So a message and the same message with
     * a trailing zero byte are distinguished *only* by that final block -- which is exactly the
     * property Snefru, GOST R 34.11-94 and belt-hash have, and the one thing here somebody would
     * "fix" by adding a 0x80.
     */
    const message = new TextEncoder().encode("no padding byte");
    const withZero = new Uint8Array(message.length + 1);
    withZero.set(message);
    for (const outputLen of LENGTHS) {
      expect(toHex(simd(outputLen, message)), `SIMD-${outputLen * 8}`).not.toBe(
        toHex(simd(outputLen, withZero)),
      );
    }
  });

  it("accepts a parameterised CubeHash, since the round count is what its name means", () => {
    /**
     * "CubeHash" without qualification means CubeHash16/32 -- sixteen rounds per 32-byte block -- and
     * that is what the vectors cover and what the tool computes. The parameters are arguments rather
     * than constants so a different `CubeHash r/b` is a metadata entry away if a vector for one ever
     * turns up; this checks that changing them changes the answer, so the plumbing is real.
     */
    const message = fromHex("00010203");
    const standard = toHex(cubehash(32, message));
    expect(toHex(cubehash(32, message, { rounds: 16, blockLen: 32 }))).toBe(standard);
    expect(toHex(cubehash(32, message, { rounds: 8, blockLen: 32 }))).not.toBe(standard);
  });
});
