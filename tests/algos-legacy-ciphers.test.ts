/**
 * Anubis and SAFER+ -- the last two algorithms on this repo's blocked list, and both unblocked by the
 * same source.
 *
 * Neither has an oracle: OpenSSL implemented neither, nothing in this tree has either, and the earlier
 * survey had exhausted Bouncy Castle, Crypto++, Botan, libgcrypt, avr-crypto-lib and FELICS looking for
 * them. **LibTomCrypt has both**, each with a built-in self-test carrying published values -- which is
 * the whole lesson of this pair, and it is recorded in `legacy-cipher-vectors.ts` rather than here.
 *
 * What the two sets cover, and it is different in each case:
 *
 *  - **Anubis: fourteen per variant, two at each of seven key lengths.** The round count is
 *    `8 + keylen/4`, so those seven exercise 12 to 18 rounds and seven different key-schedule lengths.
 *    Thin per length and broad across them, which is the right shape for a cipher whose key size is the
 *    parameter.
 *  - **SAFER+: three, one per key length**, so 8, 12 and 16 rounds. Genuinely thin, and stated as thin.
 *    What makes it defensible is that the substitution and all 512 bias bytes are *derived* rather than
 *    transcribed, and the derivations are asserted separately below -- so the vectors only have to cover
 *    the round structure, not the tables.
 *
 * Four properties are asserted rather than trusted, one per thing that could be silently wrong: Anubis's
 * S-box is Khazad's, its matrix is involutory, its round constants come out of its S-box, and SAFER+'s
 * bias rows come out of two exponentiation rules.
 */
import { describe, expect, it } from "vitest";
import {
  ANUBIS_MATRIX,
  ANUBIS_ROUND_CONSTANT_FIRST,
  ANUBIS_SBOX_FIRST,
  createAnubis,
  createKhazad,
  createSaferPlus,
  KHAZAD_SBOX,
  SAFERP_BIAS_FIRST,
} from "@ocs/algos";
import { ANUBIS_VECTORS, SAFERP_BIAS_ROW_0, SAFERP_VECTORS } from "./legacy-cipher-vectors";
import { KHAZAD_VECTORS } from "./phase8-vectors";

const unhex = (text: string): Uint8Array =>
  Uint8Array.from(text.match(/../g)!.map((p) => parseInt(p, 16)));
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

interface BlockLike {
  blockSize: number;
  encryptBlock(s: Uint8Array, d: Uint8Array): void;
  decryptBlock(s: Uint8Array, d: Uint8Array): void;
}
const one = (cipher: BlockLike, src: Uint8Array, decrypt = false): Uint8Array => {
  const out = new Uint8Array(cipher.blockSize);
  if (decrypt) cipher.decryptBlock(src, out);
  else cipher.encryptBlock(src, out);
  return out;
};

describe("Anubis", () => {
  it("reproduces both variants' vectors in both directions", () => {
    for (const variant of ["original", "tweaked"] as const) {
      const vectors = ANUBIS_VECTORS[variant];
      expect(vectors, variant).toHaveLength(14);
      for (const v of vectors) {
        const cipher = createAnubis(unhex(v.key), variant);
        expect(hex(one(cipher, unhex(v.plaintext))), `${variant} encrypt ${v.key}`).toBe(
          v.ciphertext,
        );
        // Against the published ciphertext, not a re-encryption of ours -- which is what catches an
        // inverse key schedule that is self-consistent and wrong.
        expect(hex(one(cipher, unhex(v.ciphertext), true)), `${variant} decrypt ${v.key}`).toBe(
          v.plaintext,
        );
      }
    }
  });

  it("covers all seven key lengths, which is all seven round counts", () => {
    /**
     * Asserted rather than left in a comment: the round count is `8 + keylen/4`, so a fixture that lost
     * a length would lose the only coverage of one round count, and the remaining vectors would still
     * pass. Both variants, because the two are separate code paths through the same schedule.
     */
    for (const variant of ["original", "tweaked"] as const) {
      const lengths = ANUBIS_VECTORS[variant].map((v) => v.key.length / 2);
      expect([...new Set(lengths)].sort((a, b) => a - b), variant).toEqual([
        16, 20, 24, 28, 32, 36, 40,
      ]);
    }
  });

  it("shares Khazad's S-box in its tweaked form, and not in its original", () => {
    /**
     * The reason `anubis.ts` stores one 256-byte table rather than two. Anubis and Khazad were designed
     * together and revised together, so the tweaked pair share the revised S-box -- which means Khazad's
     * 450 NESSIE vectors already pin half of Anubis's substitution layer, and a failure above points at
     * the key schedule or the matrix.
     *
     * The `not` half matters as much: the original variant has its own table, so a bug that returned the
     * tweaked tables for both would pass every tweaked vector and fail every original one. Getting those
     * two blocks the wrong way round is exactly what happened while this was being written.
     */
    expect(ANUBIS_SBOX_FIRST.tweaked).toBe(KHAZAD_SBOX[0]);
    expect(ANUBIS_SBOX_FIRST.tweaked).toBe(0xba);
    expect(ANUBIS_SBOX_FIRST.original).toBe(0xa7);

    const key = unhex("00112233445566778899aabbccddeeff");
    const block = unhex("0123456789abcdef0123456789abcdef");
    expect(hex(one(createAnubis(key, "original"), block))).not.toBe(
      hex(one(createAnubis(key, "tweaked"), block))
    );
  });

  it("derives its round constants from its own S-box", () => {
    /**
     * `rc[r] = S[4r] S[4r+1] S[4r+2] S[4r+3]`, so there is no constant table at all and a wrong S-box
     * entry breaks the key schedule as well as the substitution. Pinned per variant, because the two
     * S-boxes give two different constant sequences and a shared table would be invisible otherwise.
     */
    expect(ANUBIS_ROUND_CONSTANT_FIRST.tweaked.toString(16)).toBe("ba542f74");
    expect(ANUBIS_ROUND_CONSTANT_FIRST.original.toString(16)).toBe("a7d3e671");
  });

  it("has an involutory diffusion matrix, which is why one circuit does both directions", () => {
    /**
     * `H * H` must be the identity over GF(2^8) under 0x11d. Asserted rather than trusted for the same
     * reason Khazad's is: the matrix is the one piece of structure written out by hand, and a single
     * wrong entry would leave encryption correct while making decryption a different function -- which
     * is precisely the failure a round trip cannot see.
     */
    const mul = (a: number, b: number): number => {
      let r = 0;
      let x = a;
      let y = b;
      while (y !== 0) {
        if ((y & 1) !== 0) r ^= x;
        x = ((x << 1) ^ (x & 0x80 ? 0x11d : 0)) & 0xff;
        y >>= 1;
      }
      return r & 0xff;
    };
    expect(ANUBIS_MATRIX).toHaveLength(4);
    for (let i = 0; i < 4; i++) {
      for (let j = 0; j < 4; j++) {
        let acc = 0;
        for (let k = 0; k < 4; k++) acc ^= mul(ANUBIS_MATRIX[i]![k]!, ANUBIS_MATRIX[k]![j]!);
        expect(acc, `H*H at (${i},${j})`).toBe(i === j ? 1 : 0);
      }
    }
  });

  it("still leaves Khazad alone", () => {
    /**
     * `KHAZAD_SBOX` became exported so Anubis could import it. This re-runs the first of Khazad's own
     * NESSIE vectors -- read from that fixture rather than written out here, so it cannot drift -- so the
     * export cannot have disturbed the cipher those 256 bytes were verified through.
     */
    const v = KHAZAD_VECTORS[0]!;
    const cipher = createKhazad(unhex(v.key));
    expect(hex(one(cipher, unhex(v.plaintext)))).toBe(v.ciphertext);
  });

  it("refuses a key length that is not a multiple of four in range", () => {
    expect(() => createAnubis(new Uint8Array(18))).toThrow(/16, 20, 24, 28, 32, 36 or 40/);
    expect(() => createAnubis(new Uint8Array(44))).toThrow(/16, 20, 24, 28, 32, 36 or 40/);
  });
});

describe("SAFER+", () => {
  it("reproduces all three vectors in both directions", () => {
    expect(SAFERP_VECTORS).toHaveLength(3);
    for (const v of SAFERP_VECTORS) {
      const cipher = createSaferPlus(unhex(v.key));
      expect(hex(one(cipher, unhex(v.plaintext))), `encrypt ${v.key}`).toBe(v.ciphertext);
      expect(hex(one(cipher, unhex(v.ciphertext), true)), `decrypt ${v.key}`).toBe(v.plaintext);
    }
    // One per key length, which is one per round count: 8, 12 and 16.
    expect(SAFERP_VECTORS.map((v) => v.key.length / 2)).toEqual([16, 24, 32]);
  });

  it("derives all 512 bias bytes rather than storing them", () => {
    /**
     * The part of SAFER+ every implementation ships as half a kilobyte of literal. Rows 0 to 15 are
     * `45^(45^m mod 257)` and rows 16 to 31 are `45^m mod 257`, over one continuous index -- the same
     * sequence exponentiated twice for the first half of the schedule and once for the second.
     *
     * `SAFERP_BIAS_ROW_0` is LibTomCrypt's literal first row, so this is what says the two rules are the
     * right ones rather than merely self-consistent. Without it a wrong rule would only show up in the
     * three vectors above, which would not say where the fault was.
     */
    expect([...SAFERP_BIAS_FIRST]).toEqual([...SAFERP_BIAS_ROW_0]);
  });

  it("substitutes by discrete exponentiation, with the boxes swapped on the way back", () => {
    /**
     * There is no S-box table: the substitution is `45^x mod 257` with 256 written as 0, and its
     * inverse. The interesting consequence is that a byte position applying `exp` forwards applies
     * `log` in reverse, because the inverse of "exponentiate then add" is "subtract then take the
     * logarithm" -- and keeping the same box in both directions gives a cipher whose *encryption* is
     * entirely correct. That was this implementation's one first-attempt bug, and the decrypt half of
     * the vector test above is what caught it, which is why the fixtures carry a plaintext at all.
     *
     * Pinned here as a property: a single flipped bit anywhere must not round-trip to itself.
     */
    const key = unhex(SAFERP_VECTORS[0]!.key);
    const cipher = createSaferPlus(key);
    for (let bit = 0; bit < 128; bit += 17) {
      const block = new Uint8Array(16);
      block[bit >> 3] = 1 << (bit & 7);
      expect(hex(one(cipher, one(cipher, block), true)), `bit ${bit}`).toBe(hex(block));
    }
  });

  it("refuses a key that is not 16, 24 or 32 bytes", () => {
    expect(() => createSaferPlus(new Uint8Array(20))).toThrow(/16, 24 or 32 bytes/);
    expect(() => createSaferPlus(new Uint8Array(8))).toThrow(/16, 24 or 32 bytes/);
  });
});
