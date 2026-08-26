import { describe, expect, it } from "vitest";
import {
  createHas160,
  createKupyna,
  createPanama,
  createRadioGatun,
  has160,
  kupyna,
  panama,
  radiogatun,
} from "@ocs/algos";
import {
  KUPYNA256_ASCII_VECTORS,
  KUPYNA_HEX_VECTORS,
  RADIOGATUN32_VECTORS,
  RADIOGATUN64_VECTORS,
} from "./beltmill-vectors";

/**
 * RadioGatun, Panama, Kupyna and HAS-160 -- four hashes with no oracle anywhere in this tree.
 *
 * OpenSSL implements none of them and no dependency here does either, so published vectors are all
 * there is. What stands behind each is named rather than left implied:
 *
 *  - **RadioGatun** gets the Keccak team's own 39 vectors per width, whole rather than sliced: the set
 *    runs from the empty string to 2000 characters and costs 15 KB, which removes any question about
 *    which lengths were covered. Both widths are the same implementation with different rotation
 *    amounts, so agreement at both is agreement about the rotation table.
 *  - **Panama** gets its designers' four, including the million-'a' case -- and that one matters here
 *    more than usual, since Panama's buffer is 32 stages deep and a short message never fills it.
 *  - **Kupyna** gets seventeen from DSTU 7564's annex across all three sizes. Its S-boxes and its
 *    MixColumns are *Kalyna's*, already pinned by that cipher's own vectors, so a failure here points at
 *    the mode rather than at a table.
 *  - **HAS-160** gets seven from RHash's suite, which cites randombit.net's published set and Jacksum as
 *    independent checks.
 */

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const unhex = (text: string): Uint8Array =>
  text === "" ? new Uint8Array(0) : Uint8Array.from(text.match(/../g)!.map((p) => parseInt(p, 16)));

const ascii = (text: string): Uint8Array => {
  // These sources publish ASCII messages, and every one is in the 7-bit range.
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
};

interface Hasher {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

/**
 * Streaming has to agree with one-shot at every length in `lengths`, in ten chunk sizes.
 *
 * The default sweep is every length to 400, which is what a fast hash can afford. Kupyna passes a
 * shorter list: it is `bigint` throughout with a 14-round double permutation per block, so the full
 * sweep sat at 4.7 seconds against vitest's 5-second limit -- a test that fails on a slow machine and
 * passes on a fast one is worse than a smaller test that always means the same thing. The list it passes
 * still straddles both of its block sizes.
 */
function checkStreaming(
  label: string,
  create: () => Hasher,
  oneShot: (m: Uint8Array) => Uint8Array,
  lengths?: readonly number[],
): void {
  for (const len of lengths ?? Array.from({ length: 401 }, (_, i) => i)) {
    const message = new Uint8Array(len);
    for (let i = 0; i < len; i++) message[i] = (i * 11 + 5) & 0xff;
    const want = hex(oneShot(message));
    for (const chunk of [1, 7, 31, 32, 33, 63, 64, 155, 156, 157]) {
      const h = create();
      for (let off = 0; off < len; off += chunk) {
        h.update(message.subarray(off, Math.min(off + chunk, len)));
      }
      expect(hex(h.digest()), `${label} at ${len} bytes in ${chunk}-byte chunks`).toBe(want);
    }
  }
}

describe("RadioGatun", () => {
  it("reproduces every published vector at both widths", () => {
    for (const [bits, vectors] of [
      [32, RADIOGATUN32_VECTORS],
      [64, RADIOGATUN64_VECTORS],
    ] as const) {
      expect(vectors.length, `RadioGatun[${bits}] fixture`).toBe(39);
      for (const v of vectors) {
        expect(hex(radiogatun(bits, ascii(v.message))), `RadioGatun[${bits}] over ${v.message.length} bytes`).toBe(
          v.digest,
        );
      }
    }
  });

  /**
   * The two widths are different functions, and the fixture proves it -- but so does this, directly.
   *
   * They share every line of code except the word size, and the rotation amounts are the triangular
   * numbers reduced by it. A version that reduced by 32 in both would be correct at 32 bits and wrong at
   * 64, with nothing else to notice.
   */
  it("gives unrelated digests at the two widths", () => {
    const message = ascii("belt and mill");
    expect(hex(radiogatun(32, message))).not.toBe(hex(radiogatun(64, message)));
  });

  it("streams identically to the one-shot form", () => {
    // The 156-byte rate is what the odd chunk sizes above are there for.
    checkStreaming("RadioGatun[32]", () => createRadioGatun(32), (m) => radiogatun(32, m));
    checkStreaming("RadioGatun[64]", () => createRadioGatun(64), (m) => radiogatun(64, m));
  });
});

describe("Panama", () => {
  /** The designers' own values, as sphlib's `test_panama.c` carries them. */
  const VECTORS: readonly { message: string; digest: string }[] = [
    { message: "", digest: "aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b" },
    { message: "T", digest: "049d698307d8541f22870dfa0a551099d3d02bc6d57c610a06a4585ed8d35ff8" },
    {
      message: "The quick brown fox jumps over the lazy dog",
      digest: "5f5ca355b90ac622b0aa7e654ef5f27e9e75111415b48b8afe3add1c6b89cba1",
    },
  ];

  it("reproduces every published vector", () => {
    for (const v of VECTORS) {
      expect(hex(panama(ascii(v.message))), JSON.stringify(v.message)).toBe(v.digest);
    }
  });

  /**
   * A million 'a's, and this is the one vector that exercises the buffer.
   *
   * Panama's buffer is 32 stages of 8 words -- a kilobyte of state that a short message never fills, so
   * the three vectors above all finish before it wraps. Only a long input reaches the stage where the
   * buffer update reads what it wrote 32 blocks earlier.
   */
  it("reproduces the million-a vector, which is the only one that fills the buffer", () => {
    expect(hex(panama(new Uint8Array(1000000).fill(0x61)))).toBe(
      "af9c66fb6058e2232a5dfba063ee14b0f86f0e334e165812559435464dd9bb60",
    );
  });

  it("streams identically to the one-shot form", () => {
    checkStreaming("Panama", createPanama, panama);
  });
});

describe("Kupyna", () => {
  it("reproduces every published vector at all three sizes", () => {
    const sizes = new Set<number>();
    for (const v of KUPYNA_HEX_VECTORS) {
      // A few entries in the source file are MAC vectors at a different width; skip those.
      if (v.digest.length !== v.size / 4) continue;
      sizes.add(v.size);
      expect(
        hex(kupyna(v.size as 256 | 384 | 512, unhex(v.inputHex))),
        `Kupyna-${v.size} over ${v.inputHex.length / 2} bytes`,
      ).toBe(v.digest);
    }
    expect([...sizes].sort((a, b) => a - b)).toEqual([256, 384, 512]);
  });

  it("reproduces the ASCII vectors at 256 bits", () => {
    expect(KUPYNA256_ASCII_VECTORS.length).toBeGreaterThanOrEqual(4);
    for (const v of KUPYNA256_ASCII_VECTORS) {
      expect(hex(kupyna(256, ascii(v.message))), JSON.stringify(v.message.slice(0, 20))).toBe(v.digest);
    }
  });

  /**
   * The 384- and 512-bit forms share a state and a round count; only the output width differs.
   *
   * So 384 *is* a truncation of 512 -- the last six columns of the same eight -- and 256 is not, because
   * it runs a different permutation. Both halves are asserted, since the hash family's `truncation` flag
   * has to be right about this and someone truncating by hand needs to know.
   */
  it("truncates 512 to 384 and does not truncate to 256", () => {
    const message = ascii("Kupyna truncation");
    const at512 = hex(kupyna(512, message));
    const at384 = hex(kupyna(384, message));
    const at256 = hex(kupyna(256, message));
    // 384 takes the *last* six columns of the state, so it is the tail of the 512-bit digest.
    expect(at512.slice(at512.length - at384.length)).toBe(at384);
    expect(at512).not.toContain(at256);
  });

  it("streams identically to the one-shot form", () => {
    /**
     * Both block sizes straddled: 64 bytes for Kupyna-256 and 128 for the other two, plus the twelve-byte
     * length field's own boundary at 52 and 116 -- the offsets where a message forces an extra block.
     */
    const lengths = [0, 1, 51, 52, 53, 63, 64, 65, 115, 116, 117, 127, 128, 129, 191, 192, 193, 255, 256];
    for (const bits of [256, 384, 512] as const) {
      checkStreaming(`Kupyna-${bits}`, () => createKupyna(bits), (m) => kupyna(bits, m), lengths);
    }
  });
});

describe("HAS-160", () => {
  /**
   * RHash's own set, which cites randombit.net's published vectors and Jacksum as cross-checks.
   *
   * The `"a"` value is worth a note: a *remembered* digest ending `6e830dbf` is two bytes from the real
   * one and would pass a review. It was fetched, not recalled -- the same discipline the IDEA note in
   * `CLAUDE.md` records.
   */
  const VECTORS: readonly { message: string; digest: string }[] = [
    { message: "", digest: "307964ef34151d37c8047adec7ab50f4ff89762d" },
    { message: "a", digest: "4872bcbc4cd0f0a9dc7c2f7045e5b43b6c830db8" },
    { message: "abc", digest: "975e810488cf2a3d49838478124afce4b1c78804" },
    { message: "message digest", digest: "2338dbc8638d31225f73086246ba529f96710bc6" },
    {
      message: "abcdefghijklmnopqrstuvwxyz",
      digest: "596185c9ab6703d0d0dbb98702bc0f5729cd1d3c",
    },
    {
      message: "The quick brown fox jumps over the lazy dog",
      digest: "abe2b8c711f9e8579aa8eb40757a27b4ef14a7ea",
    },
  ];

  it("reproduces every published vector", () => {
    for (const v of VECTORS) {
      expect(hex(has160(ascii(v.message))), JSON.stringify(v.message)).toBe(v.digest);
    }
  });

  it("reproduces the million-a vector", () => {
    expect(hex(has160(new Uint8Array(1000000).fill(0x61)))).toBe(
      "d6ad6f0608b878da9b87999c2525cc84f4c9f18d",
    );
  });

  it("streams identically to the one-shot form", () => {
    checkStreaming("HAS-160", createHas160, has160);
  });
});
