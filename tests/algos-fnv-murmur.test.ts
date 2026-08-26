/**
 * FNV, joaat and MurmurHash3, against PHP's own expectations.
 *
 * These four families exist in this repo because PHP's `hash_algos()` offers them and people arrive
 * wanting to reproduce a value from a PHP application, a Cassandra token or a game-engine asset id.
 * PHP is therefore the reference, and `tests/php-hash-vectors.ts` carries what it produces --
 * extracted from `ext/hash/tests/hash_copy_001.phpt`, which enumerates every registered algorithm.
 *
 * The dedicated per-algorithm test files in php-src are used too, where they add messages the copy
 * test does not cover: `murmurhash3.phpt` for the three Murmur variants and `joaat.phpt` for Jenkins.
 */
import { describe, expect, it } from "vitest";
import { createFnv, createJoaat, createMurmur3, fnv, joaat, murmur3 } from "@ocs/algos";
import { PHP_HASH_VECTORS, PHP_MESSAGE_1, PHP_MESSAGE_2 } from "./php-hash-vectors";

const fromHex = (hex: string) =>
  hex === ""
    ? new Uint8Array(0)
    : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const ascii = (text: string) => new TextEncoder().encode(text);

const phpVector = (algo: string) => {
  const found = PHP_HASH_VECTORS.find((v) => v.algo === algo);
  if (!found) throw new Error(`no PHP vector for ${algo}`);
  return found;
};

describe("FNV", () => {
  const VARIANTS = ["fnv132", "fnv1a32", "fnv164", "fnv1a64"] as const;

  it("matches PHP for both messages", () => {
    for (const variant of VARIANTS) {
      const vector = phpVector(variant);
      expect(toHex(fnv(fromHex(PHP_MESSAGE_1), variant)), `${variant} first`).toBe(vector.first);
      expect(toHex(fnv(fromHex(PHP_MESSAGE_2), variant)), `${variant} second`).toBe(vector.second);
    }
  });

  it("reproduces the published offset basis for the empty input", () => {
    // FNV of nothing is the offset basis itself, which is the one value in the specification that
    // needs no computation -- and the one an implementation with a wrong constant fails immediately.
    expect(toHex(fnv(new Uint8Array(0), "fnv132"))).toBe("811c9dc5");
    expect(toHex(fnv(new Uint8Array(0), "fnv1a32"))).toBe("811c9dc5");
    expect(toHex(fnv(new Uint8Array(0), "fnv164"))).toBe("cbf29ce484222325");
    expect(toHex(fnv(new Uint8Array(0), "fnv1a64"))).toBe("cbf29ce484222325");
  });

  it("distinguishes FNV-1 from FNV-1a", () => {
    // Same bytes, two operation orders, two different answers. A single-byte input is enough.
    const message = ascii("a");
    expect(toHex(fnv(message, "fnv132"))).not.toBe(toHex(fnv(message, "fnv1a32")));
    expect(toHex(fnv(message, "fnv164"))).not.toBe(toHex(fnv(message, "fnv1a64")));
  });

  it("streams to the same value as one shot", () => {
    const message = fromHex(PHP_MESSAGE_2);
    for (const variant of VARIANTS) {
      const expected = toHex(fnv(message, variant));
      for (const size of [1, 3, 8, 61]) {
        const h = createFnv(variant);
        for (let at = 0; at < message.length; at += size) {
          h.update(message.subarray(at, Math.min(at + size, message.length)));
        }
        expect(toHex(h.digest()), `${variant} in ${size}s`).toBe(expected);
      }
    }
  });
});

describe("Jenkins one-at-a-time", () => {
  it("matches PHP for both messages", () => {
    const vector = phpVector("joaat");
    expect(toHex(joaat(fromHex(PHP_MESSAGE_1)))).toBe(vector.first);
    expect(toHex(joaat(fromHex(PHP_MESSAGE_2)))).toBe(vector.second);
  });

  it("matches the vectors in php-src's joaat.phpt", () => {
    // Those three, verbatim: PHP's own dedicated test for this algorithm.
    expect(toHex(joaat(ascii("hello world")))).toBe("3e4a5a57");
    expect(toHex(joaat(ascii("a")))).toBe("ca2e9442");
    expect(toHex(joaat(ascii("aa")))).toBe("7081738e");
  });

  it("returns zero for an empty input and for zero bytes, which is not a bug", () => {
    /**
     * Genuinely zero: the state starts at 0, and a 0x00 byte leaves it there because `h += h << 10`
     * and `h ^= h >>> 6` are both fixed at zero, after which the final avalanche maps 0 to 0. Worth
     * pinning, because it looks exactly like an implementation that forgot to run.
     */
    expect(toHex(joaat(new Uint8Array(0)))).toBe("00000000");
    expect(toHex(joaat(Uint8Array.of(0)))).toBe("00000000");
    expect(toHex(joaat(Uint8Array.of(0, 0)))).toBe("00000000");
    expect(toHex(joaat(Uint8Array.of(1)))).not.toBe("00000000");
  });

  it("streams to the same value as one shot", () => {
    const message = fromHex(PHP_MESSAGE_2);
    const expected = toHex(joaat(message));
    for (const size of [1, 5, 17]) {
      const h = createJoaat();
      for (let at = 0; at < message.length; at += size) {
        h.update(message.subarray(at, Math.min(at + size, message.length)));
      }
      expect(toHex(h.digest()), `chunks of ${size}`).toBe(expected);
    }
  });
});

describe("MurmurHash3", () => {
  const VARIANTS = ["murmur3a", "murmur3c", "murmur3f"] as const;

  it("matches PHP for both messages", () => {
    for (const variant of VARIANTS) {
      const vector = phpVector(variant);
      expect(toHex(murmur3(fromHex(PHP_MESSAGE_1), variant)), `${variant} first`).toBe(
        vector.first,
      );
      expect(toHex(murmur3(fromHex(PHP_MESSAGE_2), variant)), `${variant} second`).toBe(
        vector.second,
      );
    }
  });

  it("matches the vectors in php-src's murmurhash3.phpt", () => {
    expect(toHex(murmur3(ascii("foo"), "murmur3a"))).toBe("f6a5c420");
    expect(toHex(murmur3(ascii("Two hashes meet in a bar"), "murmur3c"))).toBe(
      "8036c2707453c6f37348142be7eaf75c",
    );
    expect(toHex(murmur3(ascii("hash me!"), "murmur3c"))).toBe("c7009299985a5627a9280372a9280372");
    expect(toHex(murmur3(ascii("Two hashes meet in a bar"), "murmur3f"))).toBe(
      "40256ed26fa6ece7785092ed33c8b659",
    );
    expect(toHex(murmur3(ascii("hash me!"), "murmur3f"))).toBe("c43668294e89db0ba5772846e5804467");
    expect(toHex(murmur3(ascii("hello there"), "murmur3a"))).toBe("6440964d");
    expect(toHex(murmur3(ascii("hello there"), "murmur3c"))).toBe(
      "2bcadca212d62deb69712a721e593089",
    );
    expect(toHex(murmur3(ascii("hello there"), "murmur3f"))).toBe(
      "81514cc240f57a165c95eb63f9c0eedf",
    );
  });

  it("gives three different answers, because they are three functions", () => {
    // x86_128 and x64_128 are not two spellings of one 128-bit Murmur; they differ by design.
    const message = ascii("murmur");
    const digests = VARIANTS.map((v) => toHex(murmur3(message, v)));
    expect(new Set(digests).size).toBe(3);
    expect(digests[1]).not.toBe(digests[2]);
  });

  it("streams to the same value as one shot, at every split around the block", () => {
    /**
     * Murmur's block step cannot be resumed mid-block, so the implementation buffers -- and the
     * splits that catch a mistake are the ones landing on and just past the 4- and 16-byte block
     * sizes. PHP's own test asserts the same property through `hash_update`, which is where the
     * carry-based reference implementation earns its complexity.
     */
    const message = fromHex(PHP_MESSAGE_2);
    for (const variant of VARIANTS) {
      const expected = toHex(murmur3(message, variant));
      for (const size of [1, 3, 4, 5, 15, 16, 17, 32, 61]) {
        const h = createMurmur3(variant);
        for (let at = 0; at < message.length; at += size) {
          h.update(message.subarray(at, Math.min(at + size, message.length)));
        }
        expect(toHex(h.digest()), `${variant} in ${size}s`).toBe(expected);
      }
    }
  });

  it("handles every tail length, which is where the partial-block path lives", () => {
    // Lengths 0 to 20 cover an empty input, every partial tail of both block sizes, and one full
    // block followed by a fresh tail.
    for (const variant of VARIANTS) {
      for (let n = 0; n <= 20; n++) {
        const message = new Uint8Array(n);
        for (let i = 0; i < n; i++) message[i] = (i * 13 + 7) & 0xff;
        const expected = toHex(murmur3(message, variant));
        const h = createMurmur3(variant);
        for (let at = 0; at < n; at++) h.update(message.subarray(at, at + 1));
        expect(toHex(h.digest()), `${variant} at ${n}`).toBe(expected);
      }
    }
  });
});
