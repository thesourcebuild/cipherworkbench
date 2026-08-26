import { describe, expect, it } from "vitest";
import {
  add64,
  createMd2,
  createMd4,
  createSm3,
  createWhirlpool,
  createXxHash32,
  createXxHash64,
  hex64,
  md2,
  md4,
  mul64,
  rotl64,
  shr64,
  sm3,
  toBigInt,
  u64,
  whirlpool,
  xxhash32,
  xxhash64,
} from "@ocs/algos";

const ascii = (text: string) => new TextEncoder().encode(text);
const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function pseudoRandom(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  let state = seed >>> 0;
  for (let i = 0; i < length; i++) {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out[i] = state & 0xff;
  }
  return out;
}

// ── 64-bit helpers ──────────────────────────────────────────────────────────

describe("u64 arithmetic", () => {
  /**
   * Tested directly because Whirlpool and XXH64 both depend on it and neither would
   * localise a fault here — a wrong multiply shows up as "the digest is wrong", with
   * nothing pointing at which of a hundred lines caused it.
   */
  const check = (fn: (out: ReturnType<typeof u64>) => void, expected: bigint) => {
    const out = u64();
    fn(out);
    expect(toBigInt(out)).toBe(expected & 0xffffffffffffffffn);
  };

  it("adds with carry across the 32-bit boundary", () => {
    check((out) => add64(out, u64(0, 0xffffffff), u64(0, 1)), 0x100000000n);
    check((out) => add64(out, u64(0xffffffff, 0xffffffff), u64(0, 1)), 0n);
    check((out) => add64(out, u64(0x12345678, 0x9abcdef0), u64(0, 0)), 0x123456789abcdef0n);
  });

  it("multiplies without losing precision above 2^53", () => {
    // The case that breaks a naive `a * b` on doubles: both operands large.
    check(
      (out) => mul64(out, u64(0x9e3779b1, 0x85ebca87), u64(0xc2b2ae3d, 0x27d4eb4f)),
      0x9e3779b185ebca87n * 0xc2b2ae3d27d4eb4fn,
    );
    check((out) => mul64(out, u64(0, 0xffffffff), u64(0, 0xffffffff)), 0xfffffffe00000001n);
    check((out) => mul64(out, u64(0xffffffff, 0xffffffff), u64(0, 2)), 0xfffffffffffffffen);
    check((out) => mul64(out, u64(0, 0), u64(0x1234, 0x5678)), 0n);
    // Multiplying by one must be the identity, including across the halves.
    check((out) => mul64(out, u64(0, 1), u64(0x1234, 0x5678)), 0x0000123400005678n);
  });

  it("rotates left across every boundary case", () => {
    const value = u64(0x01234567, 0x89abcdef);
    const big = 0x0123456789abcdefn;
    for (const bits of [0, 1, 7, 31, 32, 33, 63]) {
      const rotated =
        ((big << BigInt(bits)) | (big >> BigInt(64 - (bits || 64)))) & 0xffffffffffffffffn;
      const expected = bits === 0 ? big : rotated;
      check((out) => rotl64(out, value, bits), expected);
    }
  });

  it("shifts right logically", () => {
    const value = u64(0xffffffff, 0xffffffff);
    check((out) => shr64(out, value, 0), 0xffffffffffffffffn);
    check((out) => shr64(out, value, 1), 0x7fffffffffffffffn);
    check((out) => shr64(out, value, 32), 0xffffffffn);
    check((out) => shr64(out, value, 63), 1n);
  });

  it("is safe when the output aliases an input", () => {
    const a = u64(0x11111111, 0x22222222);
    add64(a, a, a);
    expect(toBigInt(a)).toBe((0x1111111122222222n * 2n) & 0xffffffffffffffffn);

    const b = u64(0x01234567, 0x89abcdef);
    rotl64(b, b, 40);
    const expected =
      ((0x0123456789abcdefn << 40n) | (0x0123456789abcdefn >> 24n)) & 0xffffffffffffffffn;
    expect(toBigInt(b)).toBe(expected);
  });

  it("formats as 16 hex characters", () => {
    expect(hex64(u64(0, 1))).toBe("0000000000000001");
    expect(hex64(u64(0xffffffff, 0xffffffff))).toBe("ffffffffffffffff");
  });
});

// ── MD2 ─────────────────────────────────────────────────────────────────────

describe("MD2 — RFC 1319 §A.5 test suite", () => {
  // The complete published suite, verbatim.
  const VECTORS: readonly [string, string][] = [
    ["", "8350e5a3e24c153df2275c9f80692773"],
    ["a", "32ec01ec4a6dac72c0ab96fb34c0b5d1"],
    ["abc", "da853b0d3f88d99b30283a69e6ded6bb"],
    ["message digest", "ab4f496bfb2a530b219ff33031fe06b0"],
    ["abcdefghijklmnopqrstuvwxyz", "4e8ddff3650292ab5a4108c3aa47940b"],
    [
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "da33def2a42df13975352846c30338cd",
    ],
    [
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "d5976f79d83d3a0dc9806c3c66f3efd8",
    ],
  ];

  for (const [input, expected] of VECTORS) {
    it(`MD2("${input.slice(0, 24)}${input.length > 24 ? "…" : ""}")`, () => {
      expect(hex(md2(ascii(input)))).toBe(expected);
    });
  }

  it("streams identically to a single update", () => {
    const input = pseudoRandom(500, 11);
    const oneShot = hex(md2(input));
    // 16-byte blocks, so 15/16/17 straddle the boundary in all three directions.
    for (const chunkSize of [1, 15, 16, 17, 64, 499]) {
      const engine = createMd2();
      for (let o = 0; o < input.length; o += chunkSize) {
        engine.update(input.subarray(o, o + chunkSize));
      }
      expect(hex(engine.digest()), `chunk ${chunkSize}`).toBe(oneShot);
    }
  });

  it("adds a full padding block when the length is already a multiple of 16", () => {
    // MD2's padding is never empty: a 16-byte message gains 16 bytes of 0x10. Getting
    // this wrong makes exactly the aligned lengths wrong.
    expect(hex(md2(new Uint8Array(16)))).not.toBe(hex(md2(new Uint8Array(0))));
    expect(md2(new Uint8Array(16))).toHaveLength(16);
  });

  it("refuses reuse after digest", () => {
    const engine = createMd2();
    engine.update(ascii("a"));
    engine.digest();
    expect(() => engine.update(ascii("b"))).toThrow(/after digest/);
    expect(() => engine.digest()).toThrow(/twice/);
  });
});

// ── MD4 ─────────────────────────────────────────────────────────────────────

describe("MD4 — RFC 1320 §A.5 test suite", () => {
  const VECTORS: readonly [string, string][] = [
    ["", "31d6cfe0d16ae931b73c59d7e0c089c0"],
    ["a", "bde52cb31de33e46245e05fbdbd6fb24"],
    ["abc", "a448017aaf21d8525fc10ae87aa6729d"],
    ["message digest", "d9130a8164549fe818874806e1c7014b"],
    ["abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"],
    [
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
      "043f8582f241db351ce627e153e7f0e4",
    ],
    [
      "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
      "e33b4ddc9c38f2199c3e7b164fcc0536",
    ],
  ];

  for (const [input, expected] of VECTORS) {
    it(`MD4("${input.slice(0, 24)}${input.length > 24 ? "…" : ""}")`, () => {
      expect(hex(md4(ascii(input)))).toBe(expected);
    });
  }

  it("streams identically to a single update", () => {
    const input = pseudoRandom(1000, 12);
    const oneShot = hex(md4(input));
    // 63/64/65 and 55/56/57 straddle the two boundaries that matter: the block size, and
    // the point where the 8-byte length field stops fitting.
    for (const chunkSize of [1, 55, 56, 57, 63, 64, 65, 999]) {
      const engine = createMd4();
      for (let o = 0; o < input.length; o += chunkSize) {
        engine.update(input.subarray(o, o + chunkSize));
      }
      expect(hex(engine.digest()), `chunk ${chunkSize}`).toBe(oneShot);
    }
  });

  it("handles every length around the padding overflow boundary", () => {
    // 56..64 is where the length field no longer fits after the 0x80 and a second block
    // is needed. Each of these must match a fresh one-shot computation.
    for (let length = 50; length <= 70; length++) {
      const input = pseudoRandom(length, length);
      const engine = createMd4();
      engine.update(input);
      expect(hex(engine.digest()), `length ${length}`).toBe(hex(md4(input)));
    }
  });
});

// ── SM3 ─────────────────────────────────────────────────────────────────────

describe("SM3 — GB/T 32905-2016 §5 examples", () => {
  it('SM3("abc") matches the standard\'s first worked example', () => {
    expect(hex(sm3(ascii("abc")))).toBe(
      "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
    );
  });

  it('SM3 of "abcd" repeated 16 times matches the second worked example', () => {
    // 64 bytes — exactly one block, so this also exercises the full-extra-padding-block path.
    expect(hex(sm3(ascii("abcd".repeat(16))))).toBe(
      "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
    );
  });

  it("produces 32 bytes for the empty input", () => {
    expect(sm3(new Uint8Array(0))).toHaveLength(32);
  });

  it("streams identically to a single update", () => {
    const input = pseudoRandom(1000, 13);
    const oneShot = hex(sm3(input));
    for (const chunkSize of [1, 55, 56, 57, 63, 64, 65, 999]) {
      const engine = createSm3();
      for (let o = 0; o < input.length; o += chunkSize) {
        engine.update(input.subarray(o, o + chunkSize));
      }
      expect(hex(engine.digest()), `chunk ${chunkSize}`).toBe(oneShot);
    }
  });

  it("handles every length around the padding overflow boundary", () => {
    for (let length = 50; length <= 70; length++) {
      const input = pseudoRandom(length, length);
      const engine = createSm3();
      engine.update(input);
      expect(hex(engine.digest()), `length ${length}`).toBe(hex(sm3(input)));
    }
  });
});

// ── Whirlpool ───────────────────────────────────────────────────────────────

describe("Whirlpool — ISO/IEC 10118-3 test vectors", () => {
  /**
   * These are the *final* Whirlpool values. WHIRLPOOL-0 and WHIRLPOOL-T — the two
   * superseded drafts, and what the one npm package implements — give entirely different
   * digests, so these vectors are also what confirms the right S-box is in use.
   */
  const VECTORS: readonly [string, string][] = [
    [
      "",
      "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
    ],
    [
      "a",
      "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a",
    ],
    [
      "abc",
      "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
    ],
    [
      "message digest",
      "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e",
    ],
    [
      "abcdefghijklmnopqrstuvwxyz",
      "f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b",
    ],
  ];

  for (const [input, expected] of VECTORS) {
    it(`Whirlpool("${input.slice(0, 24)}${input.length > 24 ? "…" : ""}")`, () => {
      expect(hex(whirlpool(ascii(input)))).toBe(expected);
    });
  }

  it("streams identically to a single update", () => {
    const input = pseudoRandom(500, 14);
    const oneShot = hex(whirlpool(input));
    // 31/32/33 matter here: Whirlpool's length field is 32 bytes, so that is where the
    // padding needs an extra block.
    for (const chunkSize of [1, 31, 32, 33, 63, 64, 65, 499]) {
      const engine = createWhirlpool();
      for (let o = 0; o < input.length; o += chunkSize) {
        engine.update(input.subarray(o, o + chunkSize));
      }
      expect(hex(engine.digest()), `chunk ${chunkSize}`).toBe(oneShot);
    }
  });

  it("handles every length around its 32-byte length field", () => {
    for (let length = 25; length <= 70; length++) {
      const input = pseudoRandom(length, length);
      const engine = createWhirlpool();
      engine.update(input);
      expect(hex(engine.digest()), `length ${length}`).toBe(hex(whirlpool(input)));
    }
  });
});

// ── xxHash ──────────────────────────────────────────────────────────────────

describe("XXH32 — reference vectors", () => {
  const VECTORS: readonly [string, number, string][] = [
    ["", 0, "02cc5d05"],
    ["a", 0, "550d7456"],
    ["abc", 0, "32d153ff"],
    ["heiå", 0, "db5abccc"],
    // 15 and 16 bytes bracket the stripe boundary, so these two are what actually
    // exercise the four-accumulator path against a fixed value.
    ["123456789012345", 0, "da7b17e8"],
    ["1234567890123456", 0, "03bf5152"],
    ["1234567890123456789012345678901", 0, "73e7476c"],
    ["12345678901234567890123456789012", 0, "e0337e4b"],
  ];

  for (const [input, seed, expected] of VECTORS) {
    it(`XXH32("${input}", seed=${seed})`, () => {
      expect(xxhash32(ascii(input), seed).toString(16).padStart(8, "0")).toBe(expected);
    });
  }

  it("takes the short-input branch below 16 bytes and the striped one above", () => {
    // 15/16/17 bracket the branch. All three must agree with a fresh computation, which
    // is the only way a mis-placed branch shows up.
    for (let length = 0; length <= 40; length++) {
      const input = pseudoRandom(length, length + 100);
      const engine = createXxHash32(0);
      engine.update(input);
      expect(engine.digest(), `length ${length}`).toBe(xxhash32(input, 0));
    }
  });

  it("streams identically to a single update", () => {
    const input = pseudoRandom(1000, 15);
    const oneShot = xxhash32(input);
    for (const chunkSize of [1, 3, 15, 16, 17, 32, 999]) {
      const engine = createXxHash32(0);
      for (let o = 0; o < input.length; o += chunkSize) {
        engine.update(input.subarray(o, o + chunkSize));
      }
      expect(engine.digest(), `chunk ${chunkSize}`).toBe(oneShot);
    }
  });

  it("honours the seed", () => {
    expect(xxhash32(ascii("abc"), 0)).not.toBe(xxhash32(ascii("abc"), 1));
  });

  it("returns an unsigned value", () => {
    // The avalanche routinely sets the top bit; a signed result would break every
    // comparison and hex rendering downstream.
    for (let i = 0; i < 200; i++) {
      expect(xxhash32(pseudoRandom(i, i))).toBeGreaterThanOrEqual(0);
    }
  });

  it("emits four big-endian bytes", () => {
    const engine = createXxHash32(0);
    engine.update(ascii("abc"));
    expect(hex(engine.digestBytes())).toBe("32d153ff");
  });
});

describe("XXH64 — reference vectors", () => {
  const VECTORS: readonly [string, number, string][] = [
    ["", 0, "ef46db3751d8e999"],
    ["a", 0, "d24ec4f1a98c6e5b"],
    ["abc", 0, "44bc2cf5ad770999"],
    ["heiå", 0, "b9d3d990d2001a1a"],
    ["123456789012345", 0, "c377d78ade001a3c"],
    ["1234567890123456", 0, "b61c33dc6c59f270"],
    // 31 and 32 bytes bracket XXH64's larger stripe.
    ["1234567890123456789012345678901", 0, "8f367cb873a5376e"],
    ["12345678901234567890123456789012", 0, "40fd1aa52d98274c"],
  ];

  for (const [input, seed, expected] of VECTORS) {
    it(`XXH64("${input}", seed=${seed})`, () => {
      expect(xxhash64(ascii(input), seed).toString(16).padStart(16, "0")).toBe(expected);
    });
  }

  it("takes the short-input branch below 32 bytes and the striped one above", () => {
    for (let length = 0; length <= 80; length++) {
      const input = pseudoRandom(length, length + 200);
      const engine = createXxHash64(0);
      engine.update(input);
      expect(engine.digest(), `length ${length}`).toBe(xxhash64(input, 0));
    }
  });

  it("streams identically to a single update", () => {
    const input = pseudoRandom(2000, 16);
    const oneShot = xxhash64(input);
    // 31/32/33 bracket the stripe; 4 and 8 exercise each tail stage.
    for (const chunkSize of [1, 4, 8, 31, 32, 33, 64, 1999]) {
      const engine = createXxHash64(0);
      for (let o = 0; o < input.length; o += chunkSize) {
        engine.update(input.subarray(o, o + chunkSize));
      }
      expect(engine.digest(), `chunk ${chunkSize}`).toBe(oneShot);
    }
  });

  it("exercises all three tail stages", () => {
    // 8-byte, 4-byte and single-byte tails, in a length that uses all three.
    const input = pseudoRandom(32 + 8 + 4 + 3, 77);
    const engine = createXxHash64(0);
    engine.update(input);
    expect(engine.digest()).toBe(xxhash64(input, 0));
  });

  it("honours a bigint seed", () => {
    expect(xxhash64(ascii("abc"), 0n)).toBe(xxhash64(ascii("abc"), 0));
    expect(xxhash64(ascii("abc"), 0xdeadbeefn)).not.toBe(xxhash64(ascii("abc"), 0n));
  });

  it("stays inside 64 bits", () => {
    for (let i = 0; i < 100; i++) {
      const value = xxhash64(pseudoRandom(i, i + 300));
      expect(value).toBeGreaterThanOrEqual(0n);
      expect(value).toBeLessThanOrEqual(0xffffffffffffffffn);
    }
  });

  it("emits eight big-endian bytes and matching hex", () => {
    const engine = createXxHash64(0);
    engine.update(ascii("abc"));
    expect(hex(engine.digestBytes())).toBe("44bc2cf5ad770999");
    expect(createXxHash64(0)).toBeDefined();
  });

  it("digest() is repeatable and does not consume the state", () => {
    const engine = createXxHash64(0);
    engine.update(ascii("abc"));
    expect(engine.digest()).toBe(engine.digest());
  });
});
