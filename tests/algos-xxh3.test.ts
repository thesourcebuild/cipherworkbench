import { expect, it } from "vitest";
import { createXXHash3, createXXHash128 } from "hash-wasm";
import { createXxh3_64, createXxh3_128, xxh3_64Bytes, xxh3_128Bytes } from "@ocs/algos";

/**
 * XXH3-64 and XXH3-128, checked against the reference C by way of `hash-wasm`.
 *
 * These two have no quotable document vector, and the reason is worth stating rather than glossing:
 * the xxHash project publishes its expected values as a 4.5 MB *generated* C header keyed to a
 * PRNG-filled buffer, not as a table anyone can cite a line of. So the guarantee here is different
 * in form and stronger in coverage — agreement with the reference implementation across:
 *
 *  - **every** length from 0 to 600, which crosses all four of XXH3's algorithm boundaries
 *    (16, 128, 240) and enters the long path;
 *  - lengths straddling the 1024-byte block boundary, up to 5000 bytes;
 *  - four seeds, including one that exercises the long path's derived secret;
 *  - 320 combinations of input length and chunk size on the streaming path.
 *
 * `hash-wasm` compiles the reference C, so this is agreement with the reference rather than with a
 * second opinion. `tests/vectors.ts`'s `NO_PUBLISHED_VECTOR` records the exemption.
 *
 * Two real bugs were caught here. The seeded long path needs a *derived* secret while the short
 * paths take the seed directly — get that split wrong and short inputs stay correct. And the
 * streaming path must leave at least one byte unbuffered per update: consuming whole 256-byte
 * buffers looks equivalent and double-counts the final stripe for every input whose length is an
 * exact multiple of 256.
 */

const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const data = (n: number) => {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = (i * 37 + 11) & 0xff;
  return out;
};

it("XXH3-64 matches hash-wasm at every length 0..600", async () => {
  const oracle = await createXXHash3();
  const bad: string[] = [];
  for (let n = 0; n <= 600; n++) {
    const input = data(n);
    oracle.init();
    oracle.update(input);
    const want = oracle.digest("hex");
    const got = hex(xxh3_64Bytes(input));
    if (got !== want) bad.push(`len ${n}: got ${got} want ${want}`);
  }
  console.log("XXH3-64 mismatches:", bad.length, bad.slice(0, 6).join(" | "));
  expect(bad.slice(0, 6)).toEqual([]);
});

it("XXH3-128 matches hash-wasm at every length 0..600", async () => {
  const oracle = await createXXHash128();
  const bad: string[] = [];
  for (let n = 0; n <= 600; n++) {
    const input = data(n);
    oracle.init();
    oracle.update(input);
    const want = oracle.digest("hex");
    const got = hex(xxh3_128Bytes(input));
    if (got !== want) bad.push(`len ${n}: got ${got} want ${want}`);
  }
  console.log("XXH3-128 mismatches:", bad.length, bad.slice(0, 6).join(" | "));
  expect(bad.slice(0, 6)).toEqual([]);
});

it("matches across the block boundary and beyond", async () => {
  const o64 = await createXXHash3();
  const o128 = await createXXHash128();
  const bad: string[] = [];
  // 1024 is the default block size, so these straddle one, two and three blocks.
  const lengths = [
    1000, 1023, 1024, 1025, 1087, 1088, 1089, 2047, 2048, 2049, 3072, 4096, 5000,
  ];
  for (const n of lengths) {
    const input = data(n);
    o64.init();
    o64.update(input);
    const w64 = o64.digest("hex");
    const g64 = hex(xxh3_64Bytes(input));
    if (g64 !== w64) bad.push(`64/len ${n}: ${g64} vs ${w64}`);
    o128.init();
    o128.update(input);
    const w128 = o128.digest("hex");
    const g128 = hex(xxh3_128Bytes(input));
    if (g128 !== w128) bad.push(`128/len ${n}: ${g128} vs ${w128}`);
  }
  console.log("multi-block mismatches:", bad.length, bad.slice(0, 4).join(" | "));
  expect(bad.slice(0, 4)).toEqual([]);
});

it("matches with a seed, across every path", async () => {
  const bad: string[] = [];
  const seeds = [1n, 0x9e3779b1n, 0xdeadbeefcafebaben, 0xffffffffffffffffn];
  for (const seed of seeds) {
    const o64 = await createXXHash3(0, Number(seed & 0xffffffffn));
    void o64;
    for (const n of [0, 1, 5, 12, 20, 100, 200, 300, 1100]) {
      const input = data(n);
      // hash-wasm takes the seed as two 32-bit halves (low, high).
      const low = Number(seed & 0xffffffffn);
      const high = Number((seed >> 32n) & 0xffffffffn);
      const h64 = await createXXHash3(low, high);
      h64.init();
      h64.update(input);
      const w = h64.digest("hex");
      const g = hex(xxh3_64Bytes(input, seed));
      if (g !== w) bad.push(`64/seed ${seed}/len ${n}: ${g} vs ${w}`);

      const h128 = await createXXHash128(low, high);
      h128.init();
      h128.update(input);
      const w2 = h128.digest("hex");
      const g2 = hex(xxh3_128Bytes(input, seed));
      if (g2 !== w2) bad.push(`128/seed ${seed}/len ${n}: ${g2} vs ${w2}`);
    }
  }
  console.log("seeded mismatches:", bad.length, bad.slice(0, 4).join(" | "));
  expect(bad.slice(0, 4)).toEqual([]);
});

it("streaming equals one-shot across lengths and chunkings", () => {
  const bad: string[] = [];
  const chunkSizes = [1, 7, 63, 64, 65, 100, 255, 256, 257, 1024];
  const lengths = [
    0, 1, 16, 17, 100, 240, 241, 256, 257, 300, 512, 1023, 1024, 1025, 2048, 3000,
  ];
  for (const length of lengths) {
    const input = data(length);
    for (const chunk of chunkSizes) {
      for (const [label, make, oneShot] of [
        ["64", createXxh3_64, xxh3_64Bytes],
        ["128", createXxh3_128, xxh3_128Bytes],
      ] as const) {
        const h = make();
        for (let off = 0; off < length; off += chunk) {
          h.update(input.subarray(off, Math.min(off + chunk, length)));
        }
        const got = hex(h.digest());
        const want = hex(oneShot(input));
        if (got !== want) bad.push(`${label}/len ${length}/chunk ${chunk}`);
      }
    }
  }
  console.log("streaming mismatches:", bad.length, bad.slice(0, 6).join(" | "));
  expect(bad.slice(0, 6)).toEqual([]);
});

it("digest() is repeatable and does not consume the state", () => {
  const input = data(5000);
  const h = createXxh3_64();
  h.update(input);
  expect(hex(h.digest())).toBe(hex(h.digest()));
  expect(hex(h.digest())).toBe(hex(xxh3_64Bytes(input)));
});

it("streaming a large input matches hash-wasm", async () => {
  const oracle = await createXXHash3();
  const input = data(100_000);
  oracle.init();
  oracle.update(input);
  const h = createXxh3_64();
  for (let off = 0; off < input.length; off += 4096) h.update(input.subarray(off, off + 4096));
  expect(hex(h.digest())).toBe(oracle.digest("hex"));
});
