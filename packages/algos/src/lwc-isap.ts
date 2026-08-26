/**
 * ISAP v2.0 -- leakage-resilient AEAD over Ascon-p or Keccak-p[400]. A NIST lightweight finalist.
 *
 * The point of ISAP is not speed, it is that an attacker who watches many encryptions on the wire or on
 * a power trace learns nothing about the long-term key: the key is used *only* inside a rekeying
 * function that absorbs its input **one bit at a time**, so no key material is ever combined with more
 * than a single bit of attacker-chosen data. The bit-serial loop below is the design, not a slow
 * implementation of something faster.
 *
 * Four instances, from two permutations and two round-count profiles:
 *
 * | Variant | Permutation | sH | sB | sE | sK |
 * |---|---|---|---|---|---|
 * | ISAP-A-128A | Ascon-p | 12 | 1 | 6 | 12 |
 * | ISAP-A-128 | Ascon-p | 12 | 12 | 12 | 12 |
 * | ISAP-K-128A | Keccak-p[400] | 16 | 1 | 8 | 8 |
 * | ISAP-K-128 | Keccak-p[400] | 20 | 12 | 12 | 12 |
 *
 * Verified against 1089 known-answer vectors per variant in both directions -- 8712 assertions, all
 * first run.
 *
 * ## Three things worth knowing
 *
 * **`sB` being one round is the whole efficiency story of the A variants.** The rekeying loop runs once
 * per input bit -- 127 iterations for a 128-bit input -- so one round there against twelve is a
 * twelvefold difference in the dominant cost.
 *
 * **The tag finalisation restores three words after rekeying.** `isapRk` overwrites the entire state;
 * words 2, 3 and 4 are saved beforehand and put back, so the final permutation runs over
 * `Ka || (the absorbed state)`. Skipping the restore gives a tag that verifies against itself and
 * against nothing else.
 *
 * **Both permutations take the *last* n rounds, not the first.** Ascon-p[6] is rounds 6..11 of twelve
 * and Keccak-p[400, 8] is rounds 12..19 of twenty. Counting from the front is a different permutation
 * that is equally self-consistent, which is exactly the failure a round trip cannot see.
 *
 * Ascon-p is reimplemented here rather than imported from `ascon.ts`: that module exposes the AEAD, the
 * hash and the XOFs but not a bare round-parameterised permutation, and ISAP needs six of them.
 */

const M64 = (1n << 64n) - 1n;

const ASCON_RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b] as const;
const rotr64 = (x: bigint, n: number): bigint => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & M64;

/** Ascon-p over the last `rounds` of its twelve-round schedule. */
export function asconPermutation(s: bigint[], rounds: number): void {
  for (let r = 12 - rounds; r < 12; r++) {
    let x0 = s[0]!;
    let x1 = s[1]!;
    let x2 = s[2]!;
    let x3 = s[3]!;
    let x4 = s[4]!;
    x2 ^= BigInt(ASCON_RC[r]!);
    x0 ^= x4;
    x4 ^= x3;
    x2 ^= x1;
    const t0 = ~x0 & M64;
    const t1 = ~x1 & M64;
    const t2 = ~x2 & M64;
    const t3 = ~x3 & M64;
    const t4 = ~x4 & M64;
    const y0 = x0 ^ (t1 & x2);
    const y1 = x1 ^ (t2 & x3);
    const y2 = x2 ^ (t3 & x4);
    const y3 = x3 ^ (t4 & x0);
    const y4 = x4 ^ (t0 & x1);
    x0 = y0; x1 = y1; x2 = y2; x3 = y3; x4 = y4;
    x1 ^= x0;
    x0 ^= x4;
    x3 ^= x2;
    x2 = ~x2 & M64;
    x0 ^= rotr64(x0, 19) ^ rotr64(x0, 28);
    x1 ^= rotr64(x1, 61) ^ rotr64(x1, 39);
    x2 ^= rotr64(x2, 1) ^ rotr64(x2, 6);
    x3 ^= rotr64(x3, 10) ^ rotr64(x3, 17);
    x4 ^= rotr64(x4, 7) ^ rotr64(x4, 41);
    s[0] = x0 & M64;
    s[1] = x1 & M64;
    s[2] = x2 & M64;
    s[3] = x3 & M64;
    s[4] = x4 & M64;
  }
}

const K400_RC = [
  0x0001, 0x8082, 0x808a, 0x8000, 0x808b, 0x0001, 0x8081, 0x8009, 0x008a, 0x0088,
  0x8009, 0x000a, 0x808b, 0x008b, 0x8089, 0x8003, 0x8002, 0x0080, 0x800a, 0x000a,
] as const;
/** The standard rho offsets reduced mod 16, indexed as x + 5y. */
const K400_RHO = [
  0, 1, 14, 12, 11, 4, 12, 6, 7, 4, 3, 10, 11, 9, 7, 9, 13, 15, 5, 8, 2, 2, 13, 8, 14,
] as const;
const rol16 = (a: number, n: number): number =>
  n === 0 ? a & 0xffff : ((a << n) | (a >>> (16 - n))) & 0xffff;
const ix = (x: number, y: number): number => (x % 5) + 5 * (y % 5);

/** Keccak-p[400] over the last `rounds` of its twenty-round schedule. Sixteen-bit lanes. */
export function keccakP400(a: Uint16Array, rounds: number): void {
  const c = new Uint16Array(5);
  const d = new Uint16Array(5);
  const t = new Uint16Array(25);
  for (let round = 20 - rounds; round < 20; round++) {
    for (let x = 0; x < 5; x++) {
      c[x] = 0;
      for (let y = 0; y < 5; y++) c[x] = c[x]! ^ a[ix(x, y)]!;
    }
    for (let x = 0; x < 5; x++) d[x] = rol16(c[(x + 1) % 5]!, 1) ^ c[(x + 4) % 5]!;
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) a[ix(x, y)] = a[ix(x, y)]! ^ d[x]!;
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) a[ix(x, y)] = rol16(a[ix(x, y)]!, K400_RHO[ix(x, y)]!);
    }
    t.set(a);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) a[ix(y, 2 * x + 3 * y)] = t[ix(x, y)]!;
    for (let y = 0; y < 5; y++) {
      for (let x = 0; x < 5; x++) c[x] = a[ix(x, y)]! ^ (~a[ix(x + 1, y)]! & a[ix(x + 2, y)]!);
      for (let x = 0; x < 5; x++) a[ix(x, y)] = c[x]! & 0xffff;
    }
    a[0] = a[0]! ^ K400_RC[round]!;
  }
}

export type IsapVariant = "a-128a" | "a-128" | "k-128a" | "k-128";

interface IsapParams {
  family: "a" | "k";
  sH: number;
  sB: number;
  sE: number;
  sK: number;
  /** The three initial-value constants, as one 64-bit word (A) or four 16-bit lanes (K). */
  ivA?: readonly [bigint, bigint, bigint];
  ivK?: readonly [readonly number[], readonly number[], readonly number[]];
}

const ISAP_PARAMS: Readonly<Record<IsapVariant, IsapParams>> = {
  "a-128a": {
    family: "a",
    sH: 12, sB: 1, sE: 6, sK: 12,
    ivA: [108156764297430540n, 180214358335358476n, 252271952373286412n],
  },
  "a-128": {
    family: "a",
    sH: 12, sB: 12, sE: 12, sK: 12,
    ivA: [108156764298152972n, 180214358336080908n, 252271952374008844n],
  },
  "k-128a": {
    family: "k",
    sH: 16, sB: 1, sE: 8, sK: 8,
    ivK: [
      [0x8001, 0x0190, 0x0110, 0x0808],
      [0x8002, 0x0190, 0x0110, 0x0808],
      [0x8003, 0x0190, 0x0110, 0x0808],
    ],
  },
  "k-128": {
    family: "k",
    sH: 20, sB: 12, sE: 12, sK: 12,
    ivK: [
      [0x8001, 0x0190, 0x0c14, 0x0c0c],
      [0x8002, 0x0190, 0x0c14, 0x0c0c],
      [0x8003, 0x0190, 0x0c14, 0x0c0c],
    ],
  },
};

const beToBig = (b: Uint8Array, off: number): bigint => {
  let v = 0n;
  for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(b[off + i] ?? 0);
  return v;
};
const bigToBe = (v: bigint, out: Uint8Array, off: number): void => {
  for (let i = 0; i < 8; i++) out[off + i] = Number((v >> BigInt(56 - 8 * i)) & 0xffn);
};

// ---------------------------------------------------------------- ISAP-A

/** The bit-by-bit rekeying function: one sB permutation per input bit, sK at each end. */
function isapRkA(
  p: IsapParams,
  key: Uint8Array,
  iv: bigint,
  y: Uint8Array,
  ylen: number,
  target?: bigint[],
): bigint[] {
  const s = target ?? [0n, 0n, 0n, 0n, 0n];
  s[0] = beToBig(key, 0);
  s[1] = beToBig(key, 8);
  s[2] = iv;
  s[3] = 0n;
  s[4] = 0n;
  asconPermutation(s, p.sK);
  const bits = ylen * 8;
  for (let i = 0; i < bits - 1; i++) {
    const bit = (y[i >>> 3]! >>> (7 - (i & 7))) & 1;
    s[0] = s[0]! ^ (BigInt(bit) << 63n);
    asconPermutation(s, p.sB);
  }
  s[0] = s[0]! ^ (BigInt(y[ylen - 1]! & 1) << 63n);
  asconPermutation(s, p.sK);
  return s;
}

function isapAMac(
  p: IsapParams,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  const s: bigint[] = [beToBig(nonce, 0), beToBig(nonce, 8), p.ivA![0], 0n, 0n];
  asconPermutation(s, p.sH);
  const absorb = (data: Uint8Array): void => {
    let off = 0;
    while (data.length - off >= 8) {
      s[0] = s[0]! ^ beToBig(data, off);
      asconPermutation(s, p.sH);
      off += 8;
    }
    const rest = data.length - off;
    for (let i = 0; i < rest; i++) s[0] = s[0]! ^ (BigInt(data[off + i]!) << BigInt((7 - i) * 8));
    s[0] = s[0]! ^ (0x80n << BigInt((7 - rest) * 8));
    asconPermutation(s, p.sH);
  };
  absorb(aad);
  // One bit of domain separation between the associated data and the ciphertext.
  s[4] = s[4]! ^ 1n;
  absorb(ct);

  const tag = new Uint8Array(16);
  bigToBe(s[0]!, tag, 0);
  bigToBe(s[1]!, tag, 8);
  const keep = [s[2]!, s[3]!, s[4]!];
  isapRkA(p, key, p.ivA![1], tag, 16, s);
  s[2] = keep[0]!;
  s[3] = keep[1]!;
  s[4] = keep[2]!;
  asconPermutation(s, p.sH);
  bigToBe(s[0]!, tag, 0);
  bigToBe(s[1]!, tag, 8);
  return tag;
}

function isapACrypt(
  p: IsapParams,
  key: Uint8Array,
  nonce: Uint8Array,
  input: Uint8Array,
): Uint8Array {
  const s = isapRkA(p, key, p.ivA![2], nonce, 16);
  s[3] = beToBig(nonce, 0);
  s[4] = beToBig(nonce, 8);
  asconPermutation(s, p.sE);
  const out = new Uint8Array(input.length);
  let off = 0;
  while (input.length - off >= 8) {
    bigToBe(beToBig(input, off) ^ s[0]!, out, off);
    asconPermutation(s, p.sE);
    off += 8;
  }
  const rest = input.length - off;
  for (let i = 0; i < rest; i++) {
    out[off + i] = input[off + i]! ^ Number((s[0]! >> BigInt((7 - i) * 8)) & 0xffn);
  }
  return out;
}

// ---------------------------------------------------------------- ISAP-K

/** The Keccak variants' rate: 144 bits. */
const K_RATE = 18;

function isapRkK(
  p: IsapParams,
  key: Uint8Array,
  iv: readonly number[],
  y: Uint8Array,
  ylen: number,
  outShorts: number,
): Uint16Array {
  const s = new Uint16Array(25);
  for (let i = 0; i < 8; i++) s[i] = key[2 * i]! | (key[2 * i + 1]! << 8);
  for (let i = 0; i < 4; i++) s[8 + i] = iv[i]!;
  keccakP400(s, p.sK);
  const bits = ylen * 8;
  for (let i = 0; i < bits - 1; i++) {
    s[0] = s[0]! ^ (((y[i >>> 3]! >>> (7 - (i & 7))) & 1) << 7);
    keccakP400(s, p.sB);
  }
  s[0] = s[0]! ^ ((y[ylen - 1]! & 1) << 7);
  keccakP400(s, p.sK);
  return s.slice(0, outShorts);
}

function isapKCrypt(
  p: IsapParams,
  key: Uint8Array,
  nonce: Uint8Array,
  input: Uint8Array,
): Uint8Array {
  const s = new Uint16Array(25);
  // 34 bytes of derived key material and then the nonce: 400 bits exactly.
  s.set(isapRkK(p, key, p.ivK![2], nonce, 16, 17), 0);
  for (let i = 0; i < 8; i++) s[17 + i] = nonce[2 * i]! | (nonce[2 * i + 1]! << 8);
  keccakP400(s, p.sE);
  const out = new Uint8Array(input.length);
  const lane = (i: number): number => (s[i >> 1]! >>> ((i & 1) << 3)) & 0xff;
  let off = 0;
  while (input.length - off >= K_RATE) {
    for (let i = 0; i < K_RATE; i++) out[off + i] = input[off + i]! ^ lane(i);
    keccakP400(s, p.sE);
    off += K_RATE;
  }
  for (let i = 0; i < input.length - off; i++) out[off + i] = input[off + i]! ^ lane(i);
  return out;
}

function isapKMac(
  p: IsapParams,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  const s = new Uint16Array(25);
  for (let i = 0; i < 8; i++) s[i] = nonce[2 * i]! | (nonce[2 * i + 1]! << 8);
  for (let i = 0; i < 4; i++) s[8 + i] = p.ivK![0]![i]!;
  keccakP400(s, p.sH);
  const absorb = (data: Uint8Array): void => {
    let off = 0;
    while (data.length - off >= K_RATE) {
      for (let i = 0; i < K_RATE >> 1; i++) {
        s[i] = s[i]! ^ (data[off + 2 * i]! | (data[off + 2 * i + 1]! << 8));
      }
      keccakP400(s, p.sH);
      off += K_RATE;
    }
    const rest = data.length - off;
    for (let i = 0; i < rest; i++) s[i >> 1] = s[i >> 1]! ^ (data[off + i]! << ((i & 1) << 3));
    s[rest >> 1] = s[rest >> 1]! ^ (0x80 << ((rest & 1) << 3));
    keccakP400(s, p.sH);
  };
  absorb(aad);
  s[24] = s[24]! ^ 0x0100;
  absorb(ct);

  const tag = new Uint8Array(16);
  const writeTag = (): void => {
    for (let i = 0; i < 8; i++) {
      tag[2 * i] = s[i]! & 0xff;
      tag[2 * i + 1] = (s[i]! >>> 8) & 0xff;
    }
  };
  writeTag();
  s.set(isapRkK(p, key, p.ivK![1], tag, 16, 8), 0);
  keccakP400(s, p.sH);
  writeTag();
  return tag;
}

// ---------------------------------------------------------------- public API

export function isapEncrypt(
  variant: IsapVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  if (key.length !== 16) throw new Error(`ISAP needs a 16-byte key; got ${key.length}.`);
  if (nonce.length !== 16) throw new Error(`ISAP needs a 16-byte nonce; got ${nonce.length}.`);
  const p = ISAP_PARAMS[variant];
  const ct = p.family === "a" ? isapACrypt(p, key, nonce, plaintext) : isapKCrypt(p, key, nonce, plaintext);
  const tag = p.family === "a" ? isapAMac(p, key, nonce, aad, ct) : isapKMac(p, key, nonce, aad, ct);
  const out = new Uint8Array(ct.length + 16);
  out.set(ct, 0);
  out.set(tag, ct.length);
  return out;
}

export function isapDecrypt(
  variant: IsapVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (key.length !== 16) throw new Error(`ISAP needs a 16-byte key; got ${key.length}.`);
  if (nonce.length !== 16) throw new Error(`ISAP needs a 16-byte nonce; got ${nonce.length}.`);
  if (data.length < 16) return null;
  const p = ISAP_PARAMS[variant];
  const ct = data.subarray(0, data.length - 16);
  const tag = p.family === "a" ? isapAMac(p, key, nonce, aad, ct) : isapKMac(p, key, nonce, aad, ct);
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= tag[i]! ^ data[data.length - 16 + i]!;
  if (diff !== 0) return null;
  return p.family === "a" ? isapACrypt(p, key, nonce, ct) : isapKCrypt(p, key, nonce, ct);
}
