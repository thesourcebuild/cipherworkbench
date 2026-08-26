/**
 * ZUC-128, ZUC-256, HC-128, HC-256, Grain v1 and Grain-128 -- six eSTREAM-era stream ciphers.
 *
 * They are together in one module because they share nothing but a shape: key and IV in, keystream out,
 * XOR with the message. There is no common primitive to factor out -- two are word-oriented software
 * designs, two are bit-oriented hardware designs, and two are LFSR-plus-nonlinear-function -- which is
 * the reason none of the six is a mode of any of the others.
 *
 * All six were verified against Bouncy Castle's test vectors, which trace back to the designers' own
 * documents: the eSTREAM phase-3 papers for HC-128 and HC-256, the Grain submissions, GSMA's
 * `eea3eia3zucv16.pdf` for ZUC-128 and the Chinese Academy of Sciences' own document for ZUC-256. None
 * has an oracle here -- OpenSSL implements none of them -- so `tests/algos-phase2-stream.test.ts` is
 * published vectors alone, and that is why every one of the six carries more than one.
 *
 * ## Two things this module does the same way everywhere
 *
 * **Every intermediate is coerced back to 32 bits.** Java's `int` wraps; a JavaScript number does not.
 * HC-128 and HC-256 are addition-heavy -- HC-256's `step` does five additions per word -- and a single
 * missing `| 0` produces a keystream that is correct for the first few words and then silently drifts
 * once a sum crosses 2^31. That failure looks like a table error rather than an arithmetic one, which is
 * why `u32` is used even where the operands provably cannot overflow.
 *
 * **The keystream is little-endian except in ZUC, where it is big-endian.** HC and Grain both emit the
 * low byte of each generated word first; ZUC emits the high byte first. Getting this wrong is invisible
 * to a round trip -- encrypt and decrypt agree perfectly with each other -- and shows up only against a
 * published value, which is the recurring lesson of this whole repo.
 */

/** Wrap to a signed 32-bit integer, as Java's `int` does. */
const u32 = (x: number): number => x | 0;
const rotr32 = (x: number, n: number): number => u32((x >>> n) | (x << (32 - n)));
const rotl32 = (x: number, n: number): number => u32((x << n) | (x >>> (32 - n)));

export interface StreamCipherEngine {
  /** A stream cipher is its own inverse: encrypt and decrypt are the same XOR. */
  process(data: Uint8Array): Uint8Array;
}

/**
 * Turns a word generator into an engine, spelling each word little-endian.
 *
 * Shared by HC-128, HC-256 and Grain-128 -- and deliberately not by Grain v1, which generates sixteen
 * bits at a time rather than thirty-two, nor by ZUC, whose byte order is the other way round.
 */
function leWordEngine(next: () => number): StreamCipherEngine {
  return {
    process(data: Uint8Array): Uint8Array {
      const out = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i += 4) {
        const word = next();
        for (let b = 0; b < 4 && i + b < data.length; b++) {
          out[i + b] = data[i + b]! ^ ((word >>> (8 * b)) & 0xff);
        }
      }
      return out;
    },
  };
}

// ---------------------------------------------------------------------------
// HC-128
// ---------------------------------------------------------------------------

/**
 * HC-128, an eSTREAM phase-3 software portfolio member by Hongjun Wu.
 *
 * Two 512-word tables that update *themselves*: each step rewrites one entry of P (or Q) using three
 * other entries of the same table, and reads a word out of the other table to produce output. So the
 * tables are the state rather than a constant, and there is no S-box anywhere in the design -- nothing
 * here could be mistyped, which puts all the risk in the indexing.
 *
 * The initialisation is deliberately expensive: 1280 words of SHA-256-like expansion, then 1024 steps
 * whose output is thrown away *into* the tables. Note the asymmetry that makes the two halves not
 * copy-paste of each other -- `g1` rotates right where `g2` rotates left, and `h1` reads Q while `h2`
 * reads P.
 */
export function createHc128(key: Uint8Array, iv: Uint8Array): StreamCipherEngine {
  if (key.length !== 16) throw new Error(`HC-128 needs a 16-byte key; got ${key.length}.`);
  if (iv.length !== 16) throw new Error(`HC-128 needs a 16-byte IV; got ${iv.length}.`);

  const p = new Int32Array(512);
  const q = new Int32Array(512);
  const w = new Int32Array(1280);

  const f1 = (x: number): number => rotr32(x, 7) ^ rotr32(x, 18) ^ (x >>> 3);
  const f2 = (x: number): number => rotr32(x, 17) ^ rotr32(x, 19) ^ (x >>> 10);

  for (let i = 0; i < 16; i++) w[i >> 2] = w[i >> 2]! | (key[i]! << (8 * (i & 3)));
  w.copyWithin(4, 0, 4);
  for (let i = 0; i < 16; i++) w[(i >> 2) + 8] = w[(i >> 2) + 8]! | (iv[i]! << (8 * (i & 3)));
  w.copyWithin(12, 8, 12);
  for (let i = 16; i < 1280; i++) {
    w[i] = u32(f2(w[i - 2]!) + w[i - 7]! + f1(w[i - 15]!) + w[i - 16]! + i);
  }
  p.set(w.subarray(256, 768));
  q.set(w.subarray(768, 1280));

  let cnt = 0;
  const dim = (x: number, y: number): number => (x - y) & 0x1ff;
  const g1 = (x: number, y: number, z: number): number =>
    u32((rotr32(x, 10) ^ rotr32(z, 23)) + rotr32(y, 8));
  const g2 = (x: number, y: number, z: number): number =>
    u32((rotl32(x, 10) ^ rotl32(z, 23)) + rotl32(y, 8));
  const h1 = (x: number): number => u32(q[x & 0xff]! + q[((x >> 16) & 0xff) + 256]!);
  const h2 = (x: number): number => u32(p[x & 0xff]! + p[((x >> 16) & 0xff) + 256]!);

  const step = (): number => {
    const j = cnt & 0x1ff;
    let ret: number;
    if (cnt < 512) {
      p[j] = u32(p[j]! + g1(p[dim(j, 3)]!, p[dim(j, 10)]!, p[dim(j, 511)]!));
      ret = h1(p[dim(j, 12)]!) ^ p[j]!;
    } else {
      q[j] = u32(q[j]! + g2(q[dim(j, 3)]!, q[dim(j, 10)]!, q[dim(j, 511)]!));
      ret = h2(q[dim(j, 12)]!) ^ q[j]!;
    }
    cnt = (cnt + 1) & 0x3ff;
    return ret;
  };

  // 1024 discarded steps, whose results are written back over the tables rather than dropped.
  for (let i = 0; i < 512; i++) p[i] = step();
  for (let i = 0; i < 512; i++) q[i] = step();
  cnt = 0;

  return leWordEngine(step);
}

export function hc128(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  return createHc128(key, iv).process(data);
}

// ---------------------------------------------------------------------------
// HC-256
// ---------------------------------------------------------------------------

/**
 * HC-256, the 256-bit sibling. Bigger tables, more taps, and a genuinely different output function.
 *
 * Two 1024-word tables rather than 512, and the output is the sum of *four* byte-indexed lookups into
 * the other table instead of two. Initialisation runs 4096 discarded steps -- four times HC-128's --
 * which is why this is the slower of the pair to key and the same speed to run.
 *
 * **A 128-bit key or IV is legal and is expanded, not rejected.** The specification defines 256 bits for
 * both, and eSTREAM's own vector files nevertheless include 128-bit sets, because the reference
 * implementation duplicates a short key and repeats a short IV to fill the buffer. Refusing them would
 * mean this tool could not reproduce vectors the designers published, which is the trade
 * `## Lint rules: what belongs` decides the other way round every time: diagnose, do not refuse.
 */
export function createHc256(key: Uint8Array, iv: Uint8Array): StreamCipherEngine {
  if (key.length !== 16 && key.length !== 32) {
    throw new Error(`HC-256 needs a 16- or 32-byte key; got ${key.length}.`);
  }
  if (iv.length !== 16 && iv.length !== 32) {
    throw new Error(`HC-256 needs a 16- or 32-byte IV; got ${iv.length}.`);
  }

  // The reference's own expansion for the short forms: the key is duplicated, the IV repeated.
  let k = key;
  if (k.length !== 32) {
    const wide = new Uint8Array(32);
    wide.set(k, 0);
    wide.set(k, 16);
    k = wide;
  }
  let v = iv;
  if (v.length !== 32) {
    const wide = new Uint8Array(32);
    wide.set(v, 0);
    wide.set(v.subarray(0, 32 - v.length), v.length);
    v = wide;
  }

  const p = new Int32Array(1024);
  const q = new Int32Array(1024);
  const w = new Int32Array(2560);

  for (let i = 0; i < 32; i++) w[i >> 2] = w[i >> 2]! | (k[i]! << (8 * (i & 3)));
  for (let i = 0; i < 32; i++) w[(i >> 2) + 8] = w[(i >> 2) + 8]! | (v[i]! << (8 * (i & 3)));
  for (let i = 16; i < 2560; i++) {
    const x = w[i - 2]!;
    const y = w[i - 15]!;
    w[i] = u32(
      (rotr32(x, 17) ^ rotr32(x, 19) ^ (x >>> 10)) +
        w[i - 7]! +
        (rotr32(y, 7) ^ rotr32(y, 18) ^ (y >>> 3)) +
        w[i - 16]! +
        i,
    );
  }
  p.set(w.subarray(512, 1536));
  q.set(w.subarray(1536, 2560));

  let cnt = 0;
  const step = (): number => {
    const j = cnt & 0x3ff;
    let ret: number;
    if (cnt < 1024) {
      let x = p[(j - 3) & 0x3ff]!;
      const y = p[(j - 1023) & 0x3ff]!;
      p[j] = u32(p[j]! + p[(j - 10) & 0x3ff]! + (rotr32(x, 10) ^ rotr32(y, 23)) + q[(x ^ y) & 0x3ff]!);
      x = p[(j - 12) & 0x3ff]!;
      ret =
        u32(
          q[x & 0xff]! +
            q[((x >> 8) & 0xff) + 256]! +
            q[((x >> 16) & 0xff) + 512]! +
            q[((x >>> 24) & 0xff) + 768]!,
        ) ^ p[j]!;
    } else {
      let x = q[(j - 3) & 0x3ff]!;
      const y = q[(j - 1023) & 0x3ff]!;
      q[j] = u32(q[j]! + q[(j - 10) & 0x3ff]! + (rotr32(x, 10) ^ rotr32(y, 23)) + p[(x ^ y) & 0x3ff]!);
      x = q[(j - 12) & 0x3ff]!;
      ret =
        u32(
          p[x & 0xff]! +
            p[((x >> 8) & 0xff) + 256]! +
            p[((x >> 16) & 0xff) + 512]! +
            p[((x >>> 24) & 0xff) + 768]!,
        ) ^ q[j]!;
    }
    cnt = (cnt + 1) & 0x7ff;
    return ret;
  };

  for (let i = 0; i < 4096; i++) step();
  cnt = 0;

  return leWordEngine(step);
}

export function hc256(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  return createHc256(key, iv).process(data);
}

// ---------------------------------------------------------------------------
// Grain v1 and Grain-128
// ---------------------------------------------------------------------------

/**
 * Grain v1: an 80-bit hardware-oriented design, eSTREAM's phase-3 hardware portfolio.
 *
 * An 80-bit LFSR and an 80-bit NFSR with a nonlinear filter reading taps from both. Conceptually it
 * clocks one bit at a time -- but every tap is at least sixteen positions away from the position being
 * written, so sixteen consecutive bits can be computed *in parallel* from the same state. That is why
 * the registers here are five 16-bit words and why one call produces two output bytes: it is the
 * standard hardware speed-up applied to software, not an approximation of the bit-serial definition.
 *
 * Two details worth stating because neither is visible in the round trip:
 *
 *  - **The LFSR is loaded with the IV followed by all ones**, not with the IV zero-padded. The IV is
 *    64 bits and the register is 80, and the specification fills the remaining sixteen with 1s.
 *  - **Initialisation feeds the output back into both registers**; generation feeds it into neither.
 *    160 clocks of that, which is ten of these sixteen-bit steps.
 */
export function createGrainV1(key: Uint8Array, iv: Uint8Array): StreamCipherEngine {
  if (key.length !== 10) throw new Error(`Grain v1 needs a 10-byte key; got ${key.length}.`);
  if (iv.length !== 8) throw new Error(`Grain v1 needs an 8-byte IV; got ${iv.length}.`);

  const lfsr = new Int32Array(5);
  const nfsr = new Int32Array(5);
  const padded = new Uint8Array(10);
  padded.set(iv);
  padded[8] = 0xff;
  padded[9] = 0xff;
  for (let i = 0, j = 0; i < 5; i++, j += 2) {
    nfsr[i] = ((key[j + 1]! << 8) | key[j]!) & 0xffff;
    lfsr[i] = ((padded[j + 1]! << 8) | padded[j]!) & 0xffff;
  }

  const shift = (a: Int32Array, value: number): void => {
    a[0] = a[1]!;
    a[1] = a[2]!;
    a[2] = a[3]!;
    a[3] = a[4]!;
    a[4] = value;
  };

  /** g(x), the NFSR feedback: degree six, and the reason Grain is not a plain LFSR pair. */
  const feedbackNfsr = (): number => {
    const b0 = nfsr[0]!;
    const b9 = (nfsr[0]! >>> 9) | (nfsr[1]! << 7);
    const b14 = (nfsr[0]! >>> 14) | (nfsr[1]! << 2);
    const b15 = (nfsr[0]! >>> 15) | (nfsr[1]! << 1);
    const b21 = (nfsr[1]! >>> 5) | (nfsr[2]! << 11);
    const b28 = (nfsr[1]! >>> 12) | (nfsr[2]! << 4);
    const b33 = (nfsr[2]! >>> 1) | (nfsr[3]! << 15);
    const b37 = (nfsr[2]! >>> 5) | (nfsr[3]! << 11);
    const b45 = (nfsr[2]! >>> 13) | (nfsr[3]! << 3);
    const b52 = (nfsr[3]! >>> 4) | (nfsr[4]! << 12);
    const b60 = (nfsr[3]! >>> 12) | (nfsr[4]! << 4);
    const b62 = (nfsr[3]! >>> 14) | (nfsr[4]! << 2);
    const b63 = (nfsr[3]! >>> 15) | (nfsr[4]! << 1);
    return (
      (b62 ^
        b60 ^
        b52 ^
        b45 ^
        b37 ^
        b33 ^
        b28 ^
        b21 ^
        b14 ^
        b9 ^
        b0 ^
        (b63 & b60) ^
        (b37 & b33) ^
        (b15 & b9) ^
        (b60 & b52 & b45) ^
        (b33 & b28 & b21) ^
        (b63 & b45 & b28 & b9) ^
        (b60 & b52 & b37 & b33) ^
        (b63 & b60 & b21 & b15) ^
        (b63 & b60 & b52 & b45 & b37) ^
        (b33 & b28 & b21 & b15 & b9) ^
        (b52 & b45 & b37 & b33 & b28 & b21)) &
      0xffff
    );
  };

  /** f(x), the LFSR feedback: the primitive polynomial, linear by definition. */
  const feedbackLfsr = (): number => {
    const s0 = lfsr[0]!;
    const s13 = (lfsr[0]! >>> 13) | (lfsr[1]! << 3);
    const s23 = (lfsr[1]! >>> 7) | (lfsr[2]! << 9);
    const s38 = (lfsr[2]! >>> 6) | (lfsr[3]! << 10);
    const s51 = (lfsr[3]! >>> 3) | (lfsr[4]! << 13);
    const s62 = (lfsr[3]! >>> 14) | (lfsr[4]! << 2);
    return (s0 ^ s13 ^ s23 ^ s38 ^ s51 ^ s62) & 0xffff;
  };

  /** h(x) plus the seven masked NFSR bits: the filter that actually produces keystream. */
  const filter = (): number => {
    const b1 = (nfsr[0]! >>> 1) | (nfsr[1]! << 15);
    const b2 = (nfsr[0]! >>> 2) | (nfsr[1]! << 14);
    const b4 = (nfsr[0]! >>> 4) | (nfsr[1]! << 12);
    const b10 = (nfsr[0]! >>> 10) | (nfsr[1]! << 6);
    const b31 = (nfsr[1]! >>> 15) | (nfsr[2]! << 1);
    const b43 = (nfsr[2]! >>> 11) | (nfsr[3]! << 5);
    const b56 = (nfsr[3]! >>> 8) | (nfsr[4]! << 8);
    const b63 = (nfsr[3]! >>> 15) | (nfsr[4]! << 1);
    const s3 = (lfsr[0]! >>> 3) | (lfsr[1]! << 13);
    const s25 = (lfsr[1]! >>> 9) | (lfsr[2]! << 7);
    const s46 = (lfsr[2]! >>> 14) | (lfsr[3]! << 2);
    const s64 = lfsr[4]!;
    return (
      (s25 ^
        b63 ^
        (s3 & s64) ^
        (s46 & s64) ^
        (s64 & b63) ^
        (s3 & s25 & s46) ^
        (s3 & s46 & s64) ^
        (s3 & s46 & b63) ^
        (s25 & s46 & b63) ^
        (s46 & s64 & b63) ^
        b1 ^
        b2 ^
        b4 ^
        b10 ^
        b31 ^
        b43 ^
        b56) &
      0xffff
    );
  };

  for (let i = 0; i < 10; i++) {
    const out = filter();
    shift(nfsr, feedbackNfsr() ^ lfsr[0]! ^ out);
    shift(lfsr, feedbackLfsr() ^ out);
  }

  return {
    process(data: Uint8Array): Uint8Array {
      const out = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i += 2) {
        const word = filter();
        out[i] = data[i]! ^ (word & 0xff);
        if (i + 1 < data.length) out[i + 1] = data[i + 1]! ^ ((word >>> 8) & 0xff);
        shift(nfsr, feedbackNfsr() ^ lfsr[0]!);
        shift(lfsr, feedbackLfsr());
      }
      return out;
    },
  };
}

export function grainV1(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  return createGrainV1(key, iv).process(data);
}

/**
 * Grain-128: the same architecture at twice the width, with a *simpler* nonlinear function.
 *
 * 128-bit registers as four 32-bit words, so one step yields four bytes rather than two, and 256
 * initialisation clocks rather than 160. The NFSR feedback is only degree two here -- Grain v1's runs to
 * degree six -- because the extra width bought the security margin that the algebraic complexity was
 * providing before. It is not a scaled-up Grain v1 and cannot be derived from one.
 *
 * The IV is 96 bits into a 128-bit register, so the top *four* bytes are the all-ones padding rather
 * than v1's two.
 */
export function createGrain128(key: Uint8Array, iv: Uint8Array): StreamCipherEngine {
  if (key.length !== 16) throw new Error(`Grain-128 needs a 16-byte key; got ${key.length}.`);
  if (iv.length !== 12) throw new Error(`Grain-128 needs a 12-byte IV; got ${iv.length}.`);

  const lfsr = new Int32Array(4);
  const nfsr = new Int32Array(4);
  const padded = new Uint8Array(16);
  padded.set(iv);
  padded.fill(0xff, 12);
  const load = (a: Uint8Array, j: number): number =>
    u32((a[j + 3]! << 24) | (a[j + 2]! << 16) | (a[j + 1]! << 8) | a[j]!);
  for (let i = 0, j = 0; i < 4; i++, j += 4) {
    nfsr[i] = load(key, j);
    lfsr[i] = load(padded, j);
  }

  const shift = (a: Int32Array, value: number): void => {
    a[0] = a[1]!;
    a[1] = a[2]!;
    a[2] = a[3]!;
    a[3] = value;
  };

  const feedbackNfsr = (): number => {
    const b0 = nfsr[0]!;
    const b3 = (nfsr[0]! >>> 3) | (nfsr[1]! << 29);
    const b11 = (nfsr[0]! >>> 11) | (nfsr[1]! << 21);
    const b13 = (nfsr[0]! >>> 13) | (nfsr[1]! << 19);
    const b17 = (nfsr[0]! >>> 17) | (nfsr[1]! << 15);
    const b18 = (nfsr[0]! >>> 18) | (nfsr[1]! << 14);
    const b26 = (nfsr[0]! >>> 26) | (nfsr[1]! << 6);
    const b27 = (nfsr[0]! >>> 27) | (nfsr[1]! << 5);
    const b40 = (nfsr[1]! >>> 8) | (nfsr[2]! << 24);
    const b48 = (nfsr[1]! >>> 16) | (nfsr[2]! << 16);
    const b56 = (nfsr[1]! >>> 24) | (nfsr[2]! << 8);
    const b59 = (nfsr[1]! >>> 27) | (nfsr[2]! << 5);
    const b61 = (nfsr[1]! >>> 29) | (nfsr[2]! << 3);
    const b65 = (nfsr[2]! >>> 1) | (nfsr[3]! << 31);
    const b67 = (nfsr[2]! >>> 3) | (nfsr[3]! << 29);
    const b68 = (nfsr[2]! >>> 4) | (nfsr[3]! << 28);
    const b84 = (nfsr[2]! >>> 20) | (nfsr[3]! << 12);
    const b91 = (nfsr[2]! >>> 27) | (nfsr[3]! << 5);
    const b96 = nfsr[3]!;
    return (
      b0 ^
      b26 ^
      b56 ^
      b91 ^
      b96 ^
      (b3 & b67) ^
      (b11 & b13) ^
      (b17 & b18) ^
      (b27 & b59) ^
      (b40 & b48) ^
      (b61 & b65) ^
      (b68 & b84)
    );
  };

  const feedbackLfsr = (): number => {
    const s0 = lfsr[0]!;
    const s7 = (lfsr[0]! >>> 7) | (lfsr[1]! << 25);
    const s38 = (lfsr[1]! >>> 6) | (lfsr[2]! << 26);
    const s70 = (lfsr[2]! >>> 6) | (lfsr[3]! << 26);
    const s81 = (lfsr[2]! >>> 17) | (lfsr[3]! << 15);
    const s96 = lfsr[3]!;
    return s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96;
  };

  const filter = (): number => {
    const b2 = (nfsr[0]! >>> 2) | (nfsr[1]! << 30);
    const b12 = (nfsr[0]! >>> 12) | (nfsr[1]! << 20);
    const b15 = (nfsr[0]! >>> 15) | (nfsr[1]! << 17);
    const b36 = (nfsr[1]! >>> 4) | (nfsr[2]! << 28);
    const b45 = (nfsr[1]! >>> 13) | (nfsr[2]! << 19);
    const b64 = nfsr[2]!;
    const b73 = (nfsr[2]! >>> 9) | (nfsr[3]! << 23);
    const b89 = (nfsr[2]! >>> 25) | (nfsr[3]! << 7);
    const b95 = (nfsr[2]! >>> 31) | (nfsr[3]! << 1);
    const s8 = (lfsr[0]! >>> 8) | (lfsr[1]! << 24);
    const s13 = (lfsr[0]! >>> 13) | (lfsr[1]! << 19);
    const s20 = (lfsr[0]! >>> 20) | (lfsr[1]! << 12);
    const s42 = (lfsr[1]! >>> 10) | (lfsr[2]! << 22);
    const s60 = (lfsr[1]! >>> 28) | (lfsr[2]! << 4);
    const s79 = (lfsr[2]! >>> 15) | (lfsr[3]! << 17);
    const s93 = (lfsr[2]! >>> 29) | (lfsr[3]! << 3);
    const s94 = (lfsr[2]! >>> 30) | (lfsr[3]! << 2);
    return (
      (b12 & s8) ^
      (s13 & s20) ^
      (b95 & s42) ^
      (s60 & s79) ^
      (b12 & b95 & s94) ^
      s93 ^
      b2 ^
      b15 ^
      b36 ^
      b45 ^
      b64 ^
      b73 ^
      b89
    );
  };

  for (let i = 0; i < 8; i++) {
    const out = filter();
    shift(nfsr, feedbackNfsr() ^ lfsr[0]! ^ out);
    shift(lfsr, feedbackLfsr() ^ out);
  }

  return leWordEngine(() => {
    const word = filter();
    shift(nfsr, feedbackNfsr() ^ lfsr[0]!);
    shift(lfsr, feedbackLfsr());
    return word;
  });
}

export function grain128(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  return createGrain128(key, iv).process(data);
}

// ---------------------------------------------------------------------------
// ZUC
// ---------------------------------------------------------------------------

/**
 * ZUC's two 8-bit S-boxes.
 *
 * These are the one thing in this module that is stored rather than computed, and they are not
 * derivable: S0 is built from three 4-bit permutations in a specific wiring and S1 is a power map over
 * GF(2^8) with an affine wrapper. Both are transcribed from the GSMA specification, and what stands
 * behind them is four published keystreams -- two per key size -- rather than a structural check.
 */
const ZUC_S0 = new Uint8Array([
  0x3e, 0x72, 0x5b, 0x47, 0xca, 0xe0, 0x00, 0x33, 0x04, 0xd1, 0x54, 0x98, 0x09, 0xb9, 0x6d, 0xcb,
  0x7b, 0x1b, 0xf9, 0x32, 0xaf, 0x9d, 0x6a, 0xa5, 0xb8, 0x2d, 0xfc, 0x1d, 0x08, 0x53, 0x03, 0x90,
  0x4d, 0x4e, 0x84, 0x99, 0xe4, 0xce, 0xd9, 0x91, 0xdd, 0xb6, 0x85, 0x48, 0x8b, 0x29, 0x6e, 0xac,
  0xcd, 0xc1, 0xf8, 0x1e, 0x73, 0x43, 0x69, 0xc6, 0xb5, 0xbd, 0xfd, 0x39, 0x63, 0x20, 0xd4, 0x38,
  0x76, 0x7d, 0xb2, 0xa7, 0xcf, 0xed, 0x57, 0xc5, 0xf3, 0x2c, 0xbb, 0x14, 0x21, 0x06, 0x55, 0x9b,
  0xe3, 0xef, 0x5e, 0x31, 0x4f, 0x7f, 0x5a, 0xa4, 0x0d, 0x82, 0x51, 0x49, 0x5f, 0xba, 0x58, 0x1c,
  0x4a, 0x16, 0xd5, 0x17, 0xa8, 0x92, 0x24, 0x1f, 0x8c, 0xff, 0xd8, 0xae, 0x2e, 0x01, 0xd3, 0xad,
  0x3b, 0x4b, 0xda, 0x46, 0xeb, 0xc9, 0xde, 0x9a, 0x8f, 0x87, 0xd7, 0x3a, 0x80, 0x6f, 0x2f, 0xc8,
  0xb1, 0xb4, 0x37, 0xf7, 0x0a, 0x22, 0x13, 0x28, 0x7c, 0xcc, 0x3c, 0x89, 0xc7, 0xc3, 0x96, 0x56,
  0x07, 0xbf, 0x7e, 0xf0, 0x0b, 0x2b, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xa6, 0x4c, 0x10, 0xfe,
  0xbc, 0x26, 0x95, 0x88, 0x8a, 0xb0, 0xa3, 0xfb, 0xc0, 0x18, 0x94, 0xf2, 0xe1, 0xe5, 0xe9, 0x5d,
  0xd0, 0xdc, 0x11, 0x66, 0x64, 0x5c, 0xec, 0x59, 0x42, 0x75, 0x12, 0xf5, 0x74, 0x9c, 0xaa, 0x23,
  0x0e, 0x86, 0xab, 0xbe, 0x2a, 0x02, 0xe7, 0x67, 0xe6, 0x44, 0xa2, 0x6c, 0xc2, 0x93, 0x9f, 0xf1,
  0xf6, 0xfa, 0x36, 0xd2, 0x50, 0x68, 0x9e, 0x62, 0x71, 0x15, 0x3d, 0xd6, 0x40, 0xc4, 0xe2, 0x0f,
  0x8e, 0x83, 0x77, 0x6b, 0x25, 0x05, 0x3f, 0x0c, 0x30, 0xea, 0x70, 0xb7, 0xa1, 0xe8, 0xa9, 0x65,
  0x8d, 0x27, 0x1a, 0xdb, 0x81, 0xb3, 0xa0, 0xf4, 0x45, 0x7a, 0x19, 0xdf, 0xee, 0x78, 0x34, 0x60,
]);

const ZUC_S1 = new Uint8Array([
  0x55, 0xc2, 0x63, 0x71, 0x3b, 0xc8, 0x47, 0x86, 0x9f, 0x3c, 0xda, 0x5b, 0x29, 0xaa, 0xfd, 0x77,
  0x8c, 0xc5, 0x94, 0x0c, 0xa6, 0x1a, 0x13, 0x00, 0xe3, 0xa8, 0x16, 0x72, 0x40, 0xf9, 0xf8, 0x42,
  0x44, 0x26, 0x68, 0x96, 0x81, 0xd9, 0x45, 0x3e, 0x10, 0x76, 0xc6, 0xa7, 0x8b, 0x39, 0x43, 0xe1,
  0x3a, 0xb5, 0x56, 0x2a, 0xc0, 0x6d, 0xb3, 0x05, 0x22, 0x66, 0xbf, 0xdc, 0x0b, 0xfa, 0x62, 0x48,
  0xdd, 0x20, 0x11, 0x06, 0x36, 0xc9, 0xc1, 0xcf, 0xf6, 0x27, 0x52, 0xbb, 0x69, 0xf5, 0xd4, 0x87,
  0x7f, 0x84, 0x4c, 0xd2, 0x9c, 0x57, 0xa4, 0xbc, 0x4f, 0x9a, 0xdf, 0xfe, 0xd6, 0x8d, 0x7a, 0xeb,
  0x2b, 0x53, 0xd8, 0x5c, 0xa1, 0x14, 0x17, 0xfb, 0x23, 0xd5, 0x7d, 0x30, 0x67, 0x73, 0x08, 0x09,
  0xee, 0xb7, 0x70, 0x3f, 0x61, 0xb2, 0x19, 0x8e, 0x4e, 0xe5, 0x4b, 0x93, 0x8f, 0x5d, 0xdb, 0xa9,
  0xad, 0xf1, 0xae, 0x2e, 0xcb, 0x0d, 0xfc, 0xf4, 0x2d, 0x46, 0x6e, 0x1d, 0x97, 0xe8, 0xd1, 0xe9,
  0x4d, 0x37, 0xa5, 0x75, 0x5e, 0x83, 0x9e, 0xab, 0x82, 0x9d, 0xb9, 0x1c, 0xe0, 0xcd, 0x49, 0x89,
  0x01, 0xb6, 0xbd, 0x58, 0x24, 0xa2, 0x5f, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xb8, 0x95, 0xe4,
  0xd0, 0x91, 0xc7, 0xce, 0xed, 0x0f, 0xb4, 0x6f, 0xa0, 0xcc, 0xf0, 0x02, 0x4a, 0x79, 0xc3, 0xde,
  0xa3, 0xef, 0xea, 0x51, 0xe6, 0x6b, 0x18, 0xec, 0x1b, 0x2c, 0x80, 0xf7, 0x74, 0xe7, 0xff, 0x21,
  0x5a, 0x6a, 0x54, 0x1e, 0x41, 0x31, 0x92, 0x35, 0xc4, 0x33, 0x07, 0x0a, 0xba, 0x7e, 0x0e, 0x34,
  0x88, 0xb1, 0x98, 0x7c, 0xf3, 0x3d, 0x60, 0x6c, 0x7b, 0xca, 0xd3, 0x1f, 0x32, 0x65, 0x04, 0x28,
  0x64, 0xbe, 0x85, 0x9b, 0x2f, 0x59, 0x8a, 0xd7, 0xb0, 0x25, 0xac, 0xaf, 0x12, 0x03, 0xe2, 0xf2,
]);

/** ZUC-128's sixteen 15-bit loading constants, from the GSMA specification. */
const ZUC128_D = [
  0x44d7, 0x26bc, 0x626b, 0x135e, 0x5789, 0x35e2, 0x7135, 0x09af, 0x4d78, 0x2f13, 0x6bc4, 0x1af1,
  0x5e26, 0x3c4d, 0x789a, 0x47ac,
];

/**
 * ZUC-256's sixteen 7-bit loading constants -- the encryption set.
 *
 * The 256-bit design defines four of these tables: one for the cipher and three more for the MAC at 32,
 * 64 and 128 bits of tag. They differ in two bits total. Only the cipher's is here, because only the
 * cipher is a tool; the MAC variants are a metadata entry away if that changes.
 */
const ZUC256_D = [
  0x22, 0x2f, 0x24, 0x2a, 0x6d, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30,
];

/**
 * ZUC, both key sizes, from one core.
 *
 * The 3GPP stream cipher: 128-EEA3 confidentiality in LTE and 5G, and the basis of 128-EIA3 integrity.
 * Structurally unlike everything else in this module -- a 16-stage LFSR over **GF(2^31 - 1)** rather
 * than GF(2), a bit-reorganisation layer that carves four 32-bit words out of five LFSR cells, and a
 * two-register nonlinear function F built from the two S-boxes above.
 *
 * Three things that matter:
 *
 *  - **The LFSR arithmetic is mod 2^31 - 1, in one's-complement form.** `addM` folds the carry out of
 *    bit 31 back into bit 0, and `mulByPow2` is a rotation within 31 bits rather than 32. Using ordinary
 *    32-bit arithmetic here produces a keystream that looks fine and matches nothing.
 *  - **The 32 initialisation rounds feed `w >>> 1` back into the LFSR**, and then one further round runs
 *    with F's output *discarded*. Skipping that discarded round shifts the whole keystream by one word.
 *  - **ZUC-128 and ZUC-256 differ only in how the LFSR is loaded**, which is why one core serves both.
 *    ZUC-128 interleaves key byte, constant and IV byte into each 31-bit cell; ZUC-256 has a bespoke
 *    scattering of a 32-byte key and a 25-byte IV, with six bits of IV folded into nine of the
 *    constants. The `variant` argument is the whole difference.
 */
export function createZuc(
  variant: "zuc128" | "zuc256",
  key: Uint8Array,
  iv: Uint8Array,
): StreamCipherEngine {
  const lfsr = new Int32Array(16);
  const f = new Int32Array(2);
  const brc = new Int32Array(4);

  if (variant === "zuc128") {
    if (key.length !== 16) throw new Error(`ZUC-128 needs a 16-byte key; got ${key.length}.`);
    if (iv.length !== 16) throw new Error(`ZUC-128 needs a 16-byte IV; got ${iv.length}.`);
    for (let i = 0; i < 16; i++) {
      lfsr[i] = (key[i]! << 23) | (ZUC128_D[i]! << 8) | iv[i]!;
    }
  } else {
    if (key.length !== 32) throw new Error(`ZUC-256 needs a 32-byte key; got ${key.length}.`);
    if (iv.length !== 25) throw new Error(`ZUC-256 needs a 25-byte IV; got ${iv.length}.`);
    const k = key;
    const v = iv;
    const d = ZUC256_D;
    const m = (a: number, b: number, c: number, e: number): number =>
      ((a & 0xff) << 23) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | (e & 0xff);
    lfsr[0] = m(k[0]!, d[0]!, k[21]!, k[16]!);
    lfsr[1] = m(k[1]!, d[1]!, k[22]!, k[17]!);
    lfsr[2] = m(k[2]!, d[2]!, k[23]!, k[18]!);
    lfsr[3] = m(k[3]!, d[3]!, k[24]!, k[19]!);
    lfsr[4] = m(k[4]!, d[4]!, k[25]!, k[20]!);
    lfsr[5] = m(v[0]!, d[5]! | (v[17]! & 0x3f), k[5]!, k[26]!);
    lfsr[6] = m(v[1]!, d[6]! | (v[18]! & 0x3f), k[6]!, k[27]!);
    lfsr[7] = m(v[10]!, d[7]! | (v[19]! & 0x3f), k[7]!, v[2]!);
    lfsr[8] = m(k[8]!, d[8]! | (v[20]! & 0x3f), v[3]!, v[11]!);
    lfsr[9] = m(k[9]!, d[9]! | (v[21]! & 0x3f), v[12]!, v[4]!);
    lfsr[10] = m(v[5]!, d[10]! | (v[22]! & 0x3f), k[10]!, k[28]!);
    lfsr[11] = m(k[11]!, d[11]! | (v[23]! & 0x3f), v[6]!, v[13]!);
    lfsr[12] = m(k[12]!, d[12]! | (v[24]! & 0x3f), v[7]!, v[14]!);
    lfsr[13] = m(k[13]!, d[13]!, v[15]!, v[8]!);
    lfsr[14] = m(k[14]!, d[14]! | ((k[31]! >>> 4) & 0xf), v[16]!, v[9]!);
    lfsr[15] = m(k[15]!, d[15]! | (k[31]! & 0xf), k[30]!, k[29]!);
  }

  /** Addition mod 2^31 - 1: the carry out of bit 31 comes back in at bit 0. */
  const addM = (a: number, b: number): number => {
    const c = u32(a + b);
    return u32((c & 0x7fffffff) + (c >>> 31));
  };
  /** Multiplication by 2^k mod 2^31 - 1, which is a rotation across 31 bits rather than 32. */
  const mulByPow2 = (x: number, k: number): number => ((x << k) | (x >>> (31 - k))) & 0x7fffffff;
  const rot = (a: number, k: number): number => u32((a << k) | (a >>> (32 - k)));
  const l1 = (x: number): number => x ^ rot(x, 2) ^ rot(x, 10) ^ rot(x, 18) ^ rot(x, 24);
  const l2 = (x: number): number => x ^ rot(x, 8) ^ rot(x, 14) ^ rot(x, 22) ^ rot(x, 30);
  const pack = (a: number, b: number, c: number, d: number): number =>
    u32(((a & 0xff) << 24) | ((b & 0xff) << 16) | ((c & 0xff) << 8) | (d & 0xff));

  const bitReorganisation = (): void => {
    brc[0] = u32(((lfsr[15]! & 0x7fff8000) << 1) | (lfsr[14]! & 0xffff));
    brc[1] = u32(((lfsr[11]! & 0xffff) << 16) | (lfsr[9]! >>> 15));
    brc[2] = u32(((lfsr[7]! & 0xffff) << 16) | (lfsr[5]! >>> 15));
    brc[3] = u32(((lfsr[2]! & 0xffff) << 16) | (lfsr[0]! >>> 15));
  };

  const nonlinear = (): number => {
    const w = u32(u32(brc[0]! ^ f[0]!) + f[1]!);
    const w1 = u32(f[0]! + brc[1]!);
    const w2 = f[1]! ^ brc[2]!;
    const u = l1(u32((w1 << 16) | (w2 >>> 16)));
    const v = l2(u32((w2 << 16) | (w1 >>> 16)));
    f[0] = pack(
      ZUC_S0[u >>> 24]!,
      ZUC_S1[(u >>> 16) & 0xff]!,
      ZUC_S0[(u >>> 8) & 0xff]!,
      ZUC_S1[u & 0xff]!,
    );
    f[1] = pack(
      ZUC_S0[v >>> 24]!,
      ZUC_S1[(v >>> 16) & 0xff]!,
      ZUC_S0[(v >>> 8) & 0xff]!,
      ZUC_S1[v & 0xff]!,
    );
    return w;
  };

  /** One LFSR step. `u` is present in initialisation mode and absent in work mode. */
  const lfsrStep = (u?: number): void => {
    let next = lfsr[0]!;
    next = addM(next, mulByPow2(lfsr[0]!, 8));
    next = addM(next, mulByPow2(lfsr[4]!, 20));
    next = addM(next, mulByPow2(lfsr[10]!, 21));
    next = addM(next, mulByPow2(lfsr[13]!, 17));
    next = addM(next, mulByPow2(lfsr[15]!, 15));
    if (u !== undefined) next = addM(next, u);
    lfsr.copyWithin(0, 1);
    lfsr[15] = next;
  };

  for (let round = 0; round < 32; round++) {
    bitReorganisation();
    lfsrStep(nonlinear() >>> 1);
  }
  // The discarded round. F advances the two registers and its output is thrown away.
  bitReorganisation();
  nonlinear();
  lfsrStep();

  return {
    process(data: Uint8Array): Uint8Array {
      const out = new Uint8Array(data.length);
      for (let i = 0; i < data.length; i += 4) {
        bitReorganisation();
        const word = nonlinear() ^ brc[3]!;
        lfsrStep();
        // Big-endian, unlike HC and Grain. See the module header.
        for (let b = 0; b < 4 && i + b < data.length; b++) {
          out[i + b] = data[i + b]! ^ ((word >>> (24 - 8 * b)) & 0xff);
        }
      }
      return out;
    },
  };
}

export function zuc(
  variant: "zuc128" | "zuc256",
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  return createZuc(variant, key, iv).process(data);
}
