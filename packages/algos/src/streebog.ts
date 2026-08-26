/**
 * Streebog, GOST R 34.11-2012, from RFC 6986. Hash codes of 256 and 512 bits.
 *
 * The Russian national hash standard, and the reason a workbench wants it: it is what
 * `openssl dgst -streebog512` produces when the GOST engine is loaded, it is mandatory for
 * qualified signatures there, and it appears in TLS via RFC 9189. No pure-ESM library implements it,
 * and OpenSSL will not do it without an engine -- so unlike Camellia there is no oracle here, and
 * the RFC's own worked examples are the whole check. Both of them, at both lengths.
 *
 * Four things to know before touching this.
 *
 * **The RFC prints every value backwards from how a program holds it.** GOST writes a 512-bit value
 * as `a_63||...||a_0`, most significant byte first, and byte i of a message is a_i -- so the hex
 * strings in RFC 6986 are the reverse of the corresponding byte strings, the printed M1 reading
 * "2109876543..." where the message is "0123456789...". Everything here is therefore held in *vector
 * order*, index 0 being a_0: a message block is a straight copy, the digest is the state as-is, and
 * the only place a reversal appears is where a printed constant is parsed. The first version of this
 * file reversed each block as well, which reproduced the RFC's round function exactly and every
 * published digest incorrectly -- worth knowing, because it means matching `g_N` proves nothing about
 * this convention.
 *
 * **Pi, A and C came out of the RFC by script.** 256 substitution entries, 64 matrix rows and twelve
 * 512-bit constants is far too much to type. See the note at the top of `camellia.ts`.
 *
 * **The lookup tables are derived, and the derivation is the interesting part.** The specification
 * applies S (substitute each byte), then P (a byte permutation), then L (multiply each 64-bit word by
 * the matrix A over GF(2)) -- 64 matrix rows conditionally XORed per word, per round, which would be
 * unusably slow. Because Tau(8j + r) = 8r + j, byte r of word j after S and P is Pi(byte j of input
 * word r); L is linear, so
 *
 *     word j of LPS(x) = XOR over r of l(Pi(byte j of word r) << 8r)
 *
 * and the inner term depends only on (r, byte). `AX` is that: eight tables of 256 64-bit values,
 * computed at load from Pi and A. This is the standard formulation, derived here rather than copied,
 * and the RFC's examples are what confirm the derivation.
 *
 * **There are two counters, and both are 512-bit.** N counts *bits* consumed and EPSILON is the sum
 * of every block as a 512-bit integer; the final two rounds fold them in. A hash that omits either
 * still round-trips against itself.
 */

/** The output lengths GOST R 34.11-2012 defines, in bytes. */
export const STREEBOG_OUTPUT_LENS: readonly number[] = [32, 64];
export const STREEBOG_BLOCK_LEN = 64;

/** Pi', RFC 6986 section 6.2. */
const PI = new Uint8Array([
  252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
  233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
  249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
  5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
  235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
  181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
  21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
  50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
  223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
  224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
  167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
  173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
  7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
  225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
  32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
  89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
]);

/**
 * The rows of the matrix A, RFC 6986 section 6.4, most significant nibble first.
 *
 * Kept as strings and parsed at load rather than written as 64 `bigint` literals: the point of this
 * table is to be diffable against the RFC, and the RFC prints hex.
 */
const A_ROWS: readonly string[] = [
  "8e20faa72ba0b470", "47107ddd9b505a38", "ad08b0e0c3282d1c", "d8045870ef14980e",
  "6c022c38f90a4c07", "3601161cf205268d", "1b8e0b0e798c13c8", "83478b07b2468764",
  "a011d380818e8f40", "5086e740ce47c920", "2843fd2067adea10", "14aff010bdd87508",
  "0ad97808d06cb404", "05e23c0468365a02", "8c711e02341b2d01", "46b60f011a83988e",
  "90dab52a387ae76f", "486dd4151c3dfdb9", "24b86a840e90f0d2", "125c354207487869",
  "092e94218d243cba", "8a174a9ec8121e5d", "4585254f64090fa0", "accc9ca9328a8950",
  "9d4df05d5f661451", "c0a878a0a1330aa6", "60543c50de970553", "302a1e286fc58ca7",
  "18150f14b9ec46dd", "0c84890ad27623e0", "0642ca05693b9f70", "0321658cba93c138",
  "86275df09ce8aaa8", "439da0784e745554", "afc0503c273aa42a", "d960281e9d1d5215",
  "e230140fc0802984", "71180a8960409a42", "b60c05ca30204d21", "5b068c651810a89e",
  "456c34887a3805b9", "ac361a443d1c8cd2", "561b0d22900e4669", "2b838811480723ba",
  "9bcf4486248d9f5d", "c3e9224312c8c1a0", "effa11af0964ee50", "f97d86d98a327728",
  "e4fa2054a80b329c", "727d102a548b194e", "39b008152acb8227", "9258048415eb419d",
  "492c024284fbaec0", "aa16012142f35760", "550b8e9e21f7a530", "a48b474f9ef5dc18",
  "70a6a56e2440598e", "3853dc371220a247", "1ca76e95091051ad", "0edd37c48a08a6d8",
  "07e095624504536c", "8d70c431ac02a736", "c83862965601dd1b", "641c314b2b8ee083",
];

/** C[1] to C[12], RFC 6986 section 6.5. Each is 512 bits, printed most significant byte first. */
const C_HEX: readonly string[] = [
  "b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507",
  "6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7",
  "f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2",
  "ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e",
  "4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57",
  "ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e",
  "f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493",
  "9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e",
  "378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb",
  "abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced",
  "7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b",
  "378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720",
];

const BLOCK = 64;

/** A 64-bit value as a pair of 32-bit halves, stored in parallel arrays for the lookup tables. */
const AX_LO = new Uint32Array(8 * 256);
const AX_HI = new Uint32Array(8 * 256);

(() => {
  // The matrix rows as (lo, hi) pairs. Row index matches the RFC's row numbering.
  const rowLo = new Uint32Array(64);
  const rowHi = new Uint32Array(64);
  for (let i = 0; i < 64; i++) {
    const hex = A_ROWS[i]!;
    rowHi[i] = parseInt(hex.slice(0, 8), 16);
    rowLo[i] = parseInt(hex.slice(8, 16), 16);
  }

  for (let r = 0; r < 8; r++) {
    for (let b = 0; b < 256; b++) {
      const substituted = PI[b]!;
      let lo = 0;
      let hi = 0;
      // Pi(b) << 8r occupies bit positions 8r..8r+7; bit i of the input selects row 63 - i.
      for (let t = 0; t < 8; t++) {
        if (((substituted >>> t) & 1) === 0) continue;
        const row = 63 - (8 * r + t);
        lo ^= rowLo[row]!;
        hi ^= rowHi[row]!;
      }
      AX_LO[r * 256 + b] = lo >>> 0;
      AX_HI[r * 256 + b] = hi >>> 0;
    }
  }
})();

/** The twelve iteration constants, in vector order -- the RFC's hex reversed. */
const C: readonly Uint8Array[] = C_HEX.map((hex) => {
  const out = new Uint8Array(BLOCK);
  for (let i = 0; i < BLOCK; i++) {
    out[BLOCK - 1 - i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
});

/** LPS, via the derived tables. `out` must not alias `input`. */
function lps(input: Uint8Array, out: Uint8Array): void {
  for (let j = 0; j < 8; j++) {
    let lo = 0;
    let hi = 0;
    for (let r = 0; r < 8; r++) {
      const b = input[r * 8 + j]!;
      lo ^= AX_LO[r * 256 + b]!;
      hi ^= AX_HI[r * 256 + b]!;
    }
    const at = j * 8;
    out[at] = lo & 0xff;
    out[at + 1] = (lo >>> 8) & 0xff;
    out[at + 2] = (lo >>> 16) & 0xff;
    out[at + 3] = (lo >>> 24) & 0xff;
    out[at + 4] = hi & 0xff;
    out[at + 5] = (hi >>> 8) & 0xff;
    out[at + 6] = (hi >>> 16) & 0xff;
    out[at + 7] = (hi >>> 24) & 0xff;
  }
}

function xorInto(target: Uint8Array, a: Uint8Array, b: Uint8Array): void {
  for (let i = 0; i < BLOCK; i++) target[i] = a[i]! ^ b[i]!;
}

/** 512-bit addition in vector order: index 0 is the least significant byte. */
function addInto(target: Uint8Array, addend: Uint8Array): void {
  let carry = 0;
  for (let i = 0; i < BLOCK; i++) {
    const sum = target[i]! + addend[i]! + carry;
    target[i] = sum & 0xff;
    carry = sum >>> 8;
  }
}

function addBits(target: Uint8Array, bits: number): void {
  let carry = bits;
  for (let i = 0; i < BLOCK && carry !== 0; i++) {
    const sum = target[i]! + (carry & 0xff);
    target[i] = sum & 0xff;
    carry = (carry >>> 8) + (sum >>> 8);
  }
}

/**
 * g_N(h, m) = E(LPS(h ^ N), m) ^ h ^ m, RFC 6986 section 8.
 *
 * Twelve rounds of LPS over the key schedule and the state in step, which is why the two scratch
 * buffers are allocated per hasher and reused rather than per call.
 */
function g(h: Uint8Array, m: Uint8Array, n: Uint8Array, scratch: Uint8Array[]): void {
  const [key, state, temp] = scratch as [Uint8Array, Uint8Array, Uint8Array];

  xorInto(temp, h, n);
  lps(temp, key); // K[1]

  xorInto(temp, m, key);
  lps(temp, state); // LPSX[K[1]](m)

  for (let i = 1; i < 12; i++) {
    // K[i+1] = LPS(K[i] ^ C[i])
    xorInto(temp, key, C[i - 1]!);
    lps(temp, key);
    xorInto(temp, state, key);
    lps(temp, state);
  }

  // K[13], and the final X with no LPS after it.
  xorInto(temp, key, C[11]!);
  lps(temp, key);

  for (let i = 0; i < BLOCK; i++) h[i] = state[i]! ^ key[i]! ^ h[i]! ^ m[i]!;
}

export interface StreebogEngine {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

class Streebog implements StreebogEngine {
  private readonly h = new Uint8Array(BLOCK);
  private readonly n = new Uint8Array(BLOCK);
  private readonly sigma = new Uint8Array(BLOCK);
  private readonly buffer = new Uint8Array(BLOCK);
  private readonly block = new Uint8Array(BLOCK);
  private readonly scratch = [
    new Uint8Array(BLOCK),
    new Uint8Array(BLOCK),
    new Uint8Array(BLOCK),
  ];
  private readonly zero = new Uint8Array(BLOCK);
  private buffered = 0;
  private done = false;

  constructor(private readonly outputLen: number) {
    if (!STREEBOG_OUTPUT_LENS.includes(outputLen)) {
      throw new Error(`Streebog produces 32 or 64 bytes; ${outputLen} was requested.`);
    }
    // IV is 0^512 for the 512-bit function and (00000001)^64 for the 256-bit one.
    if (outputLen === 32) this.h.fill(1);
  }

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("Streebog: update after digest");
    let offset = 0;
    while (offset < chunk.length) {
      const take = Math.min(BLOCK - this.buffered, chunk.length - offset);
      this.buffer.set(chunk.subarray(offset, offset + take), this.buffered);
      this.buffered += take;
      offset += take;
      if (this.buffered === BLOCK) {
        // Byte i of the stream is a_i, so vector order is the order it arrived in.
        this.block.set(this.buffer);
        g(this.h, this.block, this.n, this.scratch);
        addBits(this.n, BLOCK * 8);
        addInto(this.sigma, this.block);
        this.buffered = 0;
      }
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("Streebog: digest called twice");
    this.done = true;

    /**
     * Step 3.1: m = 0...0 || 1 || M, with the remaining message in the low bits.
     *
     * In vector order that is the tail at indices 0..r-1, a single 0x01 byte at index r, and zeros
     * above -- so a message that is an exact multiple of the block size still gets a final block
     * consisting of nothing but that 1 bit.
     */
    const r = this.buffered;
    this.block.fill(0);
    this.block.set(this.buffer.subarray(0, r));
    this.block[r] = 1;

    g(this.h, this.block, this.n, this.scratch);
    addBits(this.n, r * 8);
    addInto(this.sigma, this.block);

    g(this.h, this.n, this.zero, this.scratch);
    g(this.h, this.sigma, this.zero, this.scratch);

    // MSB_256 for the short form: the high half of the state, which is the top of vector order.
    const out = new Uint8Array(this.outputLen);
    out.set(this.h.subarray(BLOCK - this.outputLen));
    return out;
  }
}

export function createStreebog(outputLen: number): StreebogEngine {
  return new Streebog(outputLen);
}

export function streebog(data: Uint8Array, outputLen: number): Uint8Array {
  const engine = createStreebog(outputLen);
  engine.update(data);
  return engine.digest();
}
