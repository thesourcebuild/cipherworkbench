/**
 * FSB -- Fast Syndrome-Based hash (Augot, Finiasz, Gaborit, Manuel and Sendrier), a NIST SHA-3 round-1
 * submission.
 *
 * `legacy`. Not broken -- it was withdrawn after round 1 on performance grounds, not security -- but
 * nothing standardises it and nothing else implements it.
 *
 * **Its security reduces to a coding-theory problem**, which is what made it interesting: finding a
 * collision means solving regular syndrome decoding for a quasi-cyclic code. That is the opposite of
 * every other hash in this repo, whose security is an argument about a permutation.
 *
 * ## The one thing to know before touching this: nothing external checks it
 *
 * FSB is the only algorithm in this repo with **no external check of any kind**. There is no published
 * digest anywhere reachable: `fsbdoc.pdf` contains no test vector and not one hex string of any length;
 * the submission zip ships only `Reference_Implementation` with no KAT directory; no library in this
 * tree or any of its oracles has ever implemented it; and SUPERCOP's checksums would need its
 * `try-anything` harness reproduced, at which point a mismatch cannot say which side is wrong.
 *
 * So what stands behind it is **two independent formulations of the same function, required to agree**
 * -- the arrangement `crcReference` gives the CRC engine:
 *
 * - `fsbCompress` below is the reference C's formulation: eight pre-shifted copies of each block's first
 *   line, indexed by `shift & 7` with a byte offset of `(r >> 3) - (shift >> 3)`, and a word-wise XOR.
 * - `fsbCompressReference` derives each column *bit by bit* from the specification's own definition of
 *   the quasi-cyclic extension, with no precomputation and no shifted copies.
 *
 * `tests/algos-fsb.test.ts` requires them to agree at every parameter set across a range of inputs.
 * Two formulations sharing a wrong understanding of the matrix is possible; two formulations sharing a
 * transcription slip is not, and the second is what a port actually gets wrong. That is the honest
 * position, and it should not be described as verification against a vector.
 *
 * The pi table's provenance *is* verified -- see `fsb-pi.ts`.
 *
 * ## The structure, and the four places it is easy to get wrong
 *
 * Each round takes `inputsize = w * bpc - r` message bits, splits them with the current syndrome into
 * `w` column indices of `bpc` bits each, and XORs those `w` columns of the matrix together to make the
 * next `r`-bit syndrome. The final syndrome goes through **Whirlpool**, truncated to the digest length.
 *
 * **The index is three pieces, and the message half is shifted by the IV half's width.**
 * `index = (i << bpc) ^ syndromeBits ^ (messageBits << bfiv)`. The `i << bpc` term is what makes column
 * `i` come from the `i`-th group of `n/w` columns -- the "regular" in regular syndrome decoding.
 *
 * **The first line's low `r` bits are the *tail* of the p-bit vector, not zero.** That is the
 * quasi-cyclic wrap: `A_k = V_k[p - r .. p) ++ V_k`. Zero-filling instead gives a perfectly
 * deterministic hash that matches nothing.
 *
 * **The column window runs backwards: shift `s` selects `A_k[r - s .. 2r - s)`, not `A_k[s .. s + r)`.**
 * That is what the reference's `line[(r >> 3) - (shift >> 3) + j]` over a copy right-shifted by
 * `shift & 7` works out to, and the first attempt at the bit-level formulation here had it the other way
 * round -- which the cross-check caught on its first run, at every parameter set. The sanity check that
 * settles the direction: at shift 0 the window must be the *first* r bits of V, i.e. no rotation.
 *
 * **Padding is a 1 bit then the 64-bit length, and it may need a whole extra round.** If the length
 * field will not fit in the current block, the block is filled and a *second* full block carries the
 * length in its last eight bytes -- so a message can cost one more compression than its size suggests.
 *
 * **The final transform is Whirlpool over the syndrome bytes**, and the syndrome is `r` bits, not the
 * digest length. FSB-256's syndrome is 1024 bits; Whirlpool reduces it to 512 and the digest is the
 * first 256.
 */

import { whirlpool } from "./whirlpool";

/**
 * The pi table is reached through a **dynamic import**, and that is a bundling decision rather than a
 * stylistic one.
 *
 * `fsb-pi.ts` is 363 KB of base64. Statically importing it put it in the hash family's lazy chunk, which
 * took that chunk from about 174 KB to 537 KB -- so opening SHA-256 downloaded FSB's matrix. All 139 hash
 * tools share that chunk and essentially nobody wants this one, which makes it the worst possible place
 * for the largest data file in the repo.
 *
 * With `await import()` the bundler gives the table its own chunk and it is fetched only when FSB is
 * actually selected. `loadTool()` in the registry awaits `prepareFsb()` for exactly that reason, which is
 * what keeps the synchronous `Hasher` contract intact -- `ToolStream.finish()` is sync and cannot await,
 * so the load has to happen before the tool is handed over rather than inside a compute.
 *
 * The sync accessor therefore throws rather than loading, and the message says what to call. That is the
 * failure mode a caller can act on; silently returning zeros would give a plausible wrong digest.
 */
let piTable: Uint8Array | undefined;
let piLoad: Promise<void> | undefined;

/** Load the matrix table. Idempotent, and cheap after the first call. */
export function prepareFsb(): Promise<void> {
  if (piTable) return Promise.resolve();
  piLoad ??= import("./fsb-pi").then((module) => {
    piTable = module.fsbPiTable();
  });
  return piLoad;
}

/** True once `prepareFsb()` has resolved. */
export const fsbIsReady = (): boolean => piTable !== undefined;

function fsbPiTable(): Uint8Array {
  if (!piTable) {
    throw new Error(
      "FSB: its matrix table has not been loaded yet. Await prepareFsb() before hashing -- the table " +
        "is a 266 KB dynamic import so that the other hash tools do not pay for it.",
    );
  }
  return piTable;
}

export interface FsbParams {
  /** Digest length in bits. */
  readonly hashBits: number;
  /** Number of matrix columns. */
  readonly n: number;
  /** Columns XORed per round -- the code's weight. */
  readonly w: number;
  /** Syndrome length in bits. Always a multiple of 8 here. */
  readonly r: number;
  /** Bits of pi taken per quasi-cyclic block. */
  readonly p: number;
}

/**
 * The six sets from the reference's own table.
 *
 * FSB-48 is the reference's reduced set for testing rather than part of the submission, and a 48-bit
 * digest is not a hash -- it is implemented so this file is complete and is deliberately not registered
 * as a tool. The five submission sizes are.
 */
export const FSB_PARAMS: readonly FsbParams[] = [
  { hashBits: 48, n: 3 << 17, w: 24, r: 192, p: 197 },
  { hashBits: 160, n: 5 << 18, w: 80, r: 640, p: 653 },
  { hashBits: 224, n: 7 << 18, w: 112, r: 896, p: 907 },
  { hashBits: 256, n: 1 << 21, w: 1 << 7, r: 1 << 10, p: 1061 },
  { hashBits: 384, n: 23 << 16, w: 184, r: 1472, p: 1483 },
  { hashBits: 512, n: 31 << 16, w: 248, r: 1984, p: 1987 },
];

export function requireFsbParams(hashBits: number): FsbParams {
  const found = FSB_PARAMS.find((p) => p.hashBits === hashBits);
  if (!found) {
    throw new Error(
      `FSB: no parameter set for a ${hashBits}-bit digest; the reference defines ` +
        `${FSB_PARAMS.map((p) => p.hashBits).join(", ")}.`,
    );
  }
  return found;
}

const log2 = (value: number): number => {
  for (let i = 0; i < 32; i++) if (value === 1 << i) return i;
  throw new Error(`FSB: ${value} is not a power of two, so the parameters are inconsistent.`);
};

interface Derived extends FsbParams {
  /** Quasi-cyclic blocks. */
  readonly b: number;
  /** Bits per column index. */
  readonly bpc: number;
  /** Message bits consumed per round. */
  readonly inputsize: number;
  /** Index bits taken from the syndrome, per column. */
  readonly bfiv: number;
  /** Index bits taken from the message, per column. */
  readonly bfm: number;
  /** Bytes per shifted first line. */
  readonly lineBytes: number;
  /** `first_line[block][shift & 7]`, the reference's eight pre-shifted copies. */
  readonly lines: readonly (readonly Uint8Array[])[];
}

function derive(params: FsbParams): Derived {
  const { n, w, r, p } = params;
  const b = n / r;
  const bpc = log2(n / w);
  const inputsize = w * bpc - r;
  const bfiv = r / w;
  const bfm = inputsize / w;
  if (r % 8 !== 0 || inputsize % 8 !== 0) {
    throw new Error("FSB: this implementation assumes r and inputsize are whole bytes.");
  }

  const pi = fsbPiTable();
  const lineBytes = ((p + r) >> 3) + 1;
  const perBlock = (p >> 3) + 1;
  const shift = p & 7;
  const lines: Uint8Array[][] = [];

  for (let k = 0; k < b; k++) {
    const base = k * perBlock;
    const zero = new Uint8Array(lineBytes);
    // The p-bit vector sits at bit offset r.
    for (let j = 0; j < p >> 3; j++) zero[(r >> 3) + j] = pi[base + j]!;
    zero[(p + r) >> 3] = pi[base + (p >> 3)]! & (((1 << shift) - 1) << (8 - shift)) & 0xff;
    // And the low r bits are its tail -- the quasi-cyclic wrap. See the header.
    for (let j = 0; j < r >> 3; j++) {
      zero[j] =
        (((zero[(p >> 3) + j]! << shift) | (zero[(p >> 3) + j + 1]! >> (8 - shift))) & 0xff) >>> 0;
    }
    const shifted: Uint8Array[] = [zero];
    for (let s = 1; s < 8; s++) {
      const line = new Uint8Array(lineBytes);
      for (let l = 0; l < (p + r) >> 3; l++) {
        line[l] = (line[l]! ^ (zero[l]! >> s)) & 0xff;
        line[l + 1] = (line[l + 1]! ^ ((zero[l]! << (8 - s)) & 0xff)) & 0xff;
      }
      shifted.push(line);
    }
    lines.push(shifted);
  }

  return { ...params, b, bpc, inputsize, bfiv, bfm, lineBytes, lines };
}

/**
 * Cached per digest length: building the lines touches the whole pi table.
 *
 * The eight pre-shifted copies are what the reference does and they are not free -- FSB-256's are
 * 2048 blocks x 8 shifts x 262 bytes, about 4 MB. That is the price of the byte-aligned inner loop, it
 * is paid once per digest length actually used, and it is why this is cached rather than rebuilt.
 */
const derivedCache = new Map<number, Derived>();

function derivedFor(hashBits: number): Derived {
  const cached = derivedCache.get(hashBits);
  if (cached) return cached;
  const built = derive(requireFsbParams(hashBits));
  derivedCache.set(hashBits, built);
  return built;
}

/** Bit `index` of a byte array, most significant bit of byte 0 first. */
const bitAt = (data: Uint8Array, index: number): number => (data[index >> 3]! >> (7 - (index & 7))) & 1;

/**
 * The column indices for one round.
 *
 * Shared by both formulations, because this is the *addressing* rather than the matrix -- and getting
 * it wrong would break both in the same way, so it is not where the cross-check earns its keep.
 */
function columnIndices(d: Derived, syndrome: Uint8Array, buffer: Uint8Array): number[] {
  const out: number[] = [];
  for (let i = 0; i < d.w; i++) {
    let index = i << d.bpc;
    for (let j = i * d.bfiv; j < (i + 1) * d.bfiv; j++) {
      index ^= bitAt(syndrome, j) << ((i + 1) * d.bfiv - j - 1);
    }
    for (let j = i * d.bfm; j < (i + 1) * d.bfm; j++) {
      index ^= bitAt(buffer, j) << ((i + 1) * d.bfm - j - 1 + d.bfiv);
    }
    out.push(index);
  }
  return out;
}

/**
 * One compression, the reference's formulation: byte-wise XOR out of the pre-shifted lines.
 *
 * The reference casts to `unsigned int*` and XORs words; that is byte-for-byte identical to this on any
 * endianness, because both operands are read from byte arrays with the same alignment.
 */
export function fsbCompress(hashBits: number, syndrome: Uint8Array, buffer: Uint8Array): Uint8Array {
  const d = derivedFor(hashBits);
  const next = new Uint8Array(d.r >> 3);
  for (const index of columnIndices(d, syndrome, buffer)) {
    const block = Math.floor(index / d.r);
    const shift = index - block * d.r;
    const line = d.lines[block]![shift & 7]!;
    const offset = (d.r >> 3) - (shift >> 3);
    for (let j = 0; j < d.r >> 3; j++) next[j] = (next[j]! ^ line[offset + j]!) & 0xff;
  }
  return next;
}

/**
 * The same compression, derived bit by bit from the specification.
 *
 * No precomputation and no shifted copies: for each column it reads the p-bit vector straight out of the
 * pi table, forms the quasi-cyclic extension `A = V[p - r .. p) ++ V` conceptually, and takes the r-bit
 * window at `shift`. This exists purely so the two can be required to agree -- see the header.
 */
export function fsbCompressReference(
  hashBits: number,
  syndrome: Uint8Array,
  buffer: Uint8Array,
): Uint8Array {
  const d = derivedFor(hashBits);
  const pi = fsbPiTable();
  const perBlock = (d.p >> 3) + 1;
  const next = new Uint8Array(d.r >> 3);

  for (const index of columnIndices(d, syndrome, buffer)) {
    const block = Math.floor(index / d.r);
    const shift = index - block * d.r;
    const base = block * perBlock;
    for (let t = 0; t < d.r; t++) {
      /**
       * The window starts at `r - shift`, not at `shift`.
       *
       * Worked out from the reference's byte arithmetic rather than guessed, and the first attempt here
       * had it the other way round -- which is exactly what this second formulation exists to catch.
       * Its byte loop reads `line[(r >> 3) - (shift >> 3) + j]` out of a copy right-shifted by
       * `shift & 7`, so column bit v is `A[r - shift + v]`. At shift 0 that is `A[r .. 2r)`, which is
       * the first r bits of V -- i.e. no rotation, which is the sanity check that fixes the direction.
       */
      const u = d.r - shift + t;
      const inVector = u < d.r ? d.p - d.r + u : u - d.r;
      const bit = (pi[base + (inVector >> 3)]! >> (7 - (inVector & 7))) & 1;
      if (bit) next[t >> 3] = next[t >> 3]! ^ (1 << (7 - (t & 7)));
    }
  }
  return next;
}

type Compressor = (hashBits: number, syndrome: Uint8Array, buffer: Uint8Array) => Uint8Array;

/** FSB, incremental. `compress` is swappable so the two formulations share every other line. */
export class FsbHash {
  private readonly d: Derived;
  private syndrome: Uint8Array;
  private buffer: Uint8Array;
  /** Bytes currently in the buffer. */
  private filled = 0;
  private messageBytes = 0;
  private done = false;

  constructor(
    private readonly hashBits: number,
    private readonly compress: Compressor = fsbCompress,
  ) {
    this.d = derivedFor(hashBits);
    this.syndrome = new Uint8Array(this.d.r >> 3);
    this.buffer = new Uint8Array(this.d.inputsize >> 3);
  }

  private round(): void {
    this.syndrome = this.compress(this.hashBits, this.syndrome, this.buffer);
    this.buffer = new Uint8Array(this.d.inputsize >> 3);
    this.filled = 0;
  }

  update(data: Uint8Array): void {
    if (this.done) throw new Error("FSB: update() after digest()");
    const blockBytes = this.d.inputsize >> 3;
    for (const byte of data) {
      this.buffer[this.filled++] = byte;
      this.messageBytes += 1;
      if (this.filled === blockBytes) this.round();
    }
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("FSB: digest() called twice");
    this.done = true;
    const blockBytes = this.d.inputsize >> 3;
    const bitLength = BigInt(this.messageBytes) * 8n;

    // A 1 bit, then zeros, then the 64-bit length at the end of a block -- and it may need two blocks.
    this.buffer[this.filled] = 0x80;
    this.filled += 1;
    if (this.filled + 8 > blockBytes) {
      // No room for the length: finish this block and give the length one of its own.
      this.round();
    }
    for (let i = 0; i < 8; i++) {
      this.buffer[blockBytes - 1 - i] = Number((bitLength >> BigInt(8 * i)) & 0xffn);
    }
    this.round();

    const wide = whirlpool(this.syndrome);
    return wide.slice(0, this.hashBits >> 3);
  }
}

export function createFsb(hashBits: number, compress: Compressor = fsbCompress): FsbHash {
  return new FsbHash(hashBits, compress);
}

export function fsb(hashBits: number, message: Uint8Array): Uint8Array {
  const h = new FsbHash(hashBits);
  h.update(message);
  return h.digest();
}

/** The bit-by-bit formulation, for the cross-check in `tests/algos-fsb.test.ts`. */
export function fsbViaReference(hashBits: number, message: Uint8Array): Uint8Array {
  const h = new FsbHash(hashBits, fsbCompressReference);
  h.update(message);
  return h.digest();
}

/** Derived parameters, for tests that assert the arithmetic rather than a digest. */
export function fsbDerivedParams(hashBits: number): {
  b: number;
  bpc: number;
  inputsize: number;
  bfiv: number;
  bfm: number;
  piBytesUsed: number;
} {
  const d = derivedFor(hashBits);
  return {
    b: d.b,
    bpc: d.bpc,
    inputsize: d.inputsize,
    bfiv: d.bfiv,
    bfm: d.bfm,
    piBytesUsed: d.b * ((d.p >> 3) + 1),
  };
}
