/**
 * Skein and the Threefish block cipher it is built on. Skein 1.3, the SHA-3 finalist.
 *
 * Three state sizes -- 256, 512 and 1024 bits -- each producing any output length. Skein lost SHA-3
 * to Keccak and remains unbroken and widely liked; it appears in Bitcoin-adjacent proof-of-work
 * chains, in `skeinsum`, and in Bouncy Castle. Nothing in this project's dependency tree has it.
 *
 * Five things to know before touching this.
 *
 * **Everything is little-endian.** Words, the tweak, the output counter, the configuration block.
 * Skein is one of the few designs that is little-endian throughout, and mixing that up produces a hash
 * that is self-consistent and matches nothing.
 *
 * **The output length is part of the function, not a truncation.** It goes into the configuration
 * block that produces the initial chaining value, so Skein-512-256 is *not* the first 32 bytes of
 * Skein-512-512. That is why the hash family files these as `parameterized` rather than `xof`, and
 * why `tests/algos-skein.test.ts` asserts the two disagree.
 *
 * **UBI is the whole construction.** Every phase -- configuration, message, output -- is the same
 * chaining mode over Threefish with a different 128-bit tweak, and the tweak's type field plus its
 * first/final flags are what keep the phases apart. Two of Skein's three phases are a single block, so
 * an implementation can get the flags wrong and still hash a short message correctly.
 *
 * **Threefish is 64-bit *addition*, not just bitwise work.** That rules out the trick that makes
 * Ascon fast here, and it is why this uses `u64.ts` -- the module that exists so 64-bit carry handling
 * is written once. 72 rounds per block (80 for the 1024-bit state) makes Skein the slowest hash in
 * this repo by some margin; a workbench hashing pasted text will not notice, and the note on the
 * metadata says so for anyone reaching for it on a large file.
 *
 * **The tables are data, and were checked against a second implementation before use.** The eight
 * rows of rotation constants per state size and the word permutations come from the Skein 1.3
 * specification, section 3.3; each permutation was verified against the inlined form in Bouncy
 * Castle's `ThreefishEngine` before being written down, and the whole lot is checked on every run by
 * the golden-KAT vectors in the test.
 */
import { add64, copy64, readU64LE, rotl64, u64, writeU64LE, xor64, type U64 } from "./u64";

/** State sizes in bytes. */
export const SKEIN_STATE_SIZES: readonly number[] = [32, 64, 128];

/** Threefish's key-schedule parity constant, Skein 1.3 section 3.3.2. */
const C240 = u64(0x1bd11bda, 0xa9fc1a22);

/**
 * The mix rotation constants, eight rounds by `Nw / 2` columns per state size.
 *
 * Skein 1.3 table 4. The eight-row cycle is why the round loop indexes `round % 8`.
 */
const ROTATIONS: Record<number, readonly (readonly number[])[]> = {
  4: [
    [14, 16],
    [52, 57],
    [23, 40],
    [5, 37],
    [25, 33],
    [46, 12],
    [58, 22],
    [32, 32],
  ],
  8: [
    [46, 36, 19, 37],
    [33, 27, 14, 42],
    [17, 49, 36, 39],
    [44, 9, 54, 56],
    [39, 30, 34, 24],
    [13, 50, 10, 17],
    [25, 29, 39, 43],
    [8, 35, 56, 22],
  ],
  16: [
    [24, 13, 8, 47, 8, 17, 22, 37],
    [38, 19, 10, 55, 49, 18, 23, 52],
    [33, 4, 51, 13, 34, 41, 59, 17],
    [5, 20, 48, 41, 47, 28, 16, 25],
    [41, 9, 37, 31, 12, 47, 44, 30],
    [16, 34, 56, 51, 4, 53, 42, 41],
    [31, 44, 47, 46, 19, 42, 44, 25],
    [9, 48, 35, 52, 23, 31, 37, 20],
  ],
};

/**
 * The word permutation applied after each round: `next[i] = current[PERMUTATION[i]]`.
 *
 * Skein 1.3 table 3. Written in the direction the specification states it, which is the direction that
 * makes the round loop a copy rather than a scatter.
 */
const PERMUTATIONS: Record<number, readonly number[]> = {
  4: [0, 3, 2, 1],
  8: [2, 1, 4, 7, 6, 5, 0, 3],
  16: [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1],
};

/** 72 rounds for the two smaller states, 80 for the largest. */
const ROUNDS: Record<number, number> = { 4: 72, 8: 72, 16: 80 };

/** UBI block types, Skein 1.3 table 5. Four are reachable from here. */
const TYPE_KEY = 0;
const TYPE_CONFIG = 4;
const TYPE_MESSAGE = 48;
const TYPE_OUTPUT = 63;

/**
 * Threefish encryption in place: `block` is overwritten with the ciphertext.
 *
 * Only the forward direction exists, because UBI only ever encrypts -- Skein never decrypts anything,
 * and an unused inverse is a liability rather than a feature.
 */
function threefishEncrypt(
  nw: number,
  key: readonly U64[],
  tweak: readonly U64[],
  block: U64[],
  scratch: { keySchedule: U64[]; permuted: U64[]; temp: U64 },
): void {
  const rotations = ROTATIONS[nw]!;
  const permutation = PERMUTATIONS[nw]!;
  const rounds = ROUNDS[nw]!;
  const { keySchedule: ks, permuted, temp } = scratch;

  /**
   * The extended key: the `Nw` key words plus a parity word, and three tweak words.
   *
   * `t[2] = t[0] ^ t[1]` and `k[Nw] = C240 ^ (all key words)`, both from section 3.3.2. Computing
   * them once and indexing modulo `Nw + 1` is what the specification's subkey formula reduces to.
   */
  const extendedKey: U64[] = [];
  for (let i = 0; i < nw; i++) extendedKey.push(key[i]!);
  const parity = u64(C240.hi, C240.lo);
  for (let i = 0; i < nw; i++) xor64(parity, parity, key[i]!);
  extendedKey.push(parity);

  const t: U64[] = [tweak[0]!, tweak[1]!, xor64(u64(), tweak[0]!, tweak[1]!)];

  const injectSubkey = (s: number): void => {
    for (let i = 0; i < nw; i++) {
      copy64(ks[i]!, extendedKey[(s + i) % (nw + 1)]!);
    }
    // The two tweak words land in the last three positions, along with the subkey counter.
    add64(ks[nw - 3]!, ks[nw - 3]!, t[s % 3]!);
    add64(ks[nw - 2]!, ks[nw - 2]!, t[(s + 1) % 3]!);
    add64(ks[nw - 1]!, ks[nw - 1]!, u64(0, s));
    for (let i = 0; i < nw; i++) add64(block[i]!, block[i]!, ks[i]!);
  };

  injectSubkey(0);

  for (let round = 0; round < rounds; round++) {
    const rotation = rotations[round % 8]!;
    for (let j = 0; j < nw / 2; j++) {
      const x = block[2 * j]!;
      const y = block[2 * j + 1]!;
      // MIX: x += y; y = rotl(y, r) ^ x.
      add64(x, x, y);
      rotl64(temp, y, rotation[j]!);
      xor64(y, temp, x);
    }

    // Permute, then inject a subkey every fourth round.
    for (let i = 0; i < nw; i++) copy64(permuted[i]!, block[permutation[i]!]!);
    for (let i = 0; i < nw; i++) copy64(block[i]!, permuted[i]!);

    if (round % 4 === 3) injectSubkey((round + 1) / 4);
  }
}

/** One UBI block: `G = E(G, tweak, block) ^ block`. */
function ubiBlock(
  nw: number,
  g: U64[],
  blockWords: U64[],
  tweak: readonly U64[],
  scratch: { keySchedule: U64[]; permuted: U64[]; temp: U64; cipher: U64[] },
): void {
  const { cipher } = scratch;
  for (let i = 0; i < nw; i++) copy64(cipher[i]!, blockWords[i]!);
  threefishEncrypt(nw, g, tweak, cipher, scratch);
  for (let i = 0; i < nw; i++) xor64(g[i]!, cipher[i]!, blockWords[i]!);
}

/**
 * The 128-bit tweak.
 *
 * Bit layout, from Skein 1.3 section 3.2: bits 0..95 are the byte position, 112..118 the tree level,
 * 119 the bit-pad flag, 120..125 the type, 126 "first" and 127 "final". Positions here never exceed
 * 2^53 bytes, so the high half carries only the flags and the top of the position -- which is written
 * out as arithmetic rather than shifts, because `1 << 62` is not a thing in JavaScript.
 */
function makeTweak(position: number, type: number, first: boolean, final: boolean): U64[] {
  const low = u64(Math.floor(position / 0x1_0000_0000) >>> 0, position >>> 0);
  const flagsHigh = type * 0x100_0000 + (first ? 0x4000_0000 : 0) + (final ? 0x8000_0000 : 0);
  return [low, u64(flagsHigh >>> 0, 0)];
}

export interface SkeinHasher {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

class Skein implements SkeinHasher {
  private readonly nw: number;
  private readonly nb: number;
  private readonly g: U64[];
  private readonly buffer: Uint8Array;
  private readonly blockWords: U64[];
  private readonly scratch: {
    keySchedule: U64[];
    permuted: U64[];
    temp: U64;
    cipher: U64[];
  };
  private buffered = 0;
  private position = 0;
  private first = true;
  private done = false;

  constructor(
    stateBytes: number,
    private readonly outputLen: number,
    key?: Uint8Array,
  ) {
    if (!SKEIN_STATE_SIZES.includes(stateBytes)) {
      throw new Error(`Skein's state is 32, 64 or 128 bytes; ${stateBytes} was requested.`);
    }
    if (outputLen <= 0) throw new Error("Skein: output length must be positive");

    this.nb = stateBytes;
    this.nw = stateBytes / 8;
    this.g = Array.from({ length: this.nw }, () => u64());
    this.buffer = new Uint8Array(stateBytes);
    this.blockWords = Array.from({ length: this.nw }, () => u64());
    this.scratch = {
      keySchedule: Array.from({ length: this.nw }, () => u64()),
      permuted: Array.from({ length: this.nw }, () => u64()),
      temp: u64(),
      cipher: Array.from({ length: this.nw }, () => u64()),
    };

    /**
     * Skein-MAC is Skein with a key block, and the order is the whole trick.
     *
     * `G0 = UBI(0, K, T_key)` runs *before* the configuration block, so the key changes the initial
     * chaining value that the configuration then transforms. That is why Skein needs no HMAC: there is
     * no nesting, no ipad/opad, and one pass over the message. Feeding the key as though it were
     * message data instead would produce a perfectly stable tag that nothing else agrees with.
     */
    if (key && key.length > 0) this.ubi(key, TYPE_KEY);
    this.configure();
  }

  /**
   * A complete UBI pass over a byte array, used for the key and configuration blocks.
   *
   * Separate from the streaming message path because both of these are known in full up front, so
   * there is no need for the keep-one-block-in-hand dance that `update` has to do.
   */
  private ubi(data: Uint8Array, type: number): void {
    const block = new Uint8Array(this.nb);
    let position = 0;
    let first = true;

    // An empty input still gets one (zero) block, which is what the specification's UBI does.
    for (let at = 0; at === 0 || at < data.length; at += this.nb) {
      const take = Math.min(this.nb, Math.max(data.length - at, 0));
      block.fill(0);
      block.set(data.subarray(at, at + take));
      position += take;
      const final = at + this.nb >= data.length;
      this.loadBlock(block, 0);
      ubiBlock(this.nw, this.g, this.blockWords, makeTweak(position, type, first, final), this.scratch);
      first = false;
      if (final) break;
    }
  }

  /**
   * The configuration block, which is what makes the initial chaining value depend on the output
   * length.
   *
   * 32 bytes: the schema identifier "SHA3", a 16-bit version, the output length in *bits* as a 64-bit
   * little-endian value, and tree parameters left at zero for sequential hashing. Everything after
   * byte 16 is zero here; a tree-mode Skein would fill it in.
   */
  private configure(): void {
    const config = new Uint8Array(this.nb);
    config[0] = 0x53; // 'S'
    config[1] = 0x48; // 'H'
    config[2] = 0x41; // 'A'
    config[3] = 0x33; // '3'
    config[4] = 1; // version 1, little-endian 16-bit
    // Output length in bits, 64-bit little-endian at offset 8.
    let bits = this.outputLen * 8;
    for (let i = 0; i < 8; i++) {
      config[8 + i] = bits % 256;
      bits = Math.floor(bits / 256);
    }

    // Always exactly one block, and always `first` -- the key block before it does not change that,
    // because each UBI pass has its own first/final flags.
    this.loadBlock(config, 0);
    ubiBlock(this.nw, this.g, this.blockWords, makeTweak(32, TYPE_CONFIG, true, true), this.scratch);
  }

  private loadBlock(bytes: Uint8Array, at: number): void {
    for (let i = 0; i < this.nw; i++) {
      const word = readU64LE(bytes, at + i * 8);
      copy64(this.blockWords[i]!, word);
    }
  }

  update(chunk: Uint8Array): void {
    if (this.done) throw new Error("Skein: update after digest");

    let offset = 0;
    while (offset < chunk.length) {
      if (this.buffered === this.nb) {
        /**
         * A full buffer is only processed once more data is known to exist.
         *
         * UBI needs the "final" flag on the last block, and whether a block is last is only knowable
         * when the next byte arrives -- so this keeps a whole block in hand, exactly as the reference
         * does. An implementation that flushed eagerly would set `final` on nothing and hash every
         * block-aligned message wrongly.
         */
        this.processBuffered(false);
      }
      const take = Math.min(this.nb - this.buffered, chunk.length - offset);
      this.buffer.set(chunk.subarray(offset, offset + take), this.buffered);
      this.buffered += take;
      offset += take;
    }
  }

  private processBuffered(final: boolean): void {
    this.position += this.buffered;
    // The final block is zero-padded; the position counts real bytes, not padding.
    if (this.buffered < this.nb) this.buffer.fill(0, this.buffered);
    this.loadBlock(this.buffer, 0);
    ubiBlock(
      this.nw,
      this.g,
      this.blockWords,
      makeTweak(this.position, TYPE_MESSAGE, this.first, final),
      this.scratch,
    );
    this.first = false;
    this.buffered = 0;
  }

  digest(): Uint8Array {
    if (this.done) throw new Error("Skein: digest called twice");
    this.done = true;

    // Always one final message block, even for an empty message.
    this.processBuffered(true);

    /**
     * Output generation: UBI over an incrementing 64-bit counter, one call per output block.
     *
     * The chaining value is the *key* for each of these, so every output block starts from the same
     * state -- which is what makes the counter necessary and why the counter is what is hashed rather
     * than the previous output.
     */
    const out = new Uint8Array(this.outputLen);
    const counterBlock = new Uint8Array(this.nb);
    const state = this.g.map((word) => u64(word.hi, word.lo));

    for (let at = 0, counter = 0; at < this.outputLen; at += this.nb, counter++) {
      counterBlock.fill(0);
      writeU64LE(counterBlock, 0, u64(Math.floor(counter / 0x1_0000_0000) >>> 0, counter >>> 0));

      for (let i = 0; i < this.nw; i++) copy64(this.g[i]!, state[i]!);
      this.loadBlock(counterBlock, 0);
      ubiBlock(
        this.nw,
        this.g,
        this.blockWords,
        makeTweak(8, TYPE_OUTPUT, true, true),
        this.scratch,
      );

      const chunk = new Uint8Array(this.nb);
      for (let i = 0; i < this.nw; i++) writeU64LE(chunk, i * 8, this.g[i]!);
      out.set(chunk.subarray(0, Math.min(this.nb, this.outputLen - at)), at);
    }
    return out;
  }
}

/**
 * `stateBytes` is 32, 64 or 128 -- Skein-256, Skein-512 or Skein-1024.
 *
 * Pass a `key` and this is Skein-MAC, the keyed mode the Skein specification defines. Any key length
 * is accepted, including one longer than the state: UBI absorbs it in blocks, so there is no
 * hash-the-key-down step and no block-size ceiling of the kind HMAC has.
 */
export function createSkein(
  stateBytes: number,
  outputLen: number,
  key?: Uint8Array,
): SkeinHasher {
  return new Skein(stateBytes, outputLen, key);
}

export function skein(data: Uint8Array, stateBytes: number, outputLen: number): Uint8Array {
  const h = createSkein(stateBytes, outputLen);
  h.update(data);
  return h.digest();
}

/** Skein-MAC: the same function with a key block. */
export function skeinMac(
  key: Uint8Array,
  data: Uint8Array,
  stateBytes: number,
  outputLen: number,
): Uint8Array {
  const h = createSkein(stateBytes, outputLen, key);
  h.update(data);
  return h.digest();
}
