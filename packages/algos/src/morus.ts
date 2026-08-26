/**
 * MORUS, at all three CAESAR v2 parameter sets: MORUS-640-128, MORUS-1280-128 and MORUS-1280-256.
 *
 * **`broken`, and that is the whole caveat.** Ashur, Eichlseder, Lauridsen, Leurent, Minaud, Rotella,
 * Sasaki and Viguier's 2018 attack gives a correlation of about 2^-16 on MORUS-1280's keystream that
 * holds for the **full** cipher, not a reduced-round version -- so plaintext bits leak from ciphertext
 * without recovering the key. MORUS was a CAESAR finalist and lost partly because of it. Nothing should
 * be encrypted with this. It is here to reproduce values, and the tool says so.
 *
 * ## What stands behind it, stated precisely
 *
 * There is **no published known-answer file**. The CAESAR submission ships `ref/encrypt.c` and
 * SUPERCOP's `checksumsmall`, and the checksum is unusable for the reason recorded elsewhere in this
 * repo: reproducing SUPERCOP's `try.c` harness means a mismatch cannot say whether MORUS or the harness
 * is wrong. So what covers this is a **cross-check between two independent implementations**: this file
 * is a port of the designers' own `ref/encrypt.c` from the SUPERCOP tree, and it is checked against
 * `SparkDustJoe/PyMORUS`, a separately written Python implementation whose test-case file carries 20
 * vectors across both word widths.
 *
 * Be clear about what that is and is not. Two implementations by different authors, in different
 * languages, from the same specification agreeing on 20 vectors is real evidence about the
 * specification's *content* -- neither could plausibly have copied the other's bugs. It is **not** a
 * published vector, and PyMORUS cites no source for its values, so it could in principle be
 * self-generated. `tests/algos-morus.test.ts` says so rather than implying a KAT exists.
 *
 * ## Three things to preserve
 *
 * **The 640 and 1280 references order their lane shuffles differently, and the two are equivalent.**
 * In `morus640128v2` each round shuffles its register *after* the AND-and-rotate; in `morus1280128v2`
 * the shuffle sits between the XOR and the AND. That looks like a real difference and is not: in every
 * one of the five rounds the shuffled register is not one of the two AND operands, so moving the
 * shuffle across the AND cannot change anything. One implementation therefore serves both, and this
 * note exists so that nobody diffing the two references concludes otherwise.
 *
 * **MORUS-1280-128 doubles its key.** The 128-bit key becomes a 256-bit `ekey` by repeating it --
 * `ekey = [k0, k1, k0, k1]` -- and that doubled value is what gets XORed back into `state[1]` after the
 * sixteen initialisation rounds. MORUS-1280-256 uses its 256-bit key directly. So the two 1280 variants
 * are the same code with different key preparation, and zero-extending the short key instead of
 * repeating it gives a plausible wrong answer.
 *
 * **The length block is the *bit* length, and it is padded to the block.** `adlen << 3` and
 * `msglen << 3` go into the first two words; at 1280 the other two words are explicitly zero, so the
 * finalisation absorbs a 32-byte block of which half is zero. Ten rounds, not one.
 *
 * The associated data is processed through the *encryption* step with its output discarded, which is
 * why there is one `absorb` here rather than a separate AD path.
 */

export type MorusVariant = "640-128" | "1280-128" | "1280-256";

interface Params {
  readonly wordBits: 32 | 64;
  /** Bytes per block: four words. */
  readonly blockLen: number;
  readonly keyLen: number;
  readonly nonceLen: number;
  readonly rotations: readonly [number, number, number, number, number];
}

export const MORUS_VARIANTS: Readonly<Record<MorusVariant, Params>> = {
  "640-128": { wordBits: 32, blockLen: 16, keyLen: 16, nonceLen: 16, rotations: [5, 31, 7, 22, 13] },
  "1280-128": { wordBits: 64, blockLen: 32, keyLen: 16, nonceLen: 16, rotations: [13, 46, 38, 7, 4] },
  "1280-256": { wordBits: 64, blockLen: 32, keyLen: 32, nonceLen: 16, rotations: [13, 46, 38, 7, 4] },
};

export const MORUS_TAG_LEN = 16;

/** The 32 constant bytes. MORUS-640 splits them across state[3] and state[4]; 1280 puts all in [4]. */
const CONSTANT_BYTES = [
  0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
  0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
] as const;

type Lane = [bigint, bigint, bigint, bigint];

function makeOps(wordBits: 32 | 64) {
  const mask = (1n << BigInt(wordBits)) - 1n;
  const bytes = wordBits / 8;
  return {
    mask,
    bytes,
    rotl: (x: bigint, n: number): bigint =>
      n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(wordBits - n))) & mask,
    read: (src: Uint8Array, at: number): bigint => {
      let v = 0n;
      for (let i = bytes - 1; i >= 0; i--) v = (v << 8n) | BigInt(src[at + i] ?? 0);
      return v;
    },
    write: (value: bigint, dst: Uint8Array, at: number): void => {
      for (let i = 0; i < bytes; i++) dst[at + i] = Number((value >> BigInt(8 * i)) & 0xffn);
    },
  };
}

/** Rotate a four-lane register left by one slot: `[a,b,c,d] -> [d,a,b,c]` in the reference's terms. */
const rotate1 = (r: Lane): void => {
  const t = r[3];
  r[3] = r[2];
  r[2] = r[1];
  r[1] = r[0];
  r[0] = t;
};

/** Swap the two halves: `[a,b,c,d] -> [c,d,a,b]`. */
const swapHalves = (r: Lane): void => {
  let t = r[3];
  r[3] = r[1];
  r[1] = t;
  t = r[2];
  r[2] = r[0];
  r[0] = t;
};

class MorusState {
  readonly s: [Lane, Lane, Lane, Lane, Lane];
  private readonly ops: ReturnType<typeof makeOps>;
  private readonly rot: readonly [number, number, number, number, number];

  constructor(private readonly params: Params) {
    this.ops = makeOps(params.wordBits);
    this.rot = params.rotations;
    const zero = (): Lane => [0n, 0n, 0n, 0n];
    this.s = [zero(), zero(), zero(), zero(), zero()];
  }

  /**
   * One state update.
   *
   * The lane shuffle is placed *after* the AND-and-rotate, matching `morus640128v2`. See the header for
   * why that is equivalent to `morus1280128v2`'s placement.
   */
  update(msg: Lane): void {
    const { rotl, mask } = this.ops;
    const [s0, s1, s2, s3, s4] = this.s;
    const [n1, n2, n3, n4, n5] = this.rot;

    for (let i = 0; i < 4; i++) s0[i] = (s0[i]! ^ s3[i]! ^ (s1[i]! & s2[i]!)) & mask;
    for (let i = 0; i < 4; i++) s0[i] = rotl(s0[i]!, n1);
    rotate1(s3);

    for (let i = 0; i < 4; i++) s1[i] = (s1[i]! ^ msg[i]! ^ s4[i]! ^ (s2[i]! & s3[i]!)) & mask;
    for (let i = 0; i < 4; i++) s1[i] = rotl(s1[i]!, n2);
    swapHalves(s4);

    for (let i = 0; i < 4; i++) s2[i] = (s2[i]! ^ msg[i]! ^ s0[i]! ^ (s3[i]! & s4[i]!)) & mask;
    for (let i = 0; i < 4; i++) s2[i] = rotl(s2[i]!, n3);
    // s0 rotates the other way: [a,b,c,d] -> [b,c,d,a].
    {
      const t = s0[0]!;
      s0[0] = s0[1]!;
      s0[1] = s0[2]!;
      s0[2] = s0[3]!;
      s0[3] = t;
    }

    for (let i = 0; i < 4; i++) s3[i] = (s3[i]! ^ msg[i]! ^ s1[i]! ^ (s4[i]! & s0[i]!)) & mask;
    for (let i = 0; i < 4; i++) s3[i] = rotl(s3[i]!, n4);
    swapHalves(s1);

    for (let i = 0; i < 4; i++) s4[i] = (s4[i]! ^ msg[i]! ^ s2[i]! ^ (s0[i]! & s1[i]!)) & mask;
    for (let i = 0; i < 4; i++) s4[i] = rotl(s4[i]!, n5);
    rotate1(s2);
  }

  /** The keystream block: `s0 ^ rotate(s1) ^ (s2 & s3)`, with s1 taken one slot along. */
  keystream(): Lane {
    const { mask } = this.ops;
    const [s0, s1, s2, s3] = this.s;
    return [0, 1, 2, 3].map(
      (i) => (s0[i]! ^ s1[(i + 1) & 3]! ^ (s2[i]! & s3[i]!)) & mask,
    ) as unknown as Lane;
  }

  initialize(key: Uint8Array, nonce: Uint8Array): void {
    const { read, bytes } = this.ops;
    const words = 4;
    const constants = Uint8Array.from(CONSTANT_BYTES);

    if (this.params.wordBits === 32) {
      for (let i = 0; i < words; i++) this.s[0][i] = read(nonce, 4 * i);
      for (let i = 0; i < words; i++) this.s[1][i] = read(key, 4 * i);
      for (let i = 0; i < words; i++) this.s[2][i] = (1n << 32n) - 1n;
      for (let i = 0; i < words; i++) this.s[3][i] = read(constants, 4 * i);
      for (let i = 0; i < words; i++) this.s[4][i] = read(constants, 16 + 4 * i);
    } else {
      // The nonce is 16 bytes into a 32-byte register: two words, then two zeros.
      this.s[0][0] = read(nonce, 0);
      this.s[0][1] = read(nonce, 8);
      this.s[0][2] = 0n;
      this.s[0][3] = 0n;
      for (let i = 0; i < words; i++) this.s[2][i] = (1n << 64n) - 1n;
      for (let i = 0; i < words; i++) this.s[3][i] = 0n;
      for (let i = 0; i < words; i++) this.s[4][i] = read(constants, 8 * i);
    }

    // MORUS-1280-128 repeats its 128-bit key to fill the 256-bit register. See the header.
    const expanded: Lane =
      this.params.wordBits === 32
        ? [this.s[1][0], this.s[1][1], this.s[1][2], this.s[1][3]]
        : this.params.keyLen === 16
          ? [read(key, 0), read(key, 8), read(key, 0), read(key, 8)]
          : [read(key, 0), read(key, 8), read(key, 16), read(key, 24)];
    if (this.params.wordBits === 64) {
      for (let i = 0; i < words; i++) this.s[1][i] = expanded[i]!;
    }

    const zero: Lane = [0n, 0n, 0n, 0n];
    for (let i = 0; i < 16; i++) this.update(zero);
    for (let i = 0; i < words; i++) this.s[1][i] = this.s[1][i]! ^ expanded[i]!;
    void bytes;
  }

  /**
   * One block in either direction, over a whole or partial block.
   *
   * The state always absorbs *plaintext*, so decrypting a partial block has to zero the tail of the
   * recovered plaintext before absorbing it -- the reference does this with an explicit memset, and
   * skipping it leaves every full block correct and every partial one wrong.
   */
  process(
    input: Uint8Array,
    at: number,
    length: number,
    out: Uint8Array | null,
    outAt: number,
    decrypt: boolean,
  ): void {
    const { read, write, bytes } = this.ops;
    const block = this.params.blockLen;
    const padded = new Uint8Array(block);
    const keystream = this.keystream();

    if (decrypt) {
      padded.set(input.subarray(at, at + length));
      const plain = new Uint8Array(block);
      for (let i = 0; i < 4; i++) write(read(padded, bytes * i) ^ keystream[i]!, plain, bytes * i);
      if (out) out.set(plain.subarray(0, length), outAt);
      // Only the recovered bytes go back into the state; the tail is zero, not keystream.
      const absorbed = new Uint8Array(block);
      absorbed.set(plain.subarray(0, length));
      this.update([0, 1, 2, 3].map((i) => read(absorbed, bytes * i)) as unknown as Lane);
    } else {
      padded.set(input.subarray(at, at + length));
      const cipher = new Uint8Array(block);
      for (let i = 0; i < 4; i++) write(read(padded, bytes * i) ^ keystream[i]!, cipher, bytes * i);
      if (out) out.set(cipher.subarray(0, length), outAt);
      this.update([0, 1, 2, 3].map((i) => read(padded, bytes * i)) as unknown as Lane);
    }
  }

  absorb(data: Uint8Array): void {
    const block = this.params.blockLen;
    let at = 0;
    for (; at + block <= data.length; at += block) this.process(data, at, block, null, 0, false);
    const rest = data.length - at;
    if (rest !== 0) this.process(data, at, rest, null, 0, false);
  }

  finalize(adLength: number, messageLength: number): Uint8Array {
    const { read, write, bytes } = this.ops;
    const block = this.params.blockLen;
    const lengths = new Uint8Array(block);
    // Bit lengths, as two 64-bit little-endian values; the rest of the block is zero.
    let ad = BigInt(adLength) << 3n;
    let msg = BigInt(messageLength) << 3n;
    for (let i = 0; i < 8; i++) {
      lengths[i] = Number(ad & 0xffn);
      ad >>= 8n;
      lengths[8 + i] = Number(msg & 0xffn);
      msg >>= 8n;
    }
    for (let i = 0; i < 4; i++) this.s[4][i] = this.s[4][i]! ^ this.s[0][i]!;
    const lane = [0, 1, 2, 3].map((i) => read(lengths, bytes * i)) as unknown as Lane;
    for (let i = 0; i < 10; i++) this.update(lane);
    const tagWords = this.keystream();
    const wide = new Uint8Array(block);
    for (let i = 0; i < 4; i++) write(tagWords[i]!, wide, bytes * i);
    // The tag is always the first sixteen bytes, whatever the word size.
    return wide.slice(0, MORUS_TAG_LEN);
  }
}

function requireInputs(params: Params, variant: MorusVariant, key: Uint8Array, nonce: Uint8Array): void {
  if (key.length !== params.keyLen) {
    throw new Error(`MORUS-${variant}'s key is exactly ${params.keyLen} bytes; this one is ${key.length}.`);
  }
  if (nonce.length !== params.nonceLen) {
    throw new Error(`MORUS-${variant}'s nonce is exactly ${params.nonceLen} bytes; this one is ${nonce.length}.`);
  }
}

export function morusSeal(
  variant: MorusVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
  plaintext: Uint8Array,
): { ciphertext: Uint8Array; tag: Uint8Array } {
  const params = MORUS_VARIANTS[variant];
  if (!params) throw new Error(`MORUS: unknown parameter set "${String(variant)}"`);
  requireInputs(params, variant, key, nonce);
  const state = new MorusState(params);
  state.initialize(key, nonce);
  state.absorb(associatedData);

  const ciphertext = new Uint8Array(plaintext.length);
  const block = params.blockLen;
  let at = 0;
  for (; at + block <= plaintext.length; at += block) {
    state.process(plaintext, at, block, ciphertext, at, false);
  }
  const rest = plaintext.length - at;
  if (rest !== 0) state.process(plaintext, at, rest, ciphertext, at, false);

  return { ciphertext, tag: state.finalize(associatedData.length, plaintext.length) };
}

/** Returns null when the tag does not match. */
export function morusOpen(
  variant: MorusVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  associatedData: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
): Uint8Array | null {
  const params = MORUS_VARIANTS[variant];
  if (!params) throw new Error(`MORUS: unknown parameter set "${String(variant)}"`);
  requireInputs(params, variant, key, nonce);
  const state = new MorusState(params);
  state.initialize(key, nonce);
  state.absorb(associatedData);

  const plaintext = new Uint8Array(ciphertext.length);
  const block = params.blockLen;
  let at = 0;
  for (; at + block <= ciphertext.length; at += block) {
    state.process(ciphertext, at, block, plaintext, at, true);
  }
  const rest = ciphertext.length - at;
  if (rest !== 0) state.process(ciphertext, at, rest, plaintext, at, true);

  const expected = state.finalize(associatedData.length, ciphertext.length);
  if (expected.length !== tag.length) return null;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i]! ^ tag[i]!;
  return diff === 0 ? plaintext : null;
}
