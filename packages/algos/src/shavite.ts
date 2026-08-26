/**
 * SHAvite-3, a SHA-3 second-round candidate, at all four output lengths.
 *
 * The most AES-shaped design in the competition after Groestl: a Davies-Meyer construction over a
 * block cipher whose round function is literally AES rounds, keyed by a schedule derived from the
 * message. It reuses the S-box `aes-round.ts` already derives, so nothing new is stored but the four
 * initial values.
 *
 * Five things to know.
 *
 * **The message is the key, not the plaintext.** The chaining value is enciphered and the message
 * drives the key schedule -- which is why a 64-byte block expands into 144 round-key words for the
 * short variants and a 128-byte block into 448 for the long ones.
 *
 * **The bit counter is XORed into four specific places in that schedule.** Not at the start, not
 * uniformly: at word offsets 16, 56, 84 and 124 for the small version and 32, 164, 316 and 440 for the
 * big one, with the two halves of the counter swapped between them and one of the two complemented
 * each time. Those offsets are the part to leave alone.
 *
 * **The words are little-endian, including inside the AES round.** SHAvite-3's own reference calls the
 * little-endian round function, which is the opposite of what `aes-round.ts` does for AES itself. So
 * the adapter below packs each 32-bit word least significant byte first, and getting that backwards
 * produces a hash that is perfectly self-consistent and matches nothing -- it was the first thing this
 * implementation got wrong.
 *
 * **The final block carries the counter and the digest size.** The counter goes at byte 54 (or 110)
 * little-endian, and the last two bytes hold the *digest* length in words -- 7, 8, 12 or 16 -- not the
 * state's. Using the state size there leaves 256 and 512 correct and breaks 224 and 384, which is
 * exactly how that was caught.
 *
 * **The short and long variants differ in more than width.** Six rounds of a two-branch Feistel with
 * three AES rounds per branch, against fourteen rounds of a four-branch one with four AES rounds per
 * branch and a column rotation between them.
 *
 * There is no oracle -- OpenSSL never implemented SHAvite-3 -- so the check is 72 known-answer vectors
 * from the SHA-3 competition's own KATs.
 */
import { AES_SBOX } from "./aes-round";

const u32 = (x: number): number => x >>> 0;
const xtime = (a: number): number => ((a << 1) ^ (a & 0x80 ? 0x1b : 0)) & 0xff;

/** The four initial values, parsed from the reference. */
const IV: Record<string, readonly number[]> = {
  224: [
    0x6774f31c, 0x990ae210, 0xc87d4274, 0xc9546371,
    0x62b2aea8, 0x4b5801d8, 0x1b702860, 0x842f3017,
  ],
  256: [
    0x49bb3e47, 0x2674860d, 0xa8b392ac, 0x021ac4e6,
    0x409283cf, 0x620e5d86, 0x6d929dcb, 0x96cc2a8b,
  ],
  384: [
    0x83df1545, 0xf9aaec13, 0xf4803cb0, 0x11fe1f47,
    0xda6cd269, 0x4f53fcd7, 0x950529a2, 0x97908147,
    0xb0a4d7af, 0x2b9132bf, 0x226e607d, 0x3c0f8d7c,
    0x487b3f0f, 0x04363e22, 0x0155c99c, 0xec2e20d3,
  ],
  512: [
    0x72fccdd8, 0x79ca4727, 0x128a077b, 0x40d55aec,
    0xd1901a06, 0x430ae307, 0xb29f5cd1, 0xdf07fbfc,
    0x8e45d73d, 0x681ab538, 0xbde86578, 0xdd577e47,
    0xe275eade, 0x502d9fcd, 0xb9357178, 0x022a4b9a,
  ],
};

/**
 * One AES round with no key added, over four little-endian 32-bit words.
 *
 * SubBytes, ShiftRows and MixColumns, with the state packed least significant byte first -- which is
 * what SHAvite-3's reference means by its little-endian round.
 */
function aesRoundNoKey(w: readonly number[]): number[] {
  const bytes = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    for (let b = 0; b < 4; b++) bytes[4 * c + b] = (w[c]! >>> (8 * b)) & 0xff;
  }
  const out = new Uint8Array(16);
  for (let c = 0; c < 4; c++) {
    const a0 = AES_SBOX[bytes[4 * c]!]!;
    const a1 = AES_SBOX[bytes[4 * ((c + 1) & 3) + 1]!]!;
    const a2 = AES_SBOX[bytes[4 * ((c + 2) & 3) + 2]!]!;
    const a3 = AES_SBOX[bytes[4 * ((c + 3) & 3) + 3]!]!;
    out[4 * c + 0] = (xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3) & 0xff;
    out[4 * c + 1] = (a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3) & 0xff;
    out[4 * c + 2] = (a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3) & 0xff;
    out[4 * c + 3] = (xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3)) & 0xff;
  }
  const result = [0, 0, 0, 0];
  for (let c = 0; c < 4; c++) {
    let value = 0;
    for (let b = 0; b < 4; b++) value = u32(value | (out[4 * c + b]! << (8 * b)));
    result[c] = value;
  }
  return result;
}

const readLe = (buf: Uint8Array, at: number): number =>
  u32(buf[at]! | (buf[at + 1]! << 8) | (buf[at + 2]! << 16) | (buf[at + 3]! << 24));

/** Where the counter is folded into the key schedule, per variant. */
interface CounterSpot {
  at: number;
  /** Target index and which counter word, `~` marking a complement. */
  writes: readonly (readonly [number, number, boolean])[];
}

const SMALL_SPOTS: readonly CounterSpot[] = [
  { at: 16, writes: [[16, 0, false], [17, 1, true]] },
  { at: 56, writes: [[57, 1, false], [58, 0, true]] },
  { at: 84, writes: [[86, 1, false], [87, 0, true]] },
  { at: 124, writes: [[124, 0, false], [127, 1, true]] },
];

const BIG_SPOTS: readonly CounterSpot[] = [
  { at: 32, writes: [[32, 0, false], [33, 1, false], [34, 2, false], [35, 3, true]] },
  { at: 164, writes: [[164, 3, false], [165, 2, false], [166, 1, false], [167, 0, true]] },
  { at: 316, writes: [[316, 2, false], [317, 3, false], [318, 0, false], [319, 1, true]] },
  { at: 440, writes: [[440, 1, false], [441, 0, false], [442, 3, false], [443, 2, true]] },
];

/**
 * The message-derived key schedule.
 *
 * `span` is the number of message words (16 or 32), `total` the schedule length (144 or 448). The
 * shape is the same for both: pairs of AES-derived quads, then a run of purely linear ones.
 */
function expand(block: Uint8Array, counts: readonly number[], big: boolean): Int32Array {
  const span = big ? 32 : 16;
  const total = big ? 448 : 144;
  const spots = big ? BIG_SPOTS : SMALL_SPOTS;
  const aesQuads = big ? 8 : 4;
  const linearQuads = big ? 8 : 4;

  const rk = new Int32Array(total);
  for (let i = 0; i < span; i++) rk[i] = readLe(block, i * 4);

  let u = span;
  for (;;) {
    for (let quad = 0; quad < aesQuads; quad++) {
      const x = aesRoundNoKey([
        rk[u - span + 1]!,
        rk[u - span + 2]!,
        rk[u - span + 3]!,
        rk[u - span]!,
      ]);
      for (let i = 0; i < 4; i++) rk[u + i] = u32(x[i]! ^ rk[u - 4 + i]!);
      for (const spot of spots) {
        if (spot.at !== u) continue;
        for (const [target, which, complement] of spot.writes) {
          const value = complement ? u32(~counts[which]!) : counts[which]!;
          rk[target] = u32(rk[target]! ^ value);
        }
      }
      u += 4;
    }
    if (u >= total) break;
    for (let quad = 0; quad < linearQuads; quad++) {
      // The linear run folds each quad against one from `span` words back, offset by three.
      const back = big ? 7 : 3;
      for (let i = 0; i < 4; i++) {
        rk[u + i] = u32(rk[u - span + i]! ^ rk[u - back + i]!);
      }
      u += 4;
    }
  }
  return rk;
}

/** The compression function: Davies-Meyer over the message-keyed cipher. */
function compress(h: Int32Array, block: Uint8Array, counts: readonly number[], big: boolean): void {
  const rk = expand(block, counts, big);
  const p = Array.from(h);
  const aesPerBranch = big ? 4 : 3;
  let k = 0;

  const branch = (target: number, source: number): void => {
    let x = [
      u32(p[source]! ^ rk[k]!),
      u32(p[source + 1]! ^ rk[k + 1]!),
      u32(p[source + 2]! ^ rk[k + 2]!),
      u32(p[source + 3]! ^ rk[k + 3]!),
    ];
    k += 4;
    x = aesRoundNoKey(x);
    for (let pass = 1; pass < aesPerBranch; pass++) {
      for (let i = 0; i < 4; i++) x[i] = u32(x[i]! ^ rk[k + i]!);
      k += 4;
      x = aesRoundNoKey(x);
    }
    for (let i = 0; i < 4; i++) p[target + i] = u32(p[target + i]! ^ x[i]!);
  };

  if (big) {
    for (let r = 0; r < 14; r++) {
      branch(0, 4);
      branch(8, 12);
      // A rotation of the four column groups, which the short variant does not have.
      for (let i = 0; i < 4; i++) {
        const t = p[12 + i]!;
        p[12 + i] = p[8 + i]!;
        p[8 + i] = p[4 + i]!;
        p[4 + i] = p[i]!;
        p[i] = t;
      }
    }
  } else {
    for (let r = 0; r < 6; r++) {
      branch(0, 4);
      branch(4, 0);
    }
  }

  for (let i = 0; i < h.length; i++) h[i] = u32(h[i]! ^ p[i]!);
}

/** A SHAvite-3 digest of any of the four standardised lengths. */
export function shavite(outputLen: 28 | 32 | 48 | 64, message: Uint8Array): Uint8Array {
  const big = outputLen > 32;
  const blockLen = big ? 128 : 64;
  const padTo = big ? 110 : 54;
  const h = Int32Array.from(IV[String(outputLen * 8)]!);
  const counts = [0, 0, 0, 0];

  const addBits = (bits: number): void => {
    let carry = BigInt(bits);
    for (let i = 0; i < 4 && carry > 0n; i++) {
      const sum = BigInt(counts[i]! >>> 0) + (carry & 0xffffffffn);
      counts[i] = u32(Number(sum & 0xffffffffn));
      carry = sum >> 32n;
    }
  };

  let at = 0;
  for (; at + blockLen <= message.length; at += blockLen) {
    addBits(blockLen * 8);
    compress(h, message.subarray(at, at + blockLen), counts, big);
  }

  const rest = message.length - at;
  addBits(rest * 8);
  const finalCounts = counts.slice();

  const buf = new Uint8Array(blockLen);
  buf.set(message.subarray(at));
  if (rest === 0) {
    buf[0] = 0x80;
    counts.fill(0);
  } else if (rest < padTo) {
    buf[rest] = 0x80;
  } else {
    // No room for the counter: this block goes through with the padding byte and a fresh one carries
    // the length, with the counter zeroed so the extra block does not advance it.
    buf[rest] = 0x80;
    compress(h, buf, counts, big);
    buf.fill(0);
    counts.fill(0);
  }

  const countWords = big ? 4 : 2;
  for (let i = 0; i < countWords; i++) {
    for (let b = 0; b < 4; b++) buf[padTo + i * 4 + b] = (finalCounts[i]! >>> (8 * b)) & 0xff;
  }
  // The *digest* size in words, not the state's: 7, 8, 12 or 16.
  const digestWords = outputLen / 4;
  buf[blockLen - 2] = (digestWords << 5) & 0xff;
  buf[blockLen - 1] = digestWords >> 3;
  compress(h, buf, counts, big);

  const out = new Uint8Array(outputLen);
  for (let i = 0; i < outputLen; i++) out[i] = (h[i >> 2]! >>> (8 * (i & 3))) & 0xff;
  return out;
}

/** An incremental SHAvite-3. Buffered, so the manifest reports `streaming: false`. */
export function createShavite(outputLen: 28 | 32 | 48 | 64): {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
} {
  const chunks: Uint8Array[] = [];
  let length = 0;
  return {
    update: (chunk) => {
      chunks.push(chunk);
      length += chunk.length;
    },
    digest: () => {
      const all = new Uint8Array(length);
      let offset = 0;
      for (const chunk of chunks) {
        all.set(chunk, offset);
        offset += chunk.length;
      }
      return shavite(outputLen, all);
    },
  };
}
