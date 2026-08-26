/**
 * Fugue, a SHA-3 second-round candidate, at all four output lengths.
 *
 * IBM's entry, and the one whose shape is least like anything else here: there is no block. The state
 * is a ring of 30 or 36 32-bit columns, one *word* of message is injected per round, and the round
 * rotates the whole ring rather than the message advancing through it. That makes the code below read
 * oddly -- every index is relative to a moving base -- and it is why the reference implementation
 * unrolls five (or three, or four) cases instead.
 *
 * Five things to know.
 *
 * **Every table is derived from the AES S-box.** Fugue's SuperMix is usually shipped as four 1 KB
 * lookup tables; they are `(S[x], S[x], S[x]*7, S[x]*4)` in GF(2^8) under AES's polynomial, rotated
 * one byte per table. So nothing is stored but the four initial values, and
 * `tests/algos-sha3-candidates.test.ts` checks the derivation against the reference's own tables entry
 * for entry as well as against the vectors.
 *
 * **The base moves by three columns per sub-round, and by `3 * kind` per input word.** Fugue-224 and
 * -256 do two CMIX/SMIX passes per word, -384 does three, -512 does four -- which is also how many
 * columns the TIX step reaches into. One parameter, three behaviours.
 *
 * **TIX is not the same shape at each size.** The 30-column version touches five columns, the
 * 36-column ones seven and nine. They are written out rather than parameterised because the offsets
 * are not a pattern.
 *
 * **Only whole words are absorbed, and the last one is held back.** The reference deliberately keeps
 * the final four bytes as a partial and processes them at the end, followed by the 64-bit bit count as
 * two more words. Anything else changes where the count lands relative to the ring.
 *
 * **The finalisation is three different routines.** Ten rounds then thirteen double-steps for the
 * short variants; eighteen then thirteen triple-steps for 384; thirty-two then thirteen quadruple-steps
 * for 512. The rotation amounts inside those loops are irregular -- 15 and 14, or 12, 12 and 11, or 9,
 * 9, 9 and 8 -- and they are the part a reader should not try to tidy.
 *
 * There is no oracle: OpenSSL never implemented Fugue and no dependency here does. The check is 72
 * known-answer vectors from the SHA-3 competition's own KATs.
 */
import { AES_SBOX } from "./aes-round";

const u32 = (x: number): number => x >>> 0;

/** Multiplication in GF(2^8) under AES's polynomial; only 4 and 7 ever appear. */
function gmul(a: number, b: number): number {
  let left = a;
  let right = b;
  let product = 0;
  for (let i = 0; i < 8; i++) {
    if (right & 1) product ^= left;
    const overflow = left & 0x80;
    left = (left << 1) & 0xff;
    if (overflow) left ^= 0x1b;
    right >>= 1;
  }
  return product & 0xff;
}

/**
 * The four SuperMix tables, derived rather than stored.
 *
 * `MIX[0][x]` is the word `(S, S, S*7, S*4)` and the other three are that rotated right by one, two
 * and three bytes -- which is what the reference's `mixtab1..3` are, checked in the tests.
 */
export const FUGUE_MIX: readonly Uint32Array[] = (() => {
  const tables = [new Uint32Array(256), new Uint32Array(256), new Uint32Array(256), new Uint32Array(256)];
  for (let x = 0; x < 256; x++) {
    const s = AES_SBOX[x]!;
    const word = u32((s << 24) | (s << 16) | (gmul(s, 7) << 8) | gmul(s, 4));
    tables[0]![x] = word;
    tables[1]![x] = u32((word >>> 8) | (word << 24));
    tables[2]![x] = u32((word >>> 16) | (word << 16));
    tables[3]![x] = u32((word >>> 24) | (word << 8));
  }
  return tables;
})();

/** The four initial values, parsed from the reference. They are the only stored constants here. */
const IV: Record<string, readonly number[]> = {
  224: [
    0xf4c9120d, 0x6286f757, 0xee39e01c, 0xe074e3cb,
    0xa1127c62, 0x9a43d215, 0xbd8d679a,
  ],
  256: [
    0xe952bdde, 0x6671135f, 0xe0d4f668, 0xd2b0b594,
    0xf96c621d, 0xfbf929de, 0x9149e899, 0x34f8c248,
  ],
  384: [
    0xaa61ec0d, 0x31252e1f, 0xa01db4c7, 0x00600985,
    0x215ef44a, 0x741b5e9c, 0xfa693e9a, 0x473eb040,
    0xe502ae8a, 0xa99c25e0, 0xbc95517c, 0x5c1095a1,
  ],
  512: [
    0x8807a57e, 0xe616af75, 0xc5d3e4db, 0xac9ab027,
    0xd915f117, 0xb6eecc54, 0x06e8020b, 0x4a92efd1,
    0xaac6e2c9, 0xddb21398, 0xcae65838, 0x437f203f,
    0x25ea78e7, 0x951fddd6, 0xda6ed11d, 0xe13e3567,
  ],
};

/** SuperMix on the four columns starting at `base`. */
function smix(state: Uint32Array, base: number, n: number): void {
  const at = (k: number): number => (base + k) % n;
  const x = [state[at(0)]!, state[at(1)]!, state[at(2)]!, state[at(3)]!];
  const c = [0, 0, 0, 0];
  const r = [0, 0, 0, 0];
  for (let i = 0; i < 4; i++) {
    for (let j = 0; j < 4; j++) {
      const tmp = FUGUE_MIX[j]![(x[i]! >>> (8 * (3 - j))) & 0xff]!;
      c[i] = u32(c[i]! ^ tmp);
      // The diagonal contributes to its column only; everything else also feeds a row.
      if (j !== i) r[j] = u32(r[j]! ^ tmp);
    }
  }
  state[at(0)] = u32(
    ((c[0]! ^ r[0]!) & 0xff000000) |
      ((c[1]! ^ r[1]!) & 0x00ff0000) |
      ((c[2]! ^ r[2]!) & 0x0000ff00) |
      ((c[3]! ^ r[3]!) & 0x000000ff),
  );
  state[at(1)] = u32(
    ((c[1]! ^ u32(r[0]! << 8)) & 0xff000000) |
      ((c[2]! ^ u32(r[1]! << 8)) & 0x00ff0000) |
      ((c[3]! ^ u32(r[2]! << 8)) & 0x0000ff00) |
      ((c[0]! ^ (r[3]! >>> 24)) & 0x000000ff),
  );
  state[at(2)] = u32(
    ((c[2]! ^ u32(r[0]! << 16)) & 0xff000000) |
      ((c[3]! ^ u32(r[1]! << 16)) & 0x00ff0000) |
      ((c[0]! ^ (r[2]! >>> 16)) & 0x0000ff00) |
      ((c[1]! ^ (r[3]! >>> 16)) & 0x000000ff),
  );
  state[at(3)] = u32(
    ((c[3]! ^ u32(r[0]! << 24)) & 0xff000000) |
      ((c[0]! ^ (r[1]! >>> 8)) & 0x00ff0000) |
      ((c[1]! ^ (r[2]! >>> 8)) & 0x0000ff00) |
      ((c[2]! ^ (r[3]! >>> 8)) & 0x000000ff),
  );
}

/** The column mix: three columns folded forward and into a distant triple. */
function cmix(state: Uint32Array, base: number, n: number): void {
  const far = n === 30 ? 15 : 18;
  const at = (k: number): number => (base + k) % n;
  for (let i = 0; i < 3; i++) {
    state[at(i)] = u32(state[at(i)]! ^ state[at(4 + i)]!);
    state[at(far + i)] = u32(state[at(far + i)]! ^ state[at(4 + i)]!);
  }
}

/** One input word. `kind` is 2, 3 or 4: the TIX variant, and also the sub-round count. */
function absorbWord(state: Uint32Array, base: number, q: number, kind: 2 | 3 | 4, n: number): void {
  const at = (k: number): number => (base + k) % n;
  const fold = (target: number, source: number): void => {
    state[at(target)] = u32(state[at(target)]! ^ state[at(source)]!);
  };

  if (kind === 2) {
    fold(10, 0);
    state[at(0)] = q;
    fold(8, 0);
    fold(1, 24);
  } else if (kind === 3) {
    fold(16, 0);
    state[at(0)] = q;
    fold(8, 0);
    fold(1, 27);
    fold(4, 30);
  } else {
    fold(22, 0);
    state[at(0)] = q;
    fold(8, 0);
    fold(1, 24);
    fold(4, 27);
    fold(7, 30);
  }

  for (let i = 0; i < kind; i++) {
    const sub = at((n === 30 ? 27 : 33) - i * 3);
    cmix(state, sub, n);
    smix(state, sub, n);
  }
}

/** The final rounds, which differ per output length. `state` is already un-rotated. */
function finalRounds(state: Uint32Array, n: number, kind: 2 | 3 | 4, outputLen: number): Uint8Array {
  const rotateRight = (by: number): void => {
    const copy = Uint32Array.from(state);
    for (let i = 0; i < n; i++) state[(i + by) % n] = copy[i]!;
  };
  const fold = (target: number): void => {
    state[target] = u32(state[target]! ^ state[0]!);
  };
  const emit = (indices: readonly number[]): Uint8Array => {
    const out = new Uint8Array(outputLen);
    for (let i = 0; i < outputLen; i++) {
      out[i] = (state[indices[i >> 2]!]! >>> (8 * (3 - (i & 3)))) & 0xff;
    }
    return out;
  };

  if (kind === 2) {
    for (let i = 0; i < 10; i++) {
      rotateRight(3);
      cmix(state, 0, n);
      smix(state, 0, n);
    }
    for (let i = 0; i < 13; i++) {
      fold(4); fold(15); rotateRight(15); smix(state, 0, n);
      fold(4); fold(16); rotateRight(14); smix(state, 0, n);
    }
    fold(4);
    fold(15);
    return emit([1, 2, 3, 4, 15, 16, 17, 18]);
  }

  if (kind === 3) {
    for (let i = 0; i < 18; i++) {
      rotateRight(3);
      cmix(state, 0, n);
      smix(state, 0, n);
    }
    for (let i = 0; i < 13; i++) {
      fold(4); fold(12); fold(24); rotateRight(12); smix(state, 0, n);
      fold(4); fold(13); fold(24); rotateRight(12); smix(state, 0, n);
      fold(4); fold(13); fold(25); rotateRight(11); smix(state, 0, n);
    }
    fold(4);
    fold(12);
    fold(24);
    return emit([1, 2, 3, 4, 12, 13, 14, 15, 24, 25, 26, 27]);
  }

  for (let i = 0; i < 32; i++) {
    rotateRight(3);
    cmix(state, 0, n);
    smix(state, 0, n);
  }
  for (let i = 0; i < 13; i++) {
    fold(4); fold(9); fold(18); fold(27); rotateRight(9); smix(state, 0, n);
    fold(4); fold(10); fold(18); fold(27); rotateRight(9); smix(state, 0, n);
    fold(4); fold(10); fold(19); fold(27); rotateRight(9); smix(state, 0, n);
    fold(4); fold(10); fold(19); fold(28); rotateRight(8); smix(state, 0, n);
  }
  fold(4);
  fold(9);
  fold(18);
  fold(27);
  return emit([1, 2, 3, 4, 9, 10, 11, 12, 18, 19, 20, 21, 27, 28, 29, 30]);
}

/** A Fugue digest of any of the four standardised lengths. */
export function fugue(outputLen: 28 | 32 | 48 | 64, message: Uint8Array): Uint8Array {
  const n = outputLen <= 32 ? 30 : 36;
  const kind: 2 | 3 | 4 = outputLen <= 32 ? 2 : outputLen === 48 ? 3 : 4;
  const step = kind * 3;

  const state = new Uint32Array(n);
  const iv = IV[String(outputLen * 8)]!;
  state.set(iv, n - iv.length);

  let base = 0;
  const feed = (q: number): void => {
    absorbWord(state, base, q, kind, n);
    base = ((base - step) % n + n) % n;
  };

  let at = 0;
  for (; at + 4 <= message.length; at += 4) {
    feed(
      u32((message[at]! << 24) | (message[at + 1]! << 16) | (message[at + 2]! << 8) | message[at + 3]!),
    );
  }
  // A short tail is zero-padded to a word; then the bit count, high word first.
  const rest = message.length - at;
  if (rest > 0) {
    let q = 0;
    for (let i = 0; i < 4; i++) q = u32((q << 8) | (i < rest ? message[at + i]! : 0));
    feed(q);
  }
  const bits = BigInt(message.length) * 8n;
  feed(Number((bits >> 32n) & 0xffffffffn) >>> 0);
  feed(Number(bits & 0xffffffffn) >>> 0);

  // Un-rotate so the moving base becomes index zero, then run the final rounds.
  const settled = new Uint32Array(n);
  for (let i = 0; i < n; i++) settled[i] = state[(base + i) % n]!;
  return finalRounds(settled, n, kind, outputLen);
}

/** An incremental Fugue. Buffered, so the manifest reports `streaming: false`. */
export function createFugue(outputLen: 28 | 32 | 48 | 64): {
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
      return fugue(outputLen, all);
    },
  };
}
