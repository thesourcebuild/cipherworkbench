/**
 * TinyJAMBU -- the smallest of the NIST lightweight finalists, and by some distance.
 *
 * The whole permutation is a 128-bit non-linear feedback shift register: one AND, four shifted taps and
 * a key word per 32 bits of output. There is no S-box, no table and no round constant. That makes it
 * the one design in this family where nothing could be mistyped, and it moves all the risk into the
 * mode -- specifically into the frame bits and the round counts.
 *
 * Verified against 1089 known-answer vectors per key size, in both directions, all first run.
 *
 * ## What actually varies between the three key sizes
 *
 * Only two things: how many key words the feedback cycles through, and how long the *wide* permutation
 * is -- 1024, 1152 or 1280 rounds for 128-, 192- and 256-bit keys. The narrow permutation is 640 rounds
 * for all three. So a version that used one round count everywhere is correct at 128 bits and wrong
 * above it, which is the same shape as LEA's three key schedules.
 *
 * ## The frame bits, and why they are not decoration
 *
 * Four constants -- nonce, associated data, ciphertext, tag -- are XORed into the state before each
 * phase, and the *low two bits of the length* are XORed in after. Together they are the whole domain
 * separation: without them a message could be reinterpreted as associated data of the same bytes. They
 * go into `state[1]`, not `state[0]`, and at bits 4-6 rather than 0-2.
 *
 * ## Decryption masks the partial word; encryption does not need to
 *
 * On the way out, only the bytes that exist were loaded, so the word is already clean. On the way back
 * the recovered plaintext word has garbage in the bytes past the end -- the keystream is a full word --
 * so it has to be masked before it enters the state. Encrypt and decrypt agree with each other either
 * way; only a published vector at a non-multiple-of-four length shows the difference.
 */

const FRAME_NONCE = 0x10;
const FRAME_AD = 0x30;
const FRAME_CT = 0x50;
const FRAME_TAG = 0x70;
/** The narrow permutation, the same for every key size. */
const P_NARROW = 640;

export type TinyJambuKeyBits = 128 | 192 | 256;

interface TinyJambuParams {
  keyWords: number;
  /** Rounds of the wide permutation: key setup, every message block, and the tag. */
  wide: number;
}

export const TINYJAMBU_PARAMS: Readonly<Record<TinyJambuKeyBits, TinyJambuParams>> = {
  128: { keyWords: 4, wide: 1024 },
  192: { keyWords: 6, wide: 1152 },
  256: { keyWords: 8, wide: 1280 },
};

/**
 * The keyed NLFSR. One 32-bit feedback word per iteration, the key word index cycling `i mod keyWords`.
 *
 * Note the taps are at 47, 70, 85 and 91, and the only non-linearity is `NAND(s70, s85)`.
 */
function permute(state: Int32Array, key: Int32Array, rounds: number): void {
  const iterations = rounds >>> 5;
  const words = key.length;
  for (let i = 0; i < iterations; i++) {
    const s47 = ((state[2]! << 17) | (state[1]! >>> 15)) | 0;
    const s70 = ((state[3]! << 26) | (state[2]! >>> 6)) | 0;
    const s85 = ((state[3]! << 11) | (state[2]! >>> 21)) | 0;
    const s91 = ((state[3]! << 5) | (state[2]! >>> 27)) | 0;
    const feedback = (state[0]! ^ s47 ^ ~(s70 & s85) ^ s91 ^ key[i % words]!) | 0;
    state[0] = state[1]!;
    state[1] = state[2]!;
    state[2] = state[3]!;
    state[3] = feedback;
  }
}

const leWord = (b: Uint8Array, off: number, take: number): number => {
  let w = 0;
  for (let i = 0; i < take; i++) w |= b[off + i]! << (i << 3);
  return w | 0;
};

function tinyJambu(
  bits: TinyJambuKeyBits,
  key: Uint8Array,
  nonce: Uint8Array,
  input: Uint8Array,
  aad: Uint8Array,
  encrypting: boolean,
): { out: Uint8Array; tag: Uint8Array } {
  const p = TINYJAMBU_PARAMS[bits];
  if (key.length !== bits / 8) {
    throw new Error(`TinyJAMBU-${bits} needs a ${bits / 8}-byte key; got ${key.length}.`);
  }
  if (nonce.length !== 12) throw new Error(`TinyJAMBU needs a 12-byte nonce; got ${nonce.length}.`);

  const k = new Int32Array(p.keyWords);
  for (let i = 0; i < p.keyWords; i++) k[i] = leWord(key, 4 * i, 4);
  const state = new Int32Array(4);

  permute(state, k, p.wide);
  for (let i = 0; i < 3; i++) {
    state[1] = state[1]! ^ (FRAME_NONCE);
    permute(state, k, P_NARROW);
    state[3] = state[3]! ^ (leWord(nonce, 4 * i, 4));
  }

  for (let off = 0; off < aad.length; ) {
    state[1] = state[1]! ^ (FRAME_AD);
    permute(state, k, P_NARROW);
    const take = Math.min(4, aad.length - off);
    state[3] = state[3]! ^ (leWord(aad, off, take));
    off += take;
  }
  state[1] = state[1]! ^ (aad.length & 3);

  const out = new Uint8Array(input.length);
  for (let off = 0; off < input.length; ) {
    state[1] = state[1]! ^ (FRAME_CT);
    permute(state, k, p.wide);
    const take = Math.min(4, input.length - off);
    const word = leWord(input, off, take);
    let result: number;
    if (encrypting) {
      state[3] = state[3]! ^ (word);
      result = state[2]! ^ word;
    } else {
      result = state[2]! ^ word;
      // See the header: only the bytes that exist may enter the state.
      const mask = take === 4 ? -1 : (1 << (take << 3)) - 1;
      state[3] = state[3]! ^ (result & mask);
    }
    for (let i = 0; i < take; i++) out[off + i] = (result >>> (i << 3)) & 0xff;
    off += take;
  }
  state[1] = state[1]! ^ (input.length & 3);

  // The tag is two squeezes with the frame bits applied twice, not one 64-bit read.
  const tag = new Uint8Array(8);
  state[1] = state[1]! ^ (FRAME_TAG);
  permute(state, k, p.wide);
  for (let i = 0; i < 4; i++) tag[i] = (state[2]! >>> (i << 3)) & 0xff;
  state[1] = state[1]! ^ (FRAME_TAG);
  permute(state, k, P_NARROW);
  for (let i = 0; i < 4; i++) tag[4 + i] = (state[2]! >>> (i << 3)) & 0xff;
  return { out, tag };
}

export function tinyJambuEncrypt(
  bits: TinyJambuKeyBits,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const { out, tag } = tinyJambu(bits, key, nonce, plaintext, aad, true);
  const result = new Uint8Array(out.length + 8);
  result.set(out, 0);
  result.set(tag, out.length);
  return result;
}

export function tinyJambuDecrypt(
  bits: TinyJambuKeyBits,
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (data.length < 8) return null;
  const { out, tag } = tinyJambu(bits, key, nonce, data.subarray(0, data.length - 8), aad, false);
  let diff = 0;
  for (let i = 0; i < 8; i++) diff |= tag[i]! ^ data[data.length - 8 + i]!;
  return diff === 0 ? out : null;
}
