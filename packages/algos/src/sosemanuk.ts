/**
 * SOSEMANUK, the eSTREAM software-profile finalist -- Serpent's key schedule driving an LFSR over
 * GF(2^32).
 *
 * It is the last of eSTREAM's four software winners this repo did not have (HC-128, HC-256 and Rabbit
 * are in `phase2-stream.ts` and `phase6-ciphers.ts`), and structurally the most interesting of them:
 * three unrelated pieces bolted together, each doing a job the others cannot.
 *
 *  - **The key schedule is Serpent's**, unmodified, at 25 subkeys instead of 33.
 *  - **The IV injection is Serpent24** -- Serpent reduced to 24 rounds, with the 24th round applying
 *    the linear transform (which the real cipher's last round does not) and then a final subkey XOR.
 *    The state after the 12th, 18th *and* 24th rounds all three feed the initial state, which is why
 *    this cannot be built out of a Serpent that only hands back a ciphertext.
 *  - **The keystream is a ten-stage LFSR over GF(2^32)** feeding a two-register FSM, with four
 *    successive FSM outputs collected and pushed through **Serpent's S2 bitsliced** before being
 *    XORed with four successive LFSR outputs.
 *
 * Four things to preserve.
 *
 * **The two 256-word multiplication tables are derived, not transcribed.** Every implementation ships
 * 512 words for `MUL_A` and `DIV_A`. They are `b` times the four coefficients of alpha^4 over
 * GF(2^8), and `b` over the constant coefficient times the same four -- so all 512 come out of the
 * polynomial `x^8 + x^7 + x^5 + x^3 + 1` and the four exponents 23, 245, 48 and 239 the specification
 * gives. Same principle as Blowfish's 4168 bytes from pi and BelT's H-block from an LFSR, and it
 * matters for the same reason: one mistyped word gives a cipher that is perfectly self-consistent and
 * matches nothing.
 *
 * **The three Serpent24 snapshots are permuted into the state, and each one differently.** The
 * mapping was resolved from Crypto++'s `serpentp.h`, whose macros name registers rather than state
 * words -- `afterS3` says the state after round 12 sits in `(e, b, d, c)`, so the reference's
 * `m_state[6] = c` is word 3 rather than word 0. Reading the snapshots in their natural order gives a
 * keystream that looks random and matches nothing. The check that the letters were read correctly is
 * that the reference's inter-iteration register shuffle then comes out as the *identity* permutation
 * on the four words, which it does.
 *
 * **The FSM's two registers exchange roles every step**, which the reference expresses by alternating
 * which physical register it calls R1. Implementing the specification's assignments literally is
 * equivalent; implementing them *without* the alternation is right for even steps and wrong for odd.
 *
 * **`Math.imul` is mandatory** for the `R1 * 0x54655307` mix -- the product overflows 2^53, so `*`
 * silently loses the low bits the rotation then depends on. Third place in this repo where
 * JavaScript's number type is a hazard, after RC6 and SIMD.
 *
 * No oracle: OpenSSL has never implemented SOSEMANUK and nothing in this tree has it. What stands
 * behind it is the two published vectors in Crypto++'s `TestVectors/sosemanuk.txt`, and they are
 * worth more than their count suggests -- one is 160 bytes under a *5-byte* key, which exercises
 * Serpent's padding bit, and the other folds 131,072 bytes under a 256-bit key into an XOR digest,
 * which drives the LFSR through 32,768 steps. Both key extremes, and a long run no single block
 * reaches.
 */
import { SERPENT_SBOX, serpentLinear, serpentSubkeys, serpentSubstitute } from "./serpent";

const u32 = (x: number): number => x >>> 0;
const rol = (x: number, n: number): number => u32((x << n) | (x >>> (32 - n)));

/**
 * GF(2^8) under SOSEMANUK's beta polynomial, x^8 + x^7 + x^5 + x^3 + 1.
 *
 * Note this is neither AES's polynomial nor the one `blockmodes.ts` reduces with, so the tables below
 * cannot borrow from anything already in the tree.
 */
const BETA_POLY = 0x1a9;

function mul8(a: number, b: number): number {
  let r = 0;
  for (let i = 0; i < 8; i++) if (((b >> i) & 1) !== 0) r ^= a << i;
  for (let i = 15; i >= 8; i--) if (((r >> i) & 1) !== 0) r ^= BETA_POLY << (i - 8);
  return r & 0xff;
}

/** Powers of beta = 0x02, which generates the field -- checked below rather than assumed. */
const BETA_EXP = new Uint8Array(255);
const BETA_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    BETA_EXP[i] = x;
    x = mul8(x, 2);
  }
  for (let i = 0; i < 255; i++) BETA_LOG[BETA_EXP[i]!] = i;
  if (new Set(BETA_EXP).size !== 255) throw new Error("SOSEMANUK: beta does not generate GF(2^8).");
}

const beta = (i: number): number => BETA_EXP[((i % 255) + 255) % 255]!;
const div8 = (a: number, b: number): number =>
  a === 0 ? 0 : BETA_EXP[(((BETA_LOG[a]! - BETA_LOG[b]!) % 255) + 255) % 255]!;

/**
 * The two GF(2^32) tables, derived.
 *
 * alpha is a root of `alpha^4 + beta^23 alpha^3 + beta^245 alpha^2 + beta^48 alpha + beta^239`, and a
 * state word is four GF(2^8) coefficients packed most significant first. Multiplying by alpha is a
 * byte shift up plus the reduction of the byte that fell off the top, which is what `MUL_TABLE`
 * holds; dividing is a byte shift down plus alpha^-1 times the byte that fell off the bottom.
 */
const MUL_TABLE = new Uint32Array(256);
const DIV_TABLE = new Uint32Array(256);
{
  const pack = (a: number, b: number, c: number, d: number): number =>
    u32((a << 24) | (b << 16) | (c << 8) | d);
  const c3 = beta(23);
  const c2 = beta(245);
  const c1 = beta(48);
  const c0 = beta(239);
  for (let b = 0; b < 256; b++) {
    MUL_TABLE[b] = pack(mul8(b, c3), mul8(b, c2), mul8(b, c1), mul8(b, c0));
    const q = div8(b, c0);
    DIV_TABLE[b] = pack(q, mul8(q, c3), mul8(q, c2), mul8(q, c1));
  }
}

/** Exported so a test can pin the derivation against a reference's own entries. */
export const SOSEMANUK_TABLE_FIRST: readonly number[] = [MUL_TABLE[1]!, DIV_TABLE[1]!];

const mulAlpha = (x: number): number => u32(u32(x << 8) ^ MUL_TABLE[x >>> 24]!);
const divAlpha = (x: number): number => u32((x >>> 8) ^ DIV_TABLE[x & 0xff]!);

/** `x` when the low bit of `c` is clear, `x ^ y` when it is set -- the FSM's multiplexer. */
const xmux = (c: number, x: number, y: number): number => u32(x ^ (y & -(c & 1)));

/**
 * The primitive accepts 1 to 32 bytes, which is wider than the specification's 128 to 256 bits.
 *
 * That is not laxity, and it is not this implementation's choice either: Serpent's key schedule pads a
 * short key with a single one bit, so every length below 32 is well defined, the reference accepts all
 * of them, and **the reference's own published vector uses a five-byte key**. Refusing it would leave
 * a published value unreachable to check the implementation against, which is the situation the
 * "prefer a warning to a refusal" rule exists to avoid.
 *
 * The *tool* declares 16, 24 and 32 -- the specification's range -- because a one-byte key is eight
 * bits of security and a form offering it would be offering nothing. The cipher family's key note
 * says so, and `tests/algos-sosemanuk.test.ts` reaches the shorter key through this function.
 */
const MAX_KEY_LENGTH = 32;
const NONCE_LENGTH = 16;

export interface SosemanukGenerator {
  /** The next `n` bytes of keystream. Successive calls continue where the last left off. */
  keystream(n: number): Uint8Array;
}

/** SOSEMANUK's keystream generator. The key is 1 to 32 bytes; the IV is exactly 16. */
export function createSosemanuk(key: Uint8Array, iv: Uint8Array): SosemanukGenerator {
  if (key.length < 1 || key.length > MAX_KEY_LENGTH) {
    throw new Error(`SOSEMANUK's key is 1 to 32 bytes; this one is ${key.length}.`);
  }
  if (iv.length !== NONCE_LENGTH) {
    throw new Error(`SOSEMANUK's IV is exactly 16 bytes; this one is ${iv.length}.`);
  }

  // ---- IV injection: Serpent24 ----
  const rk = serpentSubkeys(key, 24);
  let x = [0, 1, 2, 3].map((i) =>
    u32(iv[4 * i]! | (iv[4 * i + 1]! << 8) | (iv[4 * i + 2]! << 16) | (iv[4 * i + 3]! << 24)),
  );
  let y12: number[] = [];
  let y18: number[] = [];
  for (let round = 0; round < 24; round++) {
    x = serpentLinear(
      serpentSubstitute(
        SERPENT_SBOX[round % 8]!,
        x.map((word, i) => u32(word ^ rk[round]![i]!)),
      ),
    );
    if (round === 11) y12 = x.slice();
    if (round === 17) y18 = x.slice();
  }
  // Round 24 keeps its linear transform and then takes the 25th subkey, unlike Serpent's own last.
  const y24 = x.map((word, i) => u32(word ^ rk[24]![i]!));

  const s = new Uint32Array(10);
  s[9] = y12[0]!;
  s[8] = y12[1]!;
  s[7] = y12[2]!;
  s[6] = y12[3]!;
  s[4] = y18[1]!;
  s[5] = y18[3]!;
  s[3] = y24[0]!;
  s[2] = y24[1]!;
  s[1] = y24[2]!;
  s[0] = y24[3]!;
  let reg1 = y18[0]!;
  let reg2 = y18[2]!;

  // One FSM update before the first step, which the reference does at the end of resynchronisation.
  reg2 = u32(reg2 + xmux(reg1, s[1]!, s[8]!));
  reg1 = rol(u32(Math.imul(reg1, 0x54655307)), 7);

  // ---- Keystream ----
  let step = 0;
  let held = new Uint8Array(0);
  let heldAt = 0;

  /** One group of four steps, which is sixteen bytes of keystream. */
  const nextBlock = () => {
    const f = [0, 0, 0, 0];
    const v = [0, 0, 0, 0];
    for (let j = 0; j < 4; j++) {
      const i = step % 10;
      // The registers exchange roles every step; the reference alternates which it calls R1.
      const even = i % 2 === 0;
      let r1 = even ? reg1 : reg2;
      let r2 = even ? reg2 : reg1;

      f[j] = u32(u32(s[(i + 9) % 10]! + r2) ^ r1);
      const t = s[i]!;
      v[j] = t;
      s[i] = u32(mulAlpha(t) ^ divAlpha(s[(i + 3) % 10]!) ^ s[(i + 9) % 10]!);
      r1 = u32(r1 + xmux(r2, s[(i + 2) % 10]!, s[(i + 9) % 10]!));
      r2 = rol(u32(Math.imul(r2, 0x54655307)), 7);

      if (even) {
        reg1 = r1;
        reg2 = r2;
      } else {
        reg2 = r1;
        reg1 = r2;
      }
      step++;
    }

    // Serpent's S2, bitsliced across the four FSM outputs, then XORed with the four LFSR outputs.
    const y = serpentSubstitute(SERPENT_SBOX[2]!, f);
    const out = new Uint8Array(16);
    for (let j = 0; j < 4; j++) {
      const word = u32(y[j]! ^ v[j]!);
      for (let b = 0; b < 4; b++) out[4 * j + b] = (word >>> (8 * b)) & 0xff;
    }
    return out;
  };

  return {
    keystream(n) {
      const out = new Uint8Array(n);
      let at = 0;
      while (at < n) {
        if (heldAt >= held.length) {
          held = nextBlock();
          heldAt = 0;
        }
        const take = Math.min(n - at, held.length - heldAt);
        out.set(held.subarray(heldAt, heldAt + take), at);
        heldAt += take;
        at += take;
      }
      return out;
    },
  };
}

/** Encrypt or decrypt -- the same operation, as for every stream cipher. */
export function sosemanukCrypt(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  const ks = createSosemanuk(key, iv).keystream(data.length);
  const out = new Uint8Array(data.length);
  for (let i = 0; i < data.length; i++) out[i] = data[i]! ^ ks[i]!;
  return out;
}
