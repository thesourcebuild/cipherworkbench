/**
 * GHASH: the universal hash GCM authenticates with, over GF(2^128).
 *
 * Here rather than borrowed because `@ocs/algos` is zero-dependency by design, and because the one
 * plausible source -- `@noble/ciphers/_polyval.js` -- is an underscore-prefixed internal module whose
 * shape is not part of that package's contract. Forty lines of field arithmetic is a better bet than a
 * dependency on someone else's private export.
 *
 * Three things to know.
 *
 * **The bit order is GCM's, which is backwards from every other polynomial in this repo.** A 16-byte
 * block is read as a polynomial whose *most* significant coefficient is the top bit of byte 0, and
 * multiplication reduces by `x^128 + x^7 + x^2 + x + 1` written as `0xe1` in the *first* byte. That is
 * why the shift below goes right and the reduction constant sits at the top: get either backwards and
 * you have a perfectly consistent hash that authenticates nothing anyone else recognises. The CRC
 * catalogue's `refin`/`refout` flags exist for the same family of mistake.
 *
 * **It is not a MAC on its own.** GHASH is a keyed hash that is only secure because GCM encrypts its
 * output and never reuses the (key, nonce) pair. Exposing it as a tool would invite exactly the misuse
 * that makes nonce reuse in GCM catastrophic, which is why this module is internal to the modes.
 *
 * **Bit-by-bit, deliberately.** The table-driven versions (4-bit or 8-bit windows) are four to sixteen
 * times faster and introduce a secret-dependent table lookup, which is the side channel that made
 * table-driven AES a problem. For a workbench authenticating pasted text, the constant-time-ish simple
 * loop is the right trade -- and it is the version that can be read against the specification.
 */

const BLOCK = 16;

/** The reduction polynomial's top byte: `x^128 + x^7 + x^2 + x + 1`. */
const R0 = 0xe1000000;

/**
 * `out = x * y` in GF(2^128), operands as four big-endian 32-bit words.
 *
 * Right-shift-and-reduce, walking the bits of `x` from the most significant. `V` accumulates `y`
 * shifted; whenever a shift pushes a one off the bottom, the reduction polynomial goes back in at the
 * top.
 */
function multiply(x: Uint32Array, y: Uint32Array, out: Uint32Array): void {
  const v = Uint32Array.from(y);
  let z0 = 0;
  let z1 = 0;
  let z2 = 0;
  let z3 = 0;

  for (let word = 0; word < 4; word++) {
    const bits = x[word]!;
    for (let bit = 31; bit >= 0; bit--) {
      if ((bits >>> bit) & 1) {
        z0 ^= v[0]!;
        z1 ^= v[1]!;
        z2 ^= v[2]!;
        z3 ^= v[3]!;
      }

      // Shift V right one bit, then reduce if the bit that fell off was set.
      const lsb = v[3]! & 1;
      v[3] = ((v[3]! >>> 1) | ((v[2]! & 1) << 31)) >>> 0;
      v[2] = ((v[2]! >>> 1) | ((v[1]! & 1) << 31)) >>> 0;
      v[1] = ((v[1]! >>> 1) | ((v[0]! & 1) << 31)) >>> 0;
      v[0] = (v[0]! >>> 1) >>> 0;
      if (lsb) v[0] = (v[0]! ^ R0) >>> 0;
    }
  }

  out[0] = z0 >>> 0;
  out[1] = z1 >>> 0;
  out[2] = z2 >>> 0;
  out[3] = z3 >>> 0;
}

function readWords(bytes: Uint8Array, at: number, count: number, out: Uint32Array): void {
  out.fill(0);
  for (let i = 0; i < count; i++) {
    const word = i >>> 2;
    out[word] = (out[word]! | (bytes[at + i]! << (8 * (3 - (i & 3))))) >>> 0;
  }
}

/**
 * GHASH under the hash subkey `h`, absorbing whole blocks and zero-padding a short final one.
 *
 * Incremental so GCM can feed it the associated data, then the ciphertext, then the length block --
 * three separately-padded runs, which is exactly the structure the specification describes.
 */
export class Ghash {
  private readonly h = new Uint32Array(4);
  private readonly y = new Uint32Array(4);
  private readonly block = new Uint32Array(4);
  private readonly product = new Uint32Array(4);

  constructor(hashKey: Uint8Array) {
    if (hashKey.length !== BLOCK) {
      throw new Error(`GHASH's subkey is 16 bytes; this one is ${hashKey.length}.`);
    }
    readWords(hashKey, 0, BLOCK, this.h);
  }

  /** Absorbs `data` as whole blocks, zero-padding the last one if it is short. */
  update(data: Uint8Array): void {
    for (let at = 0; at < data.length; at += BLOCK) {
      const take = Math.min(BLOCK, data.length - at);
      readWords(data, at, take, this.block);
      for (let i = 0; i < 4; i++) this.y[i] = (this.y[i]! ^ this.block[i]!) >>> 0;
      multiply(this.y, this.h, this.product);
      this.y.set(this.product);
    }
  }

  digest(): Uint8Array {
    const out = new Uint8Array(BLOCK);
    for (let i = 0; i < 4; i++) {
      const word = this.y[i]!;
      out[i * 4] = (word >>> 24) & 0xff;
      out[i * 4 + 1] = (word >>> 16) & 0xff;
      out[i * 4 + 2] = (word >>> 8) & 0xff;
      out[i * 4 + 3] = word & 0xff;
    }
    return out;
  }
}

export function ghash(hashKey: Uint8Array, data: Uint8Array): Uint8Array {
  const h = new Ghash(hashKey);
  h.update(data);
  return h.digest();
}
