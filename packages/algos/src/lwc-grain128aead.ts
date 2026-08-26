/**
 * Grain-128AEAD -- Grain-128a's registers with a 64-bit Wegman-Carter authenticator. A NIST finalist.
 *
 * The only bit-serial design in this family: one keystream bit per clock, and the plaintext is
 * authenticated bit by bit into an accumulator gated by a shift register. That is what makes it tiny in
 * hardware and the slowest of the nine in software.
 *
 * It is *not* the Grain-128 registered in the cipher family. The NFSR feedback here has three extra
 * cubic terms and one quartic term (from Grain-128a), and the register layout is reversed -- these shift
 * *right* with the new bit entering at the top, where plain Grain-128 shifts words left. Both are in
 * this repo and neither can be derived from the other.
 *
 * Verified against 1089 known-answer vectors in both directions.
 *
 * ## Three things that decide correctness
 *
 * **Initialisation is 320 clocks with the output fed back, then 64 more mixing the key.** The second
 * loop is the part a Grain-128 implementation does not have: it XORs key byte q bit r into the NFSR and
 * key byte q+8 bit r into the LFSR. Stopping after the 320 gives a keystream that looks fine.
 *
 * **The accumulator and the shift register are each filled from the keystream** -- 64 bits into the
 * accumulator, then 64 into the register, before any data is touched. So the first 128 keystream bits
 * never encrypt anything.
 *
 * **The associated data carries a length prefix, and it is DER-shaped.** Under 128 bytes it is one byte;
 * at or above, it is `0x80 | byteCount` followed by the length big-endian. Omitting it makes every
 * non-empty-AD vector wrong and every empty-AD vector right.
 */

interface Grain128AeadEngine {
  absorb(data: Uint8Array, off: number, len: number): void;
  crypt(input: Uint8Array, decrypting: boolean): Uint8Array;
  tag(): Uint8Array;
}

function engine(key: Uint8Array, nonce: Uint8Array): Grain128AeadEngine {
  const lfsr = new Int32Array(4);
  const nfsr = new Int32Array(4);
  const acc = new Int32Array(2);
  const sr = new Int32Array(2);

  // The 96-bit nonce fills three words; the fourth is 0xffffff7f -- all ones but the top bit.
  const iv = new Uint8Array(16);
  iv.set(nonce.subarray(0, 12));
  iv[12] = 0xff;
  iv[13] = 0xff;
  iv[14] = 0xff;
  iv[15] = 0x7f;
  const le = (b: Uint8Array, i: number): number =>
    (b[4 * i]! | (b[4 * i + 1]! << 8) | (b[4 * i + 2]! << 16) | (b[4 * i + 3]! << 24)) | 0;
  for (let i = 0; i < 4; i++) {
    nfsr[i] = le(key, i);
    lfsr[i] = le(iv, i);
  }

  /** g(x): Grain-128a's feedback -- note the three cubic and one quartic term. */
  const outNfsr = (): number => {
    const n0 = nfsr[0]!;
    const n1 = nfsr[1]!;
    const n2 = nfsr[2]!;
    const n3 = nfsr[3]!;
    const b0 = n0, b3 = n0 >>> 3, b11 = n0 >>> 11, b13 = n0 >>> 13, b17 = n0 >>> 17, b18 = n0 >>> 18;
    const b22 = n0 >>> 22, b24 = n0 >>> 24, b25 = n0 >>> 25, b26 = n0 >>> 26, b27 = n0 >>> 27;
    const b40 = n1 >>> 8, b48 = n1 >>> 16, b56 = n1 >>> 24, b59 = n1 >>> 27, b61 = n1 >>> 29;
    const b65 = n2 >>> 1, b67 = n2 >>> 3, b68 = n2 >>> 4, b70 = n2 >>> 6, b78 = n2 >>> 14;
    const b82 = n2 >>> 18, b84 = n2 >>> 20, b88 = n2 >>> 24, b91 = n2 >>> 27, b92 = n2 >>> 28;
    const b93 = n2 >>> 29, b95 = n2 >>> 31, b96 = n3;
    return (
      (b0 ^ b26 ^ b56 ^ b91 ^ b96 ^
        (b3 & b67) ^ (b11 & b13) ^ (b17 & b18) ^ (b27 & b59) ^ (b40 & b48) ^ (b61 & b65) ^
        (b68 & b84) ^ (b22 & b24 & b25) ^ (b70 & b78 & b82) ^ (b88 & b92 & b93 & b95)) & 1
    );
  };

  const outLfsr = (): number => {
    const s0 = lfsr[0]!;
    const s7 = lfsr[0]! >>> 7;
    const s38 = lfsr[1]! >>> 6;
    const s70 = lfsr[2]! >>> 6;
    const s81 = lfsr[2]! >>> 17;
    const s96 = lfsr[3]!;
    return (s0 ^ s7 ^ s38 ^ s70 ^ s81 ^ s96) & 1;
  };

  const filter = (): number => {
    const b2 = nfsr[0]! >>> 2, b12 = nfsr[0]! >>> 12, b15 = nfsr[0]! >>> 15;
    const b36 = nfsr[1]! >>> 4, b45 = nfsr[1]! >>> 13;
    const b64 = nfsr[2]!, b73 = nfsr[2]! >>> 9, b89 = nfsr[2]! >>> 25, b95 = nfsr[2]! >>> 31;
    const s8 = lfsr[0]! >>> 8, s13 = lfsr[0]! >>> 13, s20 = lfsr[0]! >>> 20;
    const s42 = lfsr[1]! >>> 10, s60 = lfsr[1]! >>> 28;
    const s79 = lfsr[2]! >>> 15, s93 = lfsr[2]! >>> 29, s94 = lfsr[2]! >>> 30;
    return (
      ((b12 & s8) ^ (s13 & s20) ^ (b95 & s42) ^ (s60 & s79) ^ (b12 & b95 & s94) ^ s93 ^
        b2 ^ b15 ^ b36 ^ b45 ^ b64 ^ b73 ^ b89) & 1
    );
  };

  const shiftInto = (a: Int32Array, bit: number): void => {
    a[0] = (a[0]! >>> 1) | (a[1]! << 31);
    a[1] = (a[1]! >>> 1) | (a[2]! << 31);
    a[2] = (a[2]! >>> 1) | (a[3]! << 31);
    a[3] = (a[3]! >>> 1) | (bit << 31);
  };
  const clock = (): void => {
    shiftInto(nfsr, (outNfsr() ^ lfsr[0]!) & 1);
    shiftInto(lfsr, outLfsr() & 1);
  };
  const nextBit = (): number => {
    const bit = filter();
    clock();
    return bit;
  };

  for (let i = 0; i < 320; i++) {
    const out = filter();
    shiftInto(nfsr, (outNfsr() ^ lfsr[0]! ^ out) & 1);
    shiftInto(lfsr, (outLfsr() ^ out) & 1);
  }
  for (let q = 0; q < 8; q++) {
    for (let r = 0; r < 8; r++) {
      const out = filter();
      shiftInto(nfsr, (outNfsr() ^ lfsr[0]! ^ out ^ (key[q]! >> r)) & 1);
      shiftInto(lfsr, (outLfsr() ^ out ^ (key[q + 8]! >> r)) & 1);
    }
  }
  const fill = (target: Int32Array): void => {
    for (let q = 0; q < 2; q++) for (let r = 0; r < 32; r++) target[q] = target[q]! | (nextBit() << r);
  };
  fill(acc);
  fill(sr);

  /** Conditionally accumulate, then advance the authenticator's register with a fresh keystream bit. */
  const update = (bit: number): void => {
    const mask = -bit;
    acc[0] = acc[0]! ^ (sr[0]! & mask);
    acc[1] = acc[1]! ^ (sr[1]! & mask);
    const fresh = nextBit();
    sr[0] = (sr[0]! >>> 1) | (sr[1]! << 31);
    sr[1] = (sr[1]! >>> 1) | (fresh << 31);
  };

  return {
    absorb(data, off, len) {
      for (let i = 0; i < len; i++) {
        const b = data[off + i]!;
        for (let j = 0; j < 8; j++) {
          clock();
          update((b >> j) & 1);
        }
      }
    },
    crypt(input, decrypting) {
      const out = new Uint8Array(input.length);
      for (let i = 0; i < input.length; i++) {
        let cc = 0;
        for (let j = 0; j < 8; j++) {
          const bit = ((input[i]! >> j) & 1) ^ nextBit();
          cc |= bit << j;
          // The *plaintext* bit is authenticated, whichever direction produced it.
          update(decrypting ? bit : (input[i]! >> j) & 1);
        }
        out[i] = cc;
      }
      return out;
    },
    tag() {
      const t = new Uint8Array(8);
      const a0 = acc[0]! ^ sr[0]!;
      const a1 = acc[1]! ^ sr[1]!;
      for (let i = 0; i < 4; i++) {
        t[i] = (a0 >>> (8 * i)) & 0xff;
        t[4 + i] = (a1 >>> (8 * i)) & 0xff;
      }
      return t;
    },
  };
}

/** The DER-shaped length prefix the specification puts in front of the associated data. */
function aadLengthPrefix(len: number): Uint8Array {
  const buf = new Uint8Array(5);
  let pos: number;
  if (len < 128) {
    pos = 4;
    buf[pos] = len;
  } else {
    pos = 5;
    let remaining = len;
    do {
      buf[--pos] = remaining & 0xff;
      remaining >>>= 8;
    } while (remaining !== 0);
    const count = 5 - pos;
    buf[--pos] = 0x80 | count;
  }
  return buf.subarray(pos);
}

function run(
  key: Uint8Array,
  nonce: Uint8Array,
  input: Uint8Array,
  aad: Uint8Array,
  decrypting: boolean,
): { out: Uint8Array; tag: Uint8Array } {
  if (key.length !== 16) throw new Error(`Grain-128AEAD needs a 16-byte key; got ${key.length}.`);
  if (nonce.length !== 12) throw new Error(`Grain-128AEAD needs a 12-byte nonce; got ${nonce.length}.`);
  const e = engine(key, nonce);
  const prefix = aadLengthPrefix(aad.length);
  e.absorb(prefix, 0, prefix.length);
  e.absorb(aad, 0, aad.length);
  const out = e.crypt(input, decrypting);
  return { out, tag: e.tag() };
}

export function grain128AeadEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Uint8Array {
  const { out, tag } = run(key, nonce, plaintext, aad, false);
  const result = new Uint8Array(out.length + 8);
  result.set(out, 0);
  result.set(tag, out.length);
  return result;
}

export function grain128AeadDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  aad: Uint8Array,
): Uint8Array | null {
  if (data.length < 8) return null;
  const { out, tag } = run(key, nonce, data.subarray(0, data.length - 8), aad, true);
  let diff = 0;
  for (let i = 0; i < 8; i++) diff |= tag[i]! ^ data[data.length - 8 + i]!;
  return diff === 0 ? out : null;
}
