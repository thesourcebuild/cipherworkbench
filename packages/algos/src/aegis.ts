/**
 * AEGIS-128L and AEGIS-256, from draft-irtf-cfrg-aegis-aead.
 *
 * An AES-round-based AEAD, and the fastest one there is on hardware with AES instructions -- roughly
 * twice AES-GCM's throughput, because the state update is eight independent AES rounds with no carry
 * chain and no field multiplication. It is in the CAESAR competition's final portfolio for
 * high-performance applications, has TLS cipher suites proposed for it, and libsodium ships it.
 *
 * Four things to know before touching this.
 *
 * **Nothing here is fast.** The point of AEGIS is `AESENC` in hardware; JavaScript has no such
 * instruction, so this runs a byte-wise AES round eight times per 32 bytes and is *slower* than
 * AES-GCM here. It is present for interoperability -- reading what libsodium or a QUIC stack wrote --
 * and the tool's own note says so rather than repeating the performance claim, which would be false in
 * this host.
 *
 * **The two variants differ in more than size.** AEGIS-128L has eight state blocks, absorbs 256 bits
 * at a time and mixes two message blocks per update; AEGIS-256 has six, absorbs 128 bits, and derives
 * its keystream from a different combination of state blocks (`S1 ^ S4 ^ S5 ^ (S2 & S3)` against
 * 128L's pair of `S1 ^ S6 ^ (S2 & S3)` and `S2 ^ S5 ^ (S6 & S7)`). They are two algorithms sharing a
 * shape, not one parameterised algorithm, which is why the update functions are written out separately.
 *
 * **Enc and Dec are not symmetric, and it matters.** Encryption absorbs the *plaintext* into the state
 * and decryption absorbs the recovered plaintext -- so a partial final block must be zero-padded
 * *after* truncation, not before. `decryptPartial` is that step, and an implementation that reuses the
 * full-block path for the tail produces a tag that verifies against itself and nothing else. Both the
 * draft's short-message vectors and its four deliberately-invalid vectors cover this.
 *
 * **The tag can be 128 or 256 bits**, and both are specified. The cipher family exposes the choice,
 * because a 256-bit tag is one of the reasons to pick AEGIS and truncating to 128 silently would throw
 * that away.
 */
import { aesRound } from "./aes-round";

export const AEGIS_BLOCK = 16;
export const AEGIS128L_KEY_LEN = 16;
export const AEGIS128L_NONCE_LEN = 16;
export const AEGIS256_KEY_LEN = 32;
export const AEGIS256_NONCE_LEN = 32;

/** The tag lengths the draft defines, in bytes. */
export const AEGIS_TAG_LENS: readonly number[] = [16, 32];

/** C0 and C1: the Fibonacci-derived constants both variants initialise from. */
const C0 = new Uint8Array([
  0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
]);
const C1 = new Uint8Array([
  0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
]);

const block = (): Uint8Array => new Uint8Array(AEGIS_BLOCK);

function xorBlocks(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = block();
  for (let i = 0; i < AEGIS_BLOCK; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

function xorInto(target: Uint8Array, other: Uint8Array): void {
  for (let i = 0; i < AEGIS_BLOCK; i++) target[i] = target[i]! ^ other[i]!;
}

/** The keystream combination, written once because both variants XOR then AND then XOR. */
function combine(
  s: readonly Uint8Array[],
  xs: readonly number[],
  andA: number,
  andB: number,
): Uint8Array {
  const out = block();
  for (let i = 0; i < AEGIS_BLOCK; i++) {
    let v = 0;
    for (const x of xs) v ^= s[x]![i]!;
    out[i] = v ^ (s[andA]![i]! & s[andB]![i]!);
  }
  return out;
}

/** `LE64(ad_bits) || LE64(msg_bits)`, the length block folded in at finalisation. */
function lengthBlock(adBytes: number, msgBytes: number): Uint8Array {
  const out = block();
  const write = (at: number, bytes: number) => {
    // Lengths are in *bits*, and JavaScript's bitwise operators stop at 32 -- so the multiply by 8
    // and the byte extraction are done in floating point, which is exact below 2^53.
    let bits = bytes * 8;
    for (let i = 0; i < 8; i++) {
      out[at + i] = bits % 256;
      bits = Math.floor(bits / 256);
    }
  };
  write(0, adBytes);
  write(8, msgBytes);
  return out;
}

/** Constant-time tag comparison: every byte is read whatever the first one says. */
function tagsMatch(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function requireLength(value: Uint8Array, expected: number, what: string): void {
  if (value.length !== expected) {
    throw new Error(`${what} must be ${expected} bytes; this one is ${value.length}.`);
  }
}

function requireTagLen(tagLen: number): void {
  if (!AEGIS_TAG_LENS.includes(tagLen)) {
    throw new Error(`AEGIS tags are 16 or 32 bytes; ${tagLen} was requested.`);
  }
}

// ── AEGIS-128L ───────────────────────────────────────────────────────────────

/**
 * The 128L state: eight blocks, updated by eight AES rounds per call.
 *
 * A class rather than a closure over eight locals, because the same state is driven by five different
 * phases (init, absorb, encrypt, decrypt, finalize) and passing eight blocks between them was the
 * version of this that had a transposition bug in it.
 */
class Aegis128L {
  private readonly s: Uint8Array[];
  private readonly next: Uint8Array[] = Array.from({ length: 8 }, block);

  constructor(key: Uint8Array, nonce: Uint8Array) {
    requireLength(key, AEGIS128L_KEY_LEN, "The AEGIS-128L key");
    requireLength(nonce, AEGIS128L_NONCE_LEN, "The AEGIS-128L nonce");

    const kn = xorBlocks(key, nonce);
    this.s = [
      Uint8Array.from(kn),
      Uint8Array.from(C1),
      Uint8Array.from(C0),
      Uint8Array.from(C1),
      Uint8Array.from(kn),
      xorBlocks(key, C0),
      xorBlocks(key, C1),
      xorBlocks(key, C0),
    ];
    for (let i = 0; i < 10; i++) this.update(nonce, key);
  }

  /** `S'0 = AESRound(S7, S0 ^ M0)`, and so on around the ring. */
  update(m0: Uint8Array, m1: Uint8Array): void {
    const s = this.s;
    const t = this.next;
    aesRound(s[7]!, xorBlocks(s[0]!, m0), t[0]!);
    aesRound(s[0]!, s[1]!, t[1]!);
    aesRound(s[1]!, s[2]!, t[2]!);
    aesRound(s[2]!, s[3]!, t[3]!);
    aesRound(s[3]!, xorBlocks(s[4]!, m1), t[4]!);
    aesRound(s[4]!, s[5]!, t[5]!);
    aesRound(s[5]!, s[6]!, t[6]!);
    aesRound(s[6]!, s[7]!, t[7]!);
    for (let i = 0; i < 8; i++) s[i]!.set(t[i]!);
  }

  /** The two 128-bit keystream blocks. */
  private keystream(): [Uint8Array, Uint8Array] {
    return [combine(this.s, [1, 6], 2, 3), combine(this.s, [2, 5], 6, 7)];
  }

  absorb(data: Uint8Array): void {
    for (let at = 0; at < data.length; at += 32) {
      const [m0, m1] = this.pair(data, at);
      this.update(m0, m1);
    }
  }

  /** A 256-bit input block as two 128-bit halves, zero-padded where the data runs out. */
  private pair(data: Uint8Array, at: number): [Uint8Array, Uint8Array] {
    const m0 = block();
    const m1 = block();
    m0.set(data.subarray(at, Math.min(at + 16, data.length)));
    if (data.length > at + 16) m1.set(data.subarray(at + 16, Math.min(at + 32, data.length)));
    return [m0, m1];
  }

  encrypt(msg: Uint8Array): Uint8Array {
    const out = new Uint8Array(msg.length);
    for (let at = 0; at < msg.length; at += 32) {
      const [z0, z1] = this.keystream();
      const [t0, t1] = this.pair(msg, at);
      const c0 = xorBlocks(t0, z0);
      const c1 = xorBlocks(t1, z1);
      out.set(c0.subarray(0, Math.min(16, msg.length - at)), at);
      if (msg.length - at > 16) out.set(c1.subarray(0, Math.min(16, msg.length - at - 16)), at + 16);
      this.update(t0, t1);
    }
    return out;
  }

  decrypt(ct: Uint8Array): Uint8Array {
    const out = new Uint8Array(ct.length);
    let at = 0;
    for (; ct.length - at >= 32; at += 32) {
      const [z0, z1] = this.keystream();
      const [t0, t1] = this.pair(ct, at);
      const p0 = xorBlocks(t0, z0);
      const p1 = xorBlocks(t1, z1);
      out.set(p0, at);
      out.set(p1, at + 16);
      this.update(p0, p1);
    }

    const remaining = ct.length - at;
    if (remaining > 0) {
      /**
       * The partial tail, and the asymmetry that makes it its own function.
       *
       * The state absorbs the *plaintext*, so the bytes fed back must be the recovered plaintext
       * zero-padded to a full block -- not the keystream XOR of a zero-padded ciphertext, which
       * differs in exactly the padding region. Using the full-block path here yields a tag that
       * verifies against this implementation and no other.
       */
      const [z0, z1] = this.keystream();
      const [t0, t1] = this.pair(ct, at);
      const p0 = xorBlocks(t0, z0);
      const p1 = xorBlocks(t1, z1);
      const recovered = new Uint8Array(32);
      recovered.set(p0, 0);
      recovered.set(p1, 16);
      out.set(recovered.subarray(0, remaining), at);

      const v0 = block();
      const v1 = block();
      const tail = recovered.subarray(0, remaining);
      v0.set(tail.subarray(0, Math.min(16, remaining)));
      if (remaining > 16) v1.set(tail.subarray(16));
      this.update(v0, v1);
    }
    return out;
  }

  finalize(adLen: number, msgLen: number, tagLen: number): Uint8Array {
    const t = xorBlocks(this.s[2]!, lengthBlock(adLen, msgLen));
    for (let i = 0; i < 7; i++) this.update(t, t);

    if (tagLen === 16) {
      const tag = block();
      for (let i = 0; i <= 6; i++) xorInto(tag, this.s[i]!);
      return tag;
    }
    const tag = new Uint8Array(32);
    const low = block();
    const high = block();
    for (let i = 0; i <= 3; i++) xorInto(low, this.s[i]!);
    for (let i = 4; i <= 7; i++) xorInto(high, this.s[i]!);
    tag.set(low, 0);
    tag.set(high, 16);
    return tag;
  }
}

// ── AEGIS-256 ────────────────────────────────────────────────────────────────

class Aegis256 {
  private readonly s: Uint8Array[];
  private readonly next: Uint8Array[] = Array.from({ length: 6 }, block);

  constructor(key: Uint8Array, nonce: Uint8Array) {
    requireLength(key, AEGIS256_KEY_LEN, "The AEGIS-256 key");
    requireLength(nonce, AEGIS256_NONCE_LEN, "The AEGIS-256 nonce");

    const k0 = key.subarray(0, 16);
    const k1 = key.subarray(16, 32);
    const n0 = nonce.subarray(0, 16);
    const n1 = nonce.subarray(16, 32);

    this.s = [
      xorBlocks(k0, n0),
      xorBlocks(k1, n1),
      Uint8Array.from(C1),
      Uint8Array.from(C0),
      xorBlocks(k0, C0),
      xorBlocks(k1, C1),
    ];

    for (let i = 0; i < 4; i++) {
      this.update(k0);
      this.update(k1);
      this.update(xorBlocks(k0, n0));
      this.update(xorBlocks(k1, n1));
    }
  }

  update(m: Uint8Array): void {
    const s = this.s;
    const t = this.next;
    aesRound(s[5]!, xorBlocks(s[0]!, m), t[0]!);
    aesRound(s[0]!, s[1]!, t[1]!);
    aesRound(s[1]!, s[2]!, t[2]!);
    aesRound(s[2]!, s[3]!, t[3]!);
    aesRound(s[3]!, s[4]!, t[4]!);
    aesRound(s[4]!, s[5]!, t[5]!);
    for (let i = 0; i < 6; i++) s[i]!.set(t[i]!);
  }

  private keystream(): Uint8Array {
    return combine(this.s, [1, 4, 5], 2, 3);
  }

  private padded(data: Uint8Array, at: number): Uint8Array {
    const out = block();
    out.set(data.subarray(at, Math.min(at + 16, data.length)));
    return out;
  }

  absorb(data: Uint8Array): void {
    for (let at = 0; at < data.length; at += 16) this.update(this.padded(data, at));
  }

  encrypt(msg: Uint8Array): Uint8Array {
    const out = new Uint8Array(msg.length);
    for (let at = 0; at < msg.length; at += 16) {
      const z = this.keystream();
      const xi = this.padded(msg, at);
      this.update(xi);
      const ci = xorBlocks(xi, z);
      out.set(ci.subarray(0, Math.min(16, msg.length - at)), at);
    }
    return out;
  }

  decrypt(ct: Uint8Array): Uint8Array {
    const out = new Uint8Array(ct.length);
    let at = 0;
    for (; ct.length - at >= 16; at += 16) {
      const z = this.keystream();
      const xi = xorBlocks(this.padded(ct, at), z);
      out.set(xi, at);
      this.update(xi);
    }

    const remaining = ct.length - at;
    if (remaining > 0) {
      // Same asymmetry as 128L's tail: absorb the truncated plaintext, zero-padded.
      const z = this.keystream();
      const xi = xorBlocks(this.padded(ct, at), z);
      out.set(xi.subarray(0, remaining), at);
      const v = block();
      v.set(xi.subarray(0, remaining));
      this.update(v);
    }
    return out;
  }

  finalize(adLen: number, msgLen: number, tagLen: number): Uint8Array {
    const t = xorBlocks(this.s[3]!, lengthBlock(adLen, msgLen));
    for (let i = 0; i < 7; i++) this.update(t);

    if (tagLen === 16) {
      const tag = block();
      for (let i = 0; i <= 5; i++) xorInto(tag, this.s[i]!);
      return tag;
    }
    const tag = new Uint8Array(32);
    const low = block();
    const high = block();
    for (let i = 0; i <= 2; i++) xorInto(low, this.s[i]!);
    for (let i = 3; i <= 5; i++) xorInto(high, this.s[i]!);
    tag.set(low, 0);
    tag.set(high, 16);
    return tag;
  }
}

// ── the public surface ───────────────────────────────────────────────────────

export type AegisVariant = "aegis128l" | "aegis256";

interface AegisState {
  absorb(data: Uint8Array): void;
  encrypt(msg: Uint8Array): Uint8Array;
  decrypt(ct: Uint8Array): Uint8Array;
  finalize(adLen: number, msgLen: number, tagLen: number): Uint8Array;
}

function start(variant: AegisVariant, key: Uint8Array, nonce: Uint8Array): AegisState {
  return variant === "aegis128l" ? new Aegis128L(key, nonce) : new Aegis256(key, nonce);
}

/**
 * Encrypts, appending the tag -- the layout every AEAD in this repo uses.
 *
 * The draft returns the ciphertext and the tag separately, as RFC 5116 does; concatenating is the
 * convention on the wire and what the cipher family's decrypt expects back.
 */
export function aegisEncrypt(
  variant: AegisVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
  tagLen = 16,
): Uint8Array {
  requireTagLen(tagLen);
  const state = start(variant, key, nonce);
  state.absorb(ad);
  const ct = state.encrypt(plaintext);
  const tag = state.finalize(ad.length, plaintext.length, tagLen);

  const out = new Uint8Array(ct.length + tagLen);
  out.set(ct, 0);
  out.set(tag, ct.length);
  return out;
}

/** Decrypts and verifies, returning `null` when the tag does not match. */
export function aegisDecrypt(
  variant: AegisVariant,
  key: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
  ad: Uint8Array = new Uint8Array(0),
  tagLen = 16,
): Uint8Array | null {
  requireTagLen(tagLen);
  if (sealed.length < tagLen) return null;

  const state = start(variant, key, nonce);
  state.absorb(ad);

  const split = sealed.length - tagLen;
  const message = state.decrypt(sealed.subarray(0, split));
  const expected = state.finalize(ad.length, message.length, tagLen);

  if (!tagsMatch(expected, sealed.subarray(split))) {
    // Nothing partial escapes: the draft requires the plaintext be discarded on failure.
    message.fill(0);
    return null;
  }
  return message;
}
