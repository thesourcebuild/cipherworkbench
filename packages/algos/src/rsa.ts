/**
 * RSA's numeric primitives and its two signature paddings, from RFC 8017.
 *
 * This exists for one reason, stated plainly because hand-rolling RSA is normally the wrong
 * answer: WebCrypto — which is where this app gets RSA — supports exactly four hashes
 * (SHA-1, SHA-256, SHA-384, SHA-512) and refuses every other with `NotSupportedError`.
 * OpenSSL will sign with fourteen. Reaching parity with the algorithms OpenSSL names means
 * having a path that does not go through `crypto.subtle`, and WebCrypto exposes no raw RSA
 * primitive to build one on top of.
 *
 * So the split is: WebCrypto for the four hashes it supports, and this module for the other
 * ten. What that buys is coverage; what it costs is stated in `A008` and repeated here, so
 * nobody has to read the implementation to find out:
 *
 * **`modPow` below is not constant-time.** It is square-and-multiply over `bigint`, and its
 * timing depends on the bits of the exponent. In a server that would be a key-recovery
 * vulnerability. In a local tool with no remote observer it is a caveat rather than a hole —
 * but a caveat worth knowing before pasting a production key into a browser tab, which is why
 * signing through this path raises a diagnostic and signing through WebCrypto does not.
 *
 * Verification is unaffected: it uses the public exponent and no secret, so there is nothing
 * for timing to leak.
 *
 * Zero dependencies, like everything else in this package. The hash is always supplied by the
 * caller as a plain function, which is what keeps it that way.
 */

/** A digest function, supplied by the caller. */
export type HashFn = (data: Uint8Array) => Uint8Array;

// ── integer conversions (RFC 8017 §4) ───────────────────────────────────────

/** OS2IP: an octet string, big-endian, as a non-negative integer. */
export function os2ip(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/**
 * I2OSP: an integer as exactly `length` big-endian octets.
 *
 * The length is fixed rather than minimal, and that matters: an RSA signature is defined to
 * be exactly as long as the modulus, so a value with a leading zero byte must keep it. A
 * `toString(16)` without this padding is the classic way to emit a 255-byte signature that
 * nothing else will accept.
 */
export function i2osp(value: bigint, length: number): Uint8Array {
  if (value < 0n) throw new Error("i2osp: negative integer");
  const out = new Uint8Array(length);
  let remaining = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  if (remaining !== 0n) throw new Error(`i2osp: integer too large for ${length} octets`);
  return out;
}

/** Square-and-multiply modular exponentiation. See the constant-time note above. */
export function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) throw new Error("modPow: modulus must be positive");
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

// ── key material ────────────────────────────────────────────────────────────

/**
 * An RSA key as plain integers.
 *
 * The CRT parameters are optional because a JWK may omit them, and present because they make
 * the private operation roughly four times faster — a 4096-bit signature without them is
 * slow enough to be felt in a UI.
 */
export interface RsaPublicKey {
  n: bigint;
  e: bigint;
  /** Modulus size in octets. Signatures and ciphertexts are exactly this long. */
  k: number;
}

export interface RsaPrivateKey extends RsaPublicKey {
  d: bigint;
  p?: bigint;
  q?: bigint;
  dp?: bigint;
  dq?: bigint;
  qi?: bigint;
}

/** RSAVP1 — the public operation, `s^e mod n`. No secret, so no timing concern. */
export function rsavp1(key: RsaPublicKey, signature: bigint): bigint {
  if (signature >= key.n) throw new Error("rsavp1: signature representative out of range");
  return modPow(signature, key.e, key.n);
}

/**
 * RSASP1 — the private operation, `m^d mod n`, via the CRT when the parameters are present.
 *
 * The CRT form computes two exponentiations over halves of the modulus instead of one over
 * the whole of it, which is why every real implementation uses it. It is not a shortcut with
 * different results: the recombination is exact.
 */
export function rsasp1(key: RsaPrivateKey, message: bigint): bigint {
  if (message >= key.n) throw new Error("rsasp1: message representative out of range");

  const { p, q, dp, dq, qi } = key;
  if (
    p !== undefined &&
    q !== undefined &&
    dp !== undefined &&
    dq !== undefined &&
    qi !== undefined
  ) {
    const m1 = modPow(message % p, dp, p);
    const m2 = modPow(message % q, dq, q);
    // h = qi * (m1 - m2) mod p, taking care that the difference can be negative.
    const diff = (((m1 - m2) % p) + p) % p;
    const h = (qi * diff) % p;
    return m2 + h * q;
  }

  return modPow(message, key.d, key.n);
}

// ── PKCS#1 v1.5 signature padding (RFC 8017 §9.2) ───────────────────────────

/**
 * The `DigestInfo` DER prefix for each hash: an ASN.1 SEQUENCE wrapping the algorithm OID,
 * a NULL parameter and an OCTET STRING header, with the digest appended.
 *
 * Every one of these was **derived, not transcribed**: each was obtained by having OpenSSL
 * sign a message under that algorithm, applying the public operation to recover the padded
 * block, and reading off the bytes preceding the digest. `tests/openssl-parity.test.ts`
 * re-derives them the same way on every run, so a typo here fails rather than producing
 * signatures that only this implementation accepts. Copying these out of a blog post is how
 * a wrong OID ends up shipping — it verifies against itself perfectly.
 *
 * Keyed by this repo's hash ids, not OpenSSL's names.
 *
 * `md5-sha1`'s entry is the empty string, and that is not a placeholder. TLS 1.0 and 1.1 signed
 * the raw 36-byte MD5 ‖ SHA-1 concatenation with no `DigestInfo` wrapper at all — RFC 4346
 * §4.7 specifies exactly that, and OpenSSL still does it. Deriving the prefix from OpenSSL
 * produces zero bytes, which is how this was confirmed rather than guessed.
 */
export const PKCS1_DIGEST_INFO_PREFIX: Readonly<Record<string, string>> = {
  // No DigestInfo — see the note above. The digest is padded directly.
  "md5-sha1": "",
  md5: "3020300c06082a864886f70d020505000410",
  ripemd160: "3021300906052b2403020105000414",
  sha1: "3021300906052b0e03021a05000414",
  sha224: "302d300d06096086480165030402040500041c",
  sha256: "3031300d060960864801650304020105000420",
  sha384: "3041300d060960864801650304020205000430",
  sha512: "3051300d060960864801650304020305000440",
  "sha512-224": "302d300d06096086480165030402050500041c",
  "sha512-256": "3031300d060960864801650304020605000420",
  "sha3-224": "302d300d06096086480165030402070500041c",
  "sha3-256": "3031300d060960864801650304020805000420",
  "sha3-384": "3041300d060960864801650304020905000430",
  "sha3-512": "3051300d060960864801650304020a05000440",
  sm3: "3030300c06082a811ccf5501837805000420",
};

function unhex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** The full `DigestInfo` for a digest: the hash's DER prefix followed by the digest itself. */
export function digestInfo(hashId: string, digest: Uint8Array): Uint8Array {
  const prefix = PKCS1_DIGEST_INFO_PREFIX[hashId];
  if (prefix === undefined) throw new Error(`No PKCS#1 DigestInfo prefix known for ${hashId}`);
  const der = unhex(prefix);
  const out = new Uint8Array(der.length + digest.length);
  out.set(der, 0);
  out.set(digest, der.length);
  return out;
}

/**
 * EMSA-PKCS1-v1_5: `0x00 0x01 || 0xFF… || 0x00 || DigestInfo`, padded to the modulus size.
 *
 * At least eight 0xFF octets are required, which is what sets the minimum usable key size for
 * a given hash — SHA-512 under a 512-bit key does not fit, and saying so beats a wrong answer.
 */
export function emsaPkcs1Encode(hashId: string, digest: Uint8Array, emLen: number): Uint8Array {
  const t = digestInfo(hashId, digest);
  if (emLen < t.length + 11) {
    throw new Error(
      `The key is too small for ${hashId}: PKCS#1 v1.5 needs ${t.length + 11} octets and the modulus is ${emLen}.`,
    );
  }
  const em = new Uint8Array(emLen).fill(0xff);
  em[0] = 0x00;
  em[1] = 0x01;
  em[emLen - t.length - 1] = 0x00;
  em.set(t, emLen - t.length);
  return em;
}

// ── PSS (RFC 8017 §9.1) ─────────────────────────────────────────────────────

/** MGF1, the mask generation function both PSS and OAEP are built on. */
export function mgf1(seed: Uint8Array, length: number, hash: HashFn, hLen: number): Uint8Array {
  const out = new Uint8Array(length);
  const block = new Uint8Array(seed.length + 4);
  block.set(seed, 0);
  let offset = 0;
  for (let counter = 0; offset < length; counter++) {
    // The counter is appended as four big-endian octets, per the spec.
    block[seed.length] = (counter >>> 24) & 0xff;
    block[seed.length + 1] = (counter >>> 16) & 0xff;
    block[seed.length + 2] = (counter >>> 8) & 0xff;
    block[seed.length + 3] = counter & 0xff;
    const chunk = hash(block);
    const take = Math.min(hLen, length - offset);
    out.set(chunk.subarray(0, take), offset);
    offset += take;
  }
  return out;
}

function xorInto(target: Uint8Array, mask: Uint8Array): void {
  for (let i = 0; i < target.length; i++) target[i] = (target[i] ?? 0) ^ (mask[i] ?? 0);
}

/**
 * Clears the unused leading bits of the encoded message.
 *
 * `emBits` is `modBits - 1`, so for a modulus whose bit length is a multiple of eight the
 * encoded message is one octet shorter than the modulus; otherwise the top octet has spare
 * bits that must be zero. Getting this wrong produces a signature that verifies here and
 * nowhere else, and it only shows up for particular key sizes — 2048 bits hides it entirely.
 */
function clearLeadingBits(em: Uint8Array, emBits: number): void {
  const spare = 8 * em.length - emBits;
  if (spare > 0 && em.length > 0) em[0] = (em[0] ?? 0) & (0xff >> spare);
}

/**
 * EMSA-PSS-ENCODE. `salt` is supplied rather than generated so this stays a pure function —
 * the caller draws it from `randomBytes`, which is the app's single sanctioned source.
 */
export function emsaPssEncode(
  mHash: Uint8Array,
  salt: Uint8Array,
  emBits: number,
  hash: HashFn,
  hLen: number,
): Uint8Array {
  const emLen = Math.ceil(emBits / 8);
  const sLen = salt.length;
  if (emLen < hLen + sLen + 2) {
    throw new Error(
      `The key is too small for PSS with this hash: it needs ${hLen + sLen + 2} octets and has ${emLen}.`,
    );
  }

  // M' = eight zero octets || mHash || salt. The zero prefix is what distinguishes the
  // hash of the message from the hash of the PSS structure.
  const mPrime = new Uint8Array(8 + hLen + sLen);
  mPrime.set(mHash, 8);
  mPrime.set(salt, 8 + hLen);
  const h = hash(mPrime);

  const db = new Uint8Array(emLen - hLen - 1);
  db[emLen - hLen - sLen - 2] = 0x01;
  db.set(salt, emLen - hLen - sLen - 1);

  const maskedDb = new Uint8Array(db);
  xorInto(maskedDb, mgf1(h, db.length, hash, hLen));
  clearLeadingBits(maskedDb, emBits - 8 * hLen - 8);

  const em = new Uint8Array(emLen);
  em.set(maskedDb, 0);
  em.set(h, emLen - hLen - 1);
  em[emLen - 1] = 0xbc;
  return em;
}

/**
 * EMSA-PSS-VERIFY. Returns a boolean rather than throwing: an invalid signature is an answer,
 * not an error, and the caller renders it as one.
 */
export function emsaPssVerify(
  mHash: Uint8Array,
  em: Uint8Array,
  sLen: number,
  emBits: number,
  hash: HashFn,
  hLen: number,
): boolean {
  const emLen = Math.ceil(emBits / 8);
  if (em.length !== emLen) return false;
  if (emLen < hLen + sLen + 2) return false;
  if (em[emLen - 1] !== 0xbc) return false;

  const maskedDb = em.subarray(0, emLen - hLen - 1);
  const h = em.subarray(emLen - hLen - 1, emLen - 1);

  const spare = 8 * maskedDb.length - (emBits - 8 * hLen - 8);
  if (spare > 0 && ((maskedDb[0] ?? 0) & (0xff << (8 - spare)) & 0xff) !== 0) return false;

  const db = new Uint8Array(maskedDb);
  xorInto(db, mgf1(h, db.length, hash, hLen));
  clearLeadingBits(db, emBits - 8 * hLen - 8);

  for (let i = 0; i < emLen - hLen - sLen - 2; i++) if (db[i] !== 0x00) return false;
  if (db[emLen - hLen - sLen - 2] !== 0x01) return false;

  const salt = db.subarray(db.length - sLen);
  const mPrime = new Uint8Array(8 + hLen + sLen);
  mPrime.set(mHash, 8);
  mPrime.set(salt, 8 + hLen);
  const expected = hash(mPrime);

  let diff = 0;
  for (let i = 0; i < hLen; i++) diff |= (expected[i] ?? 0) ^ (h[i] ?? 0);
  return diff === 0;
}

// ── the two operations, assembled ───────────────────────────────────────────

/** Signs a digest with PKCS#1 v1.5 padding. Deterministic — no salt, no randomness. */
export function rsaPkcs1Sign(
  key: RsaPrivateKey,
  hashId: string,
  digest: Uint8Array,
): Uint8Array {
  const em = emsaPkcs1Encode(hashId, digest, key.k);
  return i2osp(rsasp1(key, os2ip(em)), key.k);
}

/**
 * Verifies a PKCS#1 v1.5 signature by re-encoding and comparing.
 *
 * The comparison is against the whole re-encoded block rather than a parse of the recovered
 * one, which is the safe way round. Parsing the recovered DigestInfo leniently — tolerating
 * extra trailing bytes, a missing NULL parameter, a different length encoding — is precisely
 * what Bleichenbacher's 2006 forgery and the 2021 wave of "BERserk"-style bugs exploited.
 * Comparing bytes admits exactly one valid encoding.
 */
export function rsaPkcs1Verify(
  key: RsaPublicKey,
  hashId: string,
  digest: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (signature.length !== key.k) return false;
  let recovered: Uint8Array;
  try {
    recovered = i2osp(rsavp1(key, os2ip(signature)), key.k);
  } catch {
    return false;
  }
  let expected: Uint8Array;
  try {
    expected = emsaPkcs1Encode(hashId, digest, key.k);
  } catch {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < key.k; i++) diff |= (recovered[i] ?? 0) ^ (expected[i] ?? 0);
  return diff === 0;
}

/** The number of bits in the modulus — PSS needs it, and it is not always `8 * k`. */
export function modulusBits(n: bigint): number {
  return n.toString(2).length;
}

export function rsaPssSign(
  key: RsaPrivateKey,
  digest: Uint8Array,
  salt: Uint8Array,
  hash: HashFn,
  hLen: number,
): Uint8Array {
  const emBits = modulusBits(key.n) - 1;
  const em = emsaPssEncode(digest, salt, emBits, hash, hLen);
  return i2osp(rsasp1(key, os2ip(em)), key.k);
}

export function rsaPssVerify(
  key: RsaPublicKey,
  digest: Uint8Array,
  signature: Uint8Array,
  saltLen: number,
  hash: HashFn,
  hLen: number,
): boolean {
  if (signature.length !== key.k) return false;
  const emBits = modulusBits(key.n) - 1;
  try {
    const em = i2osp(rsavp1(key, os2ip(signature)), Math.ceil(emBits / 8));
    return emsaPssVerify(digest, em, saltLen, emBits, hash, hLen);
  } catch {
    return false;
  }
}
