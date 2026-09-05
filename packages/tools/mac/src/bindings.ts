import { cmac } from "@noble/ciphers/aes.js";
import { poly1305 } from "@noble/ciphers/_poly1305.js";
import { hmac } from "@noble/hashes/hmac.js";
import { kmac128, kmac256 } from "@noble/hashes/sha3-addons.js";
import { blake224, blake256, blake384, blake512 } from "@noble/hashes/blake1.js";
import { blake2b, blake2s } from "@noble/hashes/blake2.js";
import { md5, ripemd160, sha1 } from "@noble/hashes/legacy.js";
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from "@noble/hashes/sha2.js";
import { sha3_224, sha3_256, sha3_384, sha3_512 } from "@noble/hashes/sha3.js";
import {
  createAsconMac,
  createAsconPrf,
  asconPrfShort,
  ASCON_PRF_SHORT_MAX,
  createGost,
  createHaval,
  createMd2,
  createMd4,
  createRipemd128,
  createRipemd256,
  createRipemd320,
  createSm3,
  createSkein,
  createSnefru,
  createStreebog,
  createTiger,
  createWhirlpool,
  createHighwayHash,
  siphash24,
  siphash13,
  siphash48,
  halfSipHash24,
  chaskeyMac,
  pelicanMac,
  poly1305AesMac,
  retailMac,
  pmacAes,
  vmac,
  gmac,
  umac,
  cbcMac,
  lightMac,
} from "@ocs/algos";
import { requireHmacHash } from "./catalogue/tool-meta";

/**
 * The only module in this package that imports an implementation. Reached through
 * `./definition`, so listing four tools in the sidebar loads none of it.
 *
 * Everything here is verified against its standard in `tests/mac.test.ts`: RFC 4231 for
 * HMAC, SP 800-185 for KMAC, RFC 8439 for Poly1305, RFC 4493 for AES-CMAC.
 */

/** The incremental shape the compute path uses, matching `ToolStream`'s needs. */
export interface MacHasher {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

/**
 * Hash constructors HMAC can be keyed with.
 *
 * SM3 comes from `@ocs/algos` and is not a noble `CHash`, so it needs an adapter to
 * satisfy noble's `hmac`. Rather than fake one, HMAC-SM3 is computed by hand below — the
 * construction is four lines and doing it explicitly is clearer than a shim that pretends
 * to be something it is not.
 */
const NOBLE_HASHES: Record<string, Parameters<typeof hmac>[0]> = {
  sha224,
  sha256,
  sha384,
  sha512,
  "sha512-224": sha512_224,
  "sha512-256": sha512_256,
  "sha3-224": sha3_224,
  "sha3-256": sha3_256,
  "sha3-384": sha3_384,
  "sha3-512": sha3_512,
  sha1,
  md5,
  ripemd160,
  blake2b,
  blake2s,
  // BLAKE1 is noble's too, so HMAC over it uses the audited path and is covered by the cross-check
  // against noble in `tests/mac.test.ts` for free.
  blake224,
  blake256,
  blake384,
  blake512,
};

/**
 * Every hash HMAC can be keyed that does not come from noble.
 *
 * Thirty-two of the forty-eight, once the list was widened to everything PHP's `hash_hmac_algos()`
 * offers. They arrive from `@ocs/algos` as `{ update, digest }` factories rather than as noble
 * `CHash` objects, which is what `hmacGeneric` below exists for.
 *
 * `blockLen` is not read from here -- `requireHmacHash` owns it, so the metadata the form shows and
 * the block size the construction uses cannot disagree. What this map supplies is only the hash.
 */
const LOCAL_HASHES: Record<string, () => MacHasher> = {
  sm3: createSm3,
  md2: createMd2,
  md4: createMd4,
  ripemd128: createRipemd128,
  ripemd256: createRipemd256,
  ripemd320: createRipemd320,
  whirlpool: createWhirlpool,
  snefru: createSnefru,
  gost94: () => createGost("test"),
  "gost94-crypto": () => createGost("crypto"),
  streebog256: () => createStreebog(32),
  streebog512: () => createStreebog(64),
  // Skein's block is its state size, and the output length is the natural one for each.
  skein256: () => createSkein(32, 32),
  skein512: () => createSkein(64, 64),
  skein1024: () => createSkein(128, 128),
  "tiger128-3": () => createTiger(3, 16),
  "tiger160-3": () => createTiger(3, 20),
  "tiger192-3": () => createTiger(3, 24),
  "tiger128-4": () => createTiger(4, 16),
  "tiger160-4": () => createTiger(4, 20),
  "tiger192-4": () => createTiger(4, 24),
  "haval128-3": () => createHaval(3, 16),
  "haval160-3": () => createHaval(3, 20),
  "haval192-3": () => createHaval(3, 24),
  "haval224-3": () => createHaval(3, 28),
  "haval256-3": () => createHaval(3, 32),
  "haval128-4": () => createHaval(4, 16),
  "haval160-4": () => createHaval(4, 20),
  "haval192-4": () => createHaval(4, 24),
  "haval224-4": () => createHaval(4, 28),
  "haval256-4": () => createHaval(4, 32),
  "haval128-5": () => createHaval(5, 16),
  "haval160-5": () => createHaval(5, 20),
  "haval192-5": () => createHaval(5, 24),
  "haval224-5": () => createHaval(5, 28),
  "haval256-5": () => createHaval(5, 32),
};

const IPAD = 0x36;
const OPAD = 0x5c;

/**
 * HMAC over any incremental hash, straight from RFC 2104. Streaming.
 *
 * This replaces what used to be a hand-written HMAC-SM3 plus a comment explaining that it could not
 * stream. It can: the inner hash consumes `K ^ ipad` and then the message as it arrives, and only the
 * *outer* hash needs the inner digest -- which does not exist until `digest()` anyway. The old
 * one-shot restriction was a property of that implementation, not of the construction.
 *
 * Two details that matter and are easy to get wrong. A key longer than the block is **hashed down**
 * before padding, not truncated -- truncating agrees with the standard for every key shorter than the
 * block and diverges silently for longer ones. And the padded key is `blockLen` bytes even when the
 * hash's own block is unusual: MD2's is 16 and Snefru's and GOST's are 32, which is exactly why
 * `blockLen` comes from the metadata rather than being assumed to be 64.
 */
function hmacGeneric(create: () => MacHasher, blockLen: number, key: Uint8Array): MacHasher {
  const normalized = new Uint8Array(blockLen);
  if (key.length > blockLen) {
    const reducer = create();
    reducer.update(key);
    normalized.set(reducer.digest());
  } else {
    normalized.set(key);
  }

  const inner = create();
  const innerPad = new Uint8Array(blockLen);
  for (let i = 0; i < blockLen; i++) innerPad[i] = normalized[i]! ^ IPAD;
  inner.update(innerPad);

  return {
    update: (chunk) => inner.update(chunk),
    digest: () => {
      const innerDigest = inner.digest();
      const outer = create();
      const outerPad = new Uint8Array(blockLen);
      for (let i = 0; i < blockLen; i++) outerPad[i] = normalized[i]! ^ OPAD;
      outer.update(outerPad);
      outer.update(innerDigest);
      return outer.digest();
    },
  };
}

/**
 * One HMAC, whichever half of the list the hash came from.
 *
 * noble's `hmac` is kept for the sixteen hashes noble provides, because it is audited and because it
 * gives `hmacGeneric` something to be checked against -- `tests/mac.test.ts` runs both over every
 * noble hash and requires them to agree, which is what makes the generic path trustworthy for the
 * thirty-two hashes noble does not have.
 */
function hmacFor(hashId: string, key: Uint8Array): MacHasher {
  const noble = NOBLE_HASHES[hashId];
  if (noble) {
    const engine = hmac.create(noble, key);
    return {
      update: (chunk) => void engine.update(chunk),
      digest: () => engine.digest(),
    };
  }

  const create = LOCAL_HASHES[hashId];
  if (!create) throw new Error(`HMAC is not bound for hash: ${hashId}`);
  return hmacGeneric(create, requireHmacHash(hashId).blockLen, key);
}

export function computeHmac(hashId: string, key: Uint8Array, message: Uint8Array): Uint8Array {
  const engine = hmacFor(hashId, key);
  engine.update(message);
  return engine.digest();
}

/** Incremental HMAC. Available for every hash now, including the ones from `@ocs/algos`. */
export function createHmacStream(hashId: string, key: Uint8Array): MacHasher {
  return hmacFor(hashId, key);
}

/**
 * Skein-MAC, Ascon-MAC, Ascon-PRF and Ascon-PRFShort: the native keyed modes.
 *
 * All four key their primitive directly rather than nesting hashes the way HMAC must, which is why they
 * need no block size and no ipad/opad. Three of them stream; PRFShort does not, and cannot -- its input
 * is capped at 16 bytes and its length is part of the initialising value, so there is nothing to absorb
 * incrementally.
 */
export function createSkeinMacStream(
  key: Uint8Array,
  stateBytes: number,
  outputLen: number,
): MacHasher {
  return createSkein(stateBytes, outputLen, key);
}

export function createAsconMacStream(key: Uint8Array): MacHasher {
  return createAsconMac(key);
}

export function createAsconPrfStream(key: Uint8Array, outputLen: number): MacHasher {
  return createAsconPrf(key, outputLen);
}

/**
 * HighwayHash, streaming.
 *
 * Genuinely incremental, unlike the five non-cryptographic families in the hash package: HighwayHash
 * consumes 32-byte packets in order and only its remainder needs holding back. The width chooses one of
 * three finalisers rather than truncating one, so it goes in at construction.
 */
export function createHighwayStream(key: Uint8Array, outputLen: number): MacHasher {
  const bits = outputLen === 32 ? 256 : outputLen === 16 ? 128 : 64;
  return createHighwayHash(key, bits);
}

/**
 * Ascon-PRFShort, one-shot, with its input limit reported rather than thrown.
 *
 * The compute path turns this into a rendered error, which is the family's convention for anything a
 * user reaches by typing too much into the input panel.
 */
export function computeAsconPrfShort(
  key: Uint8Array,
  message: Uint8Array,
  outputLen: number,
): Uint8Array {
  if (message.length > ASCON_PRF_SHORT_MAX) {
    throw new Error(
      `Ascon-PRFShort takes at most ${ASCON_PRF_SHORT_MAX} bytes of input; this one is ${message.length}. Use Ascon-PRF for anything longer.`,
    );
  }
  return asconPrfShort(key, message, outputLen);
}

export function computeKmac(
  variant: string,
  key: Uint8Array,
  message: Uint8Array,
  outputLen: number,
  customization: Uint8Array,
): Uint8Array {
  const fn = variant === "kmac256" ? kmac256 : kmac128;
  // `dkLen` is always passed explicitly. noble's defaults are 16 and 32 bytes
  // respectively, which are not the lengths SP 800-185's samples use, and leaving it
  // implicit would make the tool disagree with the standard for no visible reason.
  return fn(key, message, { dkLen: outputLen, personalization: customization });
}

export function createKmacStream(
  variant: string,
  key: Uint8Array,
  outputLen: number,
  customization: Uint8Array,
): MacHasher {
  const fn = variant === "kmac256" ? kmac256 : kmac128;
  const engine = fn.create(key, { dkLen: outputLen, personalization: customization });
  return {
    update: (chunk) => void engine.update(chunk),
    digest: () => engine.digest(),
  };
}

/**
 * SipHash-2-4.
 *
 * The one binding here that is a straight call into `@ocs/algos` with nothing wrapped around it: no
 * key stretching, no output truncation to arrange, no streaming shape. The round counts are parameters
 * of the implementation and fixed at 2 and 4 here, because SipHash-1-3 has no reachable published
 * vector -- see the note in `packages/algos/src/siphash.ts`.
 */
export function computeSiphash(key: Uint8Array, message: Uint8Array): Uint8Array {
  return siphash24(key, message);
}

export function computeSiphash13(key: Uint8Array, message: Uint8Array): Uint8Array {
  return siphash13(key, message);
}

export function computeSiphash48(key: Uint8Array, message: Uint8Array): Uint8Array {
  return siphash48(key, message);
}

export function computeHalfSiphash(key: Uint8Array, message: Uint8Array): Uint8Array {
  return halfSipHash24(key, message);
}

/** Note the argument order: message first, key second. */
export function computePoly1305(key: Uint8Array, message: Uint8Array): Uint8Array {
  return poly1305(message, key);
}

export function createPoly1305Stream(key: Uint8Array): MacHasher {
  const engine = poly1305.create(key);
  return {
    update: (chunk) => void engine.update(chunk),
    digest: () => engine.digest(),
  };
}

export function computeCmac(key: Uint8Array, message: Uint8Array): Uint8Array {
  return cmac(message, key);
}

export function computeChaskey(key: Uint8Array, message: Uint8Array): Uint8Array {
  return chaskeyMac(key, message);
}

export function computePelican(key: Uint8Array, message: Uint8Array): Uint8Array {
  return pelicanMac(key, message);
}

export function computePoly1305Aes(key: Uint8Array, message: Uint8Array): Uint8Array {
  const keyR = key.subarray(0, 16);
  const keyK = key.subarray(16, 32);
  const nonce = new Uint8Array(16);
  return poly1305AesMac(keyR, keyK, nonce, message);
}

export function computeRetailMac(key: Uint8Array, message: Uint8Array): Uint8Array {
  return retailMac(key, message, { padding: "pad2" });
}

export function computePmac(key: Uint8Array, message: Uint8Array): Uint8Array {
  return pmacAes(key, message);
}

export function computeVmac(key: Uint8Array, message: Uint8Array): Uint8Array {
  return vmac(key, message, { nonce: new Uint8Array(16) });
}

export function computeGmac(key: Uint8Array, message: Uint8Array): Uint8Array {
  return gmac(key, message, { nonce: new Uint8Array(12) });
}

export function computeUmac(key: Uint8Array, message: Uint8Array): Uint8Array {
  return umac(key, message, { nonce: new Uint8Array(8) });
}

export function computeCbcMac(key: Uint8Array, message: Uint8Array): Uint8Array {
  return cbcMac(key, message);
}

export function computeLightMac(key: Uint8Array, message: Uint8Array): Uint8Array {
  return lightMac(key, message);
}

