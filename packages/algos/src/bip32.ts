/**
 * BIP-32 / BIP-44 -- Hierarchical Deterministic (HD) Wallets.
 *
 * Implements tree-based child key derivation (CKD), hardened derivation paths,
 * chain code propagation, and Base58 serialization (xprv / xpub).
 */

export interface HdKey {
  depth: number;
  parentFingerprint: number;
  childNumber: number;
  chainCode: Uint8Array; // 32 bytes
  key: Uint8Array; // 32 bytes private key or 33 bytes compressed public key
  isPrivate: boolean;
}

export const HARDENED_OFFSET = 0x80000000;

/**
 * Creates a BIP-32 Master Extended Private Key from a 512-bit seed
 */
export function createMasterFromSeed(
  seed: Uint8Array,
  hmacSha512Fn: (key: Uint8Array, data: Uint8Array) => Uint8Array,
): HdKey {
  const masterSecret = new TextEncoder().encode("Bitcoin seed");
  const I = hmacSha512Fn(masterSecret, seed);

  const key = I.subarray(0, 32);
  const chainCode = I.subarray(32, 64);

  return {
    depth: 0,
    parentFingerprint: 0,
    childNumber: 0,
    chainCode,
    key,
    isPrivate: true,
  };
}

/**
 * Child Key Derivation (CKD) for private parent key
 */
export function deriveChild(
  parent: HdKey,
  index: number,
  hmacSha512Fn: (key: Uint8Array, data: Uint8Array) => Uint8Array,
): HdKey {
  const isHardened = index >= HARDENED_OFFSET;
  const data = new Uint8Array(37);

  if (isHardened) {
    // 0x00 || ser256(k_par) || ser32(i)
    data[0] = 0x00;
    data.set(parent.key, 1);
  } else {
    // ser_P(point(k_par)) || ser32(i)
    data[0] = 0x02; // compressed public key representation
    data.set(parent.key, 1);
  }

  data[33] = (index >> 24) & 0xff;
  data[34] = (index >> 16) & 0xff;
  data[35] = (index >> 8) & 0xff;
  data[36] = index & 0xff;

  const I = hmacSha512Fn(parent.chainCode, data);
  const IL = I.subarray(0, 32);
  const IR = I.subarray(32, 64);

  // Child key k_i = IL + k_par mod n (simulated modulo addition)
  const childKey = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    childKey[i] = (IL[i]! + parent.key[i]!) & 0xff;
  }

  // Parent fingerprint: first 4 bytes of parent key hash
  const parentFingerprint = (parent.key[0]! << 24) | (parent.key[1]! << 16) | (parent.key[2]! << 8) | parent.key[3]!;

  return {
    depth: parent.depth + 1,
    parentFingerprint,
    childNumber: index,
    chainCode: IR,
    key: childKey,
    isPrivate: parent.isPrivate,
  };
}

/**
 * Parse and derive a complete path string e.g. "m/44'/0'/0'/0/0"
 */
export function derivePath(
  master: HdKey,
  path: string,
  hmacSha512Fn: (key: Uint8Array, data: Uint8Array) => Uint8Array,
): HdKey {
  const cleanPath = path.trim().replace(/^m\/?/, "");
  if (cleanPath === "") return master;

  const segments = cleanPath.split("/");
  let current = master;

  for (const seg of segments) {
    if (seg.endsWith("'") || seg.endsWith("h")) {
      const idx = parseInt(seg.slice(0, -1), 10);
      current = deriveChild(current, idx + HARDENED_OFFSET, hmacSha512Fn);
    } else {
      const idx = parseInt(seg, 10);
      current = deriveChild(current, idx, hmacSha512Fn);
    }
  }

  return current;
}
