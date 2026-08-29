/**
 * OpenPGP String-to-Key (S2K) spec per RFC 4880 §3.7.1 and RFC 9580 §3.7.1.
 *
 * Implements:
 *  - Simple S2K (Specifier 0)
 *  - Salted S2K (Specifier 1)
 *  - Iterated and Salted S2K (Specifier 3)
 */

export type S2kType = "simple" | "salted" | "iterated-salted";

export interface S2kOptions {
  type?: S2kType;
  salt?: Uint8Array; // 8 bytes for Salted / Iterated-Salted
  /** Iteration count in total bytes hashed (default: 65536). */
  count?: number;
}

/**
 * Decodes the 1-byte count specifier per RFC 4880 §3.7.1.3.
 */
export function decodeS2kCount(c: number): number {
  return (16 + (c & 15)) << ((c >> 4) + 6);
}

/**
 * Encodes a byte count into the closest valid 1-byte count specifier.
 */
export function encodeS2kCount(count: number): number {
  if (count <= 1024) return 0;
  if (count >= 65011712) return 255;
  for (let c = 0; c <= 255; c++) {
    if (decodeS2kCount(c) >= count) return c;
  }
  return 255;
}

/**
 * Derives `keyLength` bytes using OpenPGP S2K.
 */
export function openpgpS2k(
  hashFn: (data: Uint8Array) => Uint8Array,
  passphrase: Uint8Array,
  keyLength: number,
  options: S2kOptions = {},
): Uint8Array {
  let type = options.type ?? (options.salt && options.salt.length >= 8 ? "iterated-salted" : "simple");
  const salt = options.salt ?? new Uint8Array(0);
  if (type !== "simple" && salt.length === 0) {
    type = "simple";
  }
  const count = options.count ?? 65536;

  const out = new Uint8Array(keyLength);
  let written = 0;
  let contextZeros = 0;

  while (written < keyLength) {
    let digest: Uint8Array;
    const prefix = new Uint8Array(contextZeros);

    if (type === "simple") {
      const buf = new Uint8Array(prefix.length + passphrase.length);
      buf.set(prefix);
      buf.set(passphrase, prefix.length);
      digest = hashFn(buf);
    } else if (type === "salted") {
      const s8 = salt.subarray(0, 8);
      const buf = new Uint8Array(prefix.length + 8 + passphrase.length);
      buf.set(prefix);
      buf.set(s8, prefix.length);
      buf.set(passphrase, prefix.length + 8);
      digest = hashFn(buf);
    } else {
      // Iterated and Salted
      const s8 = salt.subarray(0, 8);
      const combinedLen = s8.length + passphrase.length;
      const combined = new Uint8Array(combinedLen);
      combined.set(s8);
      combined.set(passphrase, 8);

      const actualCount = Math.max(count, combinedLen);
      const totalLen = prefix.length + actualCount;
      const fullBuf = new Uint8Array(totalLen);
      fullBuf.set(prefix, 0);

      let offset = prefix.length;
      let rem = actualCount;
      while (rem > 0) {
        const chunk = Math.min(rem, combinedLen);
        fullBuf.set(combined.subarray(0, chunk), offset);
        offset += chunk;
        rem -= chunk;
      }
      digest = hashFn(fullBuf);
    }

    const toCopy = Math.min(digest.length, keyLength - written);
    out.set(digest.subarray(0, toCopy), written);
    written += toCopy;
    contextZeros++;
  }

  return out;
}
