/**
 * NIST SP 800-108 Recommendation for Key Derivation Using Pseudorandom Functions.
 * Implements KDF in Counter Mode using HMAC-SHA256.
 * K(i) = PRF(K_in, [i]_2 || Label || 0x00 || Context || [L]_2)
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

export interface Sp800108Options {
  key: Uint8Array;
  label?: string | Uint8Array;
  context?: string | Uint8Array;
  length: number; // Output length L in bytes
}

export function sp800108KdfCounter(options: Sp800108Options): Uint8Array {
  const label = typeof options.label === "string" ? new TextEncoder().encode(options.label) : (options.label ?? new Uint8Array(0));
  const context = typeof options.context === "string" ? new TextEncoder().encode(options.context) : (options.context ?? new Uint8Array(0));

  const L_bits = options.length * 8;
  const h = 32; // HMAC-SHA256 output length
  const n = Math.ceil(options.length / h);

  const out = new Uint8Array(options.length);
  let generated = 0;

  for (let i = 1; i <= n; i++) {
    // [i]_2 (32-bit big endian) || Label || 0x00 || Context || [L]_2 (32-bit big endian)
    const data = new Uint8Array(4 + label.length + 1 + context.length + 4);
    let o = 0;

    data[o++] = (i >>> 24) & 0xff;
    data[o++] = (i >>> 16) & 0xff;
    data[o++] = (i >>> 8) & 0xff;
    data[o++] = i & 0xff;

    data.set(label, o);
    o += label.length;

    data[o++] = 0x00;

    data.set(context, o);
    o += context.length;

    data[o++] = (L_bits >>> 24) & 0xff;
    data[o++] = (L_bits >>> 16) & 0xff;
    data[o++] = (L_bits >>> 8) & 0xff;
    data[o++] = L_bits & 0xff;

    const block = hmac(sha256, options.key, data);
    const toCopy = Math.min(h, options.length - generated);
    out.set(block.subarray(0, toCopy), generated);
    generated += toCopy;
  }

  return out;
}
