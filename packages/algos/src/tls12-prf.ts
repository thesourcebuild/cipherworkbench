/**
 * TLS 1.2 Pseudo-Random Function (PRF) per RFC 5246 §5.
 *
 * Uses the P_hash data expansion function over HMAC-SHA256 (or HMAC-SHA384/512).
 */

export interface Tls12PrfOptions {
  label?: string | Uint8Array;
  seed?: Uint8Array;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrays) {
    out.set(a, pos);
    pos += a.length;
  }
  return out;
}

/**
 * TLS 1.2 PRF / P_hash key expansion function.
 */
export function tls12Prf(
  hmacFn: (key: Uint8Array, message: Uint8Array) => Uint8Array,
  secret: Uint8Array,
  length: number,
  options: Tls12PrfOptions = {},
): Uint8Array {
  const labelBytes =
    typeof options.label === "string"
      ? new TextEncoder().encode(options.label)
      : (options.label ?? new Uint8Array(0));
  const seedBytes = options.seed ?? new Uint8Array(0);
  const seed = concat(labelBytes, seedBytes);

  const out = new Uint8Array(length);
  let written = 0;
  let aCurrent = hmacFn(secret, seed); // A(1) = HMAC(secret, seed)

  while (written < length) {
    const block = hmacFn(secret, concat(aCurrent, seed));
    const toCopy = Math.min(block.length, length - written);
    out.set(block.subarray(0, toCopy), written);
    written += toCopy;
    aCurrent = hmacFn(secret, aCurrent); // A(i) = HMAC(secret, A(i-1))
  }

  return out;
}
