/**
 * Catena -- Memory-hard password scrambler (Password Hashing Competition Finalist).
 *
 * Implements Catena-Dragonfly / BRG (Bit-Reversal Graph) memory-hard mixing.
 */

export interface CatenaOptions {
  /** Memory cost parameter (default 10 -> 2^10 = 1024 state blocks). */
  lambda?: number;
  /** Time cost: iterations over the graph (default 1). */
  tCost?: number;
}

function bitReverse(v: number, bits: number): number {
  let r = 0;
  for (let i = 0; i < bits; i++) {
    r = (r << 1) | ((v >>> i) & 1);
  }
  return r;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/**
 * Catena password hash.
 */
export function catenaHash(
  hashFn: (data: Uint8Array) => Uint8Array,
  password: Uint8Array,
  salt: Uint8Array,
  options: CatenaOptions = {},
): Uint8Array {
  const lambda = Math.min(Math.max(options.lambda ?? 10, 1), 20);
  const tCost = Math.max(options.tCost ?? 1, 1);
  const n = 1 << lambda;

  // Initialize V[0]..V[n-1]
  const v: Uint8Array[] = new Array(n);
  v[0] = hashFn(concat(salt, password));
  for (let i = 1; i < n; i++) {
    v[i] = hashFn(concat(v[i - 1]!, new Uint8Array([i & 0xff])));
  }

  // Time iterations over Bit-Reversal Graph
  for (let t = 0; t < tCost; t++) {
    for (let i = 0; i < n; i++) {
      const prevIdx = (i - 1 + n) % n;
      const brIdx = bitReverse(i, lambda);
      v[i] = hashFn(concat(v[prevIdx]!, v[brIdx]!));
    }
  }

  return hashFn(concat(password, v[n - 1]!));
}
