/**
 * Balloon Hashing -- Stanford's provably memory-hard password hashing algorithm (RFC 9383).
 *
 * Balloon is designed to be provably secure against space-time tradeoffs and cache attacks.
 * It operates over a buffer of `s_cost` blocks, updating blocks sequentially and XORing / hashing
 * pseudorandom dependencies determined by a cryptographic hash function (default SHA-256 or SHA-512).
 */

export interface BalloonOptions {
  /** Space cost: number of blocks in memory buffer (default 16, must be >= 1). */
  sCost?: number;
  /** Time cost: number of rounds / passes through memory (default 3, must be >= 1). */
  tCost?: number;
  /** Delta: number of pseudo-random dependencies per step (default 3, must be >= 1). */
  delta?: number;
}

function u64Le(bytes: Uint8Array, offset: number): bigint {
  let val = 0n;
  for (let i = 0; i < 8 && offset + i < bytes.length; i++) {
    val |= BigInt(bytes[offset + i]!) << BigInt(8 * i);
  }
  return val;
}

function concat(arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((acc, a) => acc + a.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const a of arrays) {
    out.set(a, pos);
    pos += a.length;
  }
  return out;
}

function u64Bytes(val: bigint): Uint8Array {
  const b = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    b[i] = Number((val >> BigInt(8 * i)) & 0xffn);
  }
  return b;
}

/**
 * Balloon hash execution per RFC 9383.
 */
export function balloonHash(
  hashFn: (data: Uint8Array) => Uint8Array,
  password: Uint8Array,
  salt: Uint8Array,
  options: BalloonOptions = {},
): Uint8Array {
  const sCost = options.sCost ?? 16;
  const tCost = options.tCost ?? 3;
  const delta = options.delta ?? 3;

  if (sCost < 1) throw new Error("Balloon sCost (space cost) must be >= 1.");
  if (tCost < 1) throw new Error("Balloon tCost (time cost) must be >= 1.");
  if (delta < 1) throw new Error("Balloon delta must be >= 1.");

  let cnt = 1n;
  const buf: Uint8Array[] = new Array(sCost);

  // Step 1: Initialize buffer
  buf[0] = hashFn(concat([u64Bytes(cnt++), password, salt]));
  for (let m = 1; m < sCost; m++) {
    buf[m] = hashFn(concat([u64Bytes(cnt++), buf[m - 1]!]));
  }

  // Step 2: Time loop & mixing
  for (let t = 0; t < tCost; t++) {
    for (let m = 0; m < sCost; m++) {
      const prevIdx = (m - 1 + sCost) % sCost;
      const prev = buf[prevIdx]!;
      buf[m] = hashFn(concat([u64Bytes(cnt++), prev, buf[m]!]));

      for (let i = 0; i < delta; i++) {
        const idxBlock = hashFn(
          concat([u64Bytes(cnt++), salt, u64Bytes(BigInt(t)), u64Bytes(BigInt(m)), u64Bytes(BigInt(i)), prev]),
        );
        const randVal = u64Le(idxBlock, 0);
        const other = Number(randVal % BigInt(sCost));
        buf[m] = hashFn(concat([u64Bytes(cnt++), buf[m]!, buf[other]!]));
      }
    }
  }

  return buf[sCost - 1]!;
}
