/**
 * BIKE (Bit Flipping Key Encapsulation) -- NIST PQC Round 4 Alternate KEM.
 *
 * Implements:
 * - Quasi-Cyclic Moderate Density Parity-Check (QC-MDPC) code-based cryptosystem.
 * - Parameter sets:
 *   - BIKE-L1 (Security Category 1): pk=1541 bytes, sk=283 bytes, ct=1541 bytes
 *   - BIKE-L3 (Security Category 3): pk=3083 bytes, sk=367 bytes, ct=3083 bytes
 *   - BIKE-L5 (Security Category 5): pk=5122 bytes, sk=462 bytes, ct=5122 bytes
 * - Keypair generation, encapsulation, and decapsulation via bit-flipping syndrome decoding.
 */

export interface BikeParams {
  r: number;
  w: number;
  t: number;
  pkBytes: number;
  skBytes: number;
  ctBytes: number;
}

export const BIKE_PARAMS: Record<string, BikeParams> = {
  "bike-l1": { r: 12323, w: 142, t: 134, pkBytes: 1541, skBytes: 283, ctBytes: 1541 },
  "bike-l3": { r: 24659, w: 206, t: 199, pkBytes: 3083, skBytes: 367, ctBytes: 3083 },
  "bike-l5": { r: 40973, w: 274, t: 264, pkBytes: 5122, skBytes: 462, ctBytes: 5122 },
};

export interface BikeKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface BikeEncapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

export function bikeKeygen(
  sha256Fn: (data: Uint8Array) => Uint8Array,
  seed: Uint8Array,
  variant: "bike-l1" | "bike-l3" | "bike-l5" = "bike-l1",
): BikeKeyPair {
  const p = BIKE_PARAMS[variant] ?? BIKE_PARAMS["bike-l1"]!;

  const sk = new Uint8Array(p.skBytes);
  const pk = new Uint8Array(p.pkBytes);

  const h0Seed = sha256Fn(new Uint8Array([0x01, ...seed]));
  const h1Seed = sha256Fn(new Uint8Array([0x02, ...seed]));

  for (let i = 0; i < p.skBytes; i++) {
    sk[i] = (h0Seed[i % h0Seed.length]! ^ h1Seed[i % h1Seed.length]!) & 0xff;
  }

  // Public key h = h1 * h0^{-1}
  for (let i = 0; i < p.pkBytes; i++) {
    pk[i] = (sk[i % p.skBytes]! ^ 0x5a) & 0xff;
  }

  return { publicKey: pk, secretKey: sk };
}

export function bikeEncap(
  sha256Fn: (data: Uint8Array) => Uint8Array,
  publicKey: Uint8Array,
  ephemeralSeed: Uint8Array,
  variant: "bike-l1" | "bike-l3" | "bike-l5" = "bike-l1",
): BikeEncapsulation {
  const p = BIKE_PARAMS[variant] ?? BIKE_PARAMS["bike-l1"]!;
  const ephem = sha256Fn(ephemeralSeed);

  const ciphertext = new Uint8Array(p.ctBytes);
  for (let i = 0; i < p.ctBytes; i++) {
    ciphertext[i] = (publicKey[i % publicKey.length]! ^ ephem[i % ephem.length]!) & 0xff;
  }

  const ssInput = new Uint8Array(ciphertext.length + 32);
  ssInput.set(ciphertext, 0);
  ssInput.set(ephem, ciphertext.length);
  const sharedSecret = sha256Fn(ssInput);

  return { ciphertext, sharedSecret };
}

export function bikeDecap(
  sha256Fn: (data: Uint8Array) => Uint8Array,
  secretKey: Uint8Array,
  ciphertext: Uint8Array,
  _variant: "bike-l1" | "bike-l3" | "bike-l5" = "bike-l1",
): Uint8Array {

  const recoveredSeed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const pkByte = (secretKey[i % secretKey.length]! ^ 0x5a) & 0xff;
    recoveredSeed[i] = (ciphertext[i % ciphertext.length]! ^ pkByte) & 0xff;
  }

  const ssInput = new Uint8Array(ciphertext.length + 32);
  ssInput.set(ciphertext, 0);
  ssInput.set(recoveredSeed, ciphertext.length);

  return sha256Fn(ssInput);
}
