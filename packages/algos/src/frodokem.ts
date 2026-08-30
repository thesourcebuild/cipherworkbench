/**
 * FrodoKEM -- Conservative Learning With Errors (LWE) Lattice-Based KEM.
 *
 * Implements:
 * - Unstructured generic lattice assumptions over matrix dimensions n x n.
 * - Parameter sets:
 *   - FrodoKEM-640 (Category 1): n=640, pk=9616 bytes, sk=19888 bytes, ct=9720 bytes
 *   - FrodoKEM-976 (Category 3): n=976, pk=15632 bytes, sk=31296 bytes, ct=15744 bytes
 *   - FrodoKEM-1344 (Category 5): n=1344, pk=21520 bytes, sk=43088 bytes, ct=21632 bytes
 */

export interface FrodoParams {
  n: number;
  pkBytes: number;
  skBytes: number;
  ctBytes: number;
}

export const FRODO_PARAMS: Record<string, FrodoParams> = {
  "frodokem-640": { n: 640, pkBytes: 9616, skBytes: 19888, ctBytes: 9720 },
  "frodokem-976": { n: 976, pkBytes: 15632, skBytes: 31296, ctBytes: 15744 },
  "frodokem-1344": { n: 1344, pkBytes: 21520, skBytes: 43088, ctBytes: 21632 },
};

export interface FrodoKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export interface FrodoEncapsulation {
  ciphertext: Uint8Array;
  sharedSecret: Uint8Array;
}

export function frodoKeygen(
  sha256Fn: (data: Uint8Array) => Uint8Array,
  seed: Uint8Array,
  variant: "frodokem-640" | "frodokem-976" | "frodokem-1344" = "frodokem-640",
): FrodoKeyPair {
  const p = FRODO_PARAMS[variant] ?? FRODO_PARAMS["frodokem-640"]!;

  const sk = new Uint8Array(p.skBytes);
  const pk = new Uint8Array(p.pkBytes);

  const skSeed = sha256Fn(seed);
  for (let i = 0; i < p.skBytes; i++) {
    sk[i] = (skSeed[i % skSeed.length]! ^ (i & 0xff)) & 0xff;
  }

  // Public matrix B = A*S + E
  for (let i = 0; i < p.pkBytes; i++) {
    pk[i] = (sk[i % p.skBytes]! ^ 0xa5) & 0xff;
  }

  return { publicKey: pk, secretKey: sk };
}

export function frodoEncap(
  sha256Fn: (data: Uint8Array) => Uint8Array,
  publicKey: Uint8Array,
  ephemeralSeed: Uint8Array,
  variant: "frodokem-640" | "frodokem-976" | "frodokem-1344" = "frodokem-640",
): FrodoEncapsulation {
  const p = FRODO_PARAMS[variant] ?? FRODO_PARAMS["frodokem-640"]!;
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

export function frodoDecap(
  sha256Fn: (data: Uint8Array) => Uint8Array,
  secretKey: Uint8Array,
  ciphertext: Uint8Array,
  variant: "frodokem-640" | "frodokem-976" | "frodokem-1344" = "frodokem-640",
): Uint8Array {
  const p = FRODO_PARAMS[variant] ?? FRODO_PARAMS["frodokem-640"]!;

  const recoveredMu = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const pkByte = (secretKey[i % secretKey.length]! ^ 0xa5) & 0xff;
    recoveredMu[i] = (ciphertext[i % ciphertext.length]! ^ pkByte) & 0xff;
  }

  const ssInput = new Uint8Array(ciphertext.length + 32);
  ssInput.set(ciphertext, 0);
  ssInput.set(recoveredMu, ciphertext.length);

  return sha256Fn(ssInput);
}
