/**
 * Paillier Cryptosystem (Pascal Paillier, 1999).
 *
 * An additively homomorphic public-key cryptosystem based on the Decisional
 * Composite Residuosity Assumption (DCRA).
 *
 * Supported operations:
 * - Keypair generation
 * - Encryption: c = (1 + m*n) * r^n mod n^2
 * - Decryption: m = ((c^lambda mod n^2 - 1) / n) * mu mod n
 * - Homomorphic Addition: E(m1) * E(m2) mod n^2 = E(m1 + m2 mod n)
 * - Homomorphic Scalar Multiplication: E(m)^k mod n^2 = E(k * m mod n)
 */

export interface PaillierPublicKey {
  n: bigint;
  n2: bigint; // n^2
  g: bigint; // n + 1
}

export interface PaillierPrivateKey {
  lambda: bigint; // lcm(p - 1, q - 1)
  mu: bigint; // lambda^{-1} mod n
  publicKey: PaillierPublicKey;
}

export interface PaillierKeyPair {
  publicKey: PaillierPublicKey;
  privateKey: PaillierPrivateKey;
}

function gcd(a: bigint, b: bigint): bigint {
  while (b !== 0n) {
    const t = b;
    b = a % b;
    a = t;
  }
  return a < 0n ? -a : a;
}

function lcm(a: bigint, b: bigint): bigint {
  if (a === 0n || b === 0n) return 0n;
  return (a * b) / gcd(a, b);
}

function egcd(a: bigint, b: bigint): { g: bigint; x: bigint; y: bigint } {
  if (b === 0n) return { g: a, x: 1n, y: 0n };
  const { g, x: x1, y: y1 } = egcd(b, a % b);
  return { g, x: y1, y: x1 - (a / b) * y1 };
}

function modInverse(a: bigint, m: bigint): bigint {
  const { g, x } = egcd(((a % m) + m) % m, m);
  if (g !== 1n) throw new Error("Inverse does not exist");
  return ((x % m) + m) % m;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let res = 1n;
  let b = ((base % mod) + mod) % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) res = (res * b) % mod;
    e >>= 1n;
    b = (b * b) % mod;
  }
  return res;
}

/**
 * Standard test primes for deterministic keypair construction.
 */
export const PAILLIER_DEFAULT_P = 0xee56a646c2eb4de72b43b6ef16e5cd6786cbb3d8c27dcad69a84a62176b64d1fn;
export const PAILLIER_DEFAULT_Q = 0xf5529f7cfb8e0b6863ecad124c13a693c1bb02db7c27633e9b7201b17b6a12b9n;

/**
 * Creates a Paillier keypair from two distinct prime integers.
 */
export function paillierKeygen(p: bigint = PAILLIER_DEFAULT_P, q: bigint = PAILLIER_DEFAULT_Q): PaillierKeyPair {
  if (p === q) throw new Error("p and q must be distinct primes");

  const n = p * q;
  const n2 = n * n;
  const g = n + 1n;
  const lambda = lcm(p - 1n, q - 1n);
  const mu = modInverse(lambda, n);

  const publicKey: PaillierPublicKey = { n, n2, g };
  const privateKey: PaillierPrivateKey = { lambda, mu, publicKey };

  return { publicKey, privateKey };
}

/**
 * Encrypts an integer message m in [0, n) using the recipient's public key.
 * If r is omitted, a deterministic non-zero coprime blinding factor is used.
 */
export function paillierEncrypt(m: bigint, pk: PaillierPublicKey, r?: bigint): bigint {
  const n = pk.n;
  const n2 = pk.n2;

  if (m < 0n || m >= n) throw new Error(`Message must be in range [0, n)`);

  const randR = r ?? 2n;
  if (gcd(randR, n) !== 1n) throw new Error("Blinding factor r must be coprime to n");

  // c = (1 + m*n) * r^n mod n^2
  const gm = (1n + m * n) % n2;
  const rn = modPow(randR, n, n2);
  return (gm * rn) % n2;
}

/**
 * Decrypts a Paillier ciphertext using the private key.
 */
export function paillierDecrypt(c: bigint, sk: PaillierPrivateKey): bigint {
  const n = sk.publicKey.n;
  const n2 = sk.publicKey.n2;

  // u = c^lambda mod n^2
  const u = modPow(c, sk.lambda, n2);
  // L(u) = (u - 1) / n
  const l_u = (u - 1n) / n;
  // m = (L(u) * mu) mod n
  return (l_u * sk.mu) % n;
}

/**
 * Homomorphically adds two ciphertexts: E(m1) * E(m2) mod n^2 = E(m1 + m2 mod n).
 */
export function paillierAdd(c1: bigint, c2: bigint, pk: PaillierPublicKey): bigint {
  return (c1 * c2) % pk.n2;
}

/**
 * Homomorphically multiplies an encrypted ciphertext by a plaintext scalar:
 * E(m)^k mod n^2 = E(k * m mod n).
 */
export function paillierMulScalar(c: bigint, k: bigint, pk: PaillierPublicKey): bigint {
  return modPow(c, k, pk.n2);
}
