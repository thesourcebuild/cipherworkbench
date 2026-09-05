import { describe, expect, it } from "vitest";
import {
  ntruDecapsulate,
  ntruEncapsulate,
  ntruKeygen,
  paillierAdd,
  paillierDecrypt,
  paillierEncrypt,
  paillierKeygen,
  paillierMulScalar,
  sqisignKeygen,
  sqisignSign,
  sqisignVerify,
  SQISIGN_PK_BYTES,
  SQISIGN_SIG_BYTES,
  SQISIGN_SK_BYTES,
} from "@ocs/algos";

describe("Paillier Additively Homomorphic Cryptosystem", () => {
  // Use small primes for speedy unit tests: p = 61, q = 53
  const keypair = paillierKeygen(61n, 53n);
  const { publicKey, privateKey } = keypair;

  it("encrypts and decrypts correctly", () => {
    const message = 42n;
    const ciphertext = paillierEncrypt(message, publicKey, 5n);
    const decrypted = paillierDecrypt(ciphertext, privateKey);
    expect(decrypted).toBe(message);
  });

  it("performs homomorphic addition: E(m1) * E(m2) = E(m1 + m2)", () => {
    const m1 = 15n;
    const m2 = 27n;

    const c1 = paillierEncrypt(m1, publicKey, 3n);
    const c2 = paillierEncrypt(m2, publicKey, 7n);

    const cSum = paillierAdd(c1, c2, publicKey);
    const decryptedSum = paillierDecrypt(cSum, privateKey);

    expect(decryptedSum).toBe(m1 + m2);
  });

  it("performs homomorphic scalar multiplication: E(m)^k = E(k * m)", () => {
    const m = 12n;
    const scalar = 4n;

    const c = paillierEncrypt(m, publicKey, 11n);
    const cProduct = paillierMulScalar(c, scalar, publicKey);
    const decryptedProduct = paillierDecrypt(cProduct, privateKey);

    expect(decryptedProduct).toBe(m * scalar);
  });
});

describe("NTRU-HRSS-701 Lattice-based KEM", () => {
  const seed = new Uint8Array(32).fill(0x42);

  it("generates keypair with standard sizes", () => {
    const { publicKey, secretKey } = ntruKeygen(seed);
    expect(publicKey.length).toBe(1138);
    expect(secretKey.length).toBe(1450);
  });

  it("encapsulates and decapsulates shared secrets", () => {
    const { publicKey, secretKey } = ntruKeygen(seed);
    const ephemeralSeed = new Uint8Array(32).fill(0x99);

    const { ciphertext, sharedSecret: ssSender } = ntruEncapsulate(publicKey, ephemeralSeed);
    expect(ciphertext.length).toBe(1138);
    expect(ssSender.length).toBe(32);

    const ssReceiver = ntruDecapsulate(ciphertext, secretKey);
    expect(ssReceiver.length).toBe(32);

    // Both parties arrive at the identical 32-byte shared secret
    expect([...ssSender]).toEqual([...ssReceiver]);
  });
});

describe("SQISign (Short Quaternion and Isogeny Signatures)", () => {
  const seed = new Uint8Array(32).fill(0x77);

  it("generates keypair with compact sizes", () => {
    const { publicKey, secretKey } = sqisignKeygen(seed);
    expect(publicKey.length).toBe(SQISIGN_PK_BYTES); // 64 bytes
    expect(secretKey.length).toBe(SQISIGN_SK_BYTES); // 782 bytes
  });

  it("produces ultra-compact 177-byte signatures and verifies them", () => {
    const { publicKey, secretKey } = sqisignKeygen(seed);
    const message = new TextEncoder().encode("Post-quantum authentication statement");

    const signature = sqisignSign(secretKey, message);
    expect(signature.length).toBe(SQISIGN_SIG_BYTES); // 177 bytes

    const valid = sqisignVerify(publicKey, message, signature);
    expect(valid).toBe(true);

    // Reject corrupted signature
    const corruptedSig = new Uint8Array(signature);
    corruptedSig[0] = 0x00;
    expect(sqisignVerify(publicKey, message, corruptedSig)).toBe(false);
  });
});
