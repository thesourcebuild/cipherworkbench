import { describe, it, expect } from "vitest";
import {
  falconKeygen,
  falconSign,
  falconVerify,
  mcelieceEncap,
  mcelieceDecap,
  hqcEncap,
  hqcDecap,
  lmsKeygen,
  lmsSign,
  lmsVerify,
} from "@ocs/algos";
import { sha256 } from "@noble/hashes/sha2.js";

const hashFn = (d: Uint8Array) => sha256(d);

describe("Post-Quantum Cryptography & Stateful Signatures", () => {
  describe("FN-DSA / Falcon", () => {
    it("generates keypair, signs message, and verifies signature", () => {
      const seed = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
      const kp = falconKeygen(hashFn, seed, 512);
      expect(kp.publicKey.length).toBe(1024);

      const msg = new TextEncoder().encode("Falcon Post-Quantum Signature Test");
      const nonce = new Uint8Array(40).fill(7);
      const sig = falconSign(hashFn, kp.privateKey, msg, nonce, 512);

      const valid = falconVerify(hashFn, kp.publicKey, msg, sig, 512);
      expect(valid).toBe(true);

      // Verify tampered message fails
      const tamperedMsg = new TextEncoder().encode("Tampered Message");
      const invalid = falconVerify(hashFn, kp.publicKey, tamperedMsg, sig, 512);
      expect(invalid).toBe(false);
    });
  });

  describe("Classic McEliece", () => {
    it("encapsulates and decapsulates shared secret", () => {
      const pk = new Uint8Array(200).fill(0x5a);
      const sk = new Uint8Array(32).fill(0x42);
      const ephemSeed = new Uint8Array([1, 3, 3, 7]);

      const encap = mcelieceEncap(hashFn, pk, ephemSeed, "348864");
      expect(encap.ciphertext.length).toBe(96);
      expect(encap.sharedSecret.length).toBe(32);

      const decapSecret = mcelieceDecap(hashFn, sk, encap.ciphertext, "348864");
      expect(decapSecret.length).toBe(32);
    });
  });

  describe("HQC (Hamming Quasi-Cyclic)", () => {
    it("encapsulates and decapsulates shared secret", () => {
      const pk = new Uint8Array(4485).fill(0x12);
      const sk = new Uint8Array(64).fill(0x34);
      const seedMessage = new Uint8Array(32).fill(0x99);

      const encap = hqcEncap(hashFn, pk, seedMessage, "128");
      expect(encap.ciphertext.length).toBe(4484);
      expect(encap.sharedSecret.length).toBe(32);

      const decapSecret = hqcDecap(hashFn, sk, encap.ciphertext, "128");
      expect(decapSecret.length).toBe(32);
    });
  });

  describe("Stateful Hash Signatures (LMS)", () => {
    it("generates Merkle tree keypair, signs leaf, and verifies authentication path", () => {
      const seed = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2, 1]);
      const kp = lmsKeygen(hashFn, seed, 4); // 2^4 = 16 leaves

      const msg = new TextEncoder().encode("LMS Stateful Hash Signature RFC 8554");
      const sig = lmsSign(hashFn, kp, msg, 3); // Sign with leaf 3

      const valid = lmsVerify(hashFn, kp.root, kp.iIdentifier, msg, sig);
      expect(valid).toBe(true);

      // Verify tampered message fails
      const tamperedMsg = new TextEncoder().encode("Forged LMS Message");
      const invalid = lmsVerify(hashFn, kp.root, kp.iIdentifier, tamperedMsg, sig);
      expect(invalid).toBe(false);
    });
  });
});
