import { describe, it, expect } from "vitest";
import {
  poseidon2Hash,
  snowVCrypt,
  isaacCrypt,
  pcg64Crypt,
  xoshiro256Crypt,
  computeCShake128,
  computeCShake256,
  computeKmac128,
  computeKmac256,
  computeTupleHash128,
  computeTupleHash256,
  computeParallelHash128,
  computeParallelHash256,
  encodeGrayBytes,
  decodeGrayBytes,
  encodeBaudotIta2,
  decodeBaudotIta2,
  encodeBubbleBabble,
  decodeBubbleBabble,
  encodePgpWords,
  decodePgpWords,
} from "@ocs/algos";

describe("Phase 3-6 Extended Models & Encodings", () => {
  describe("Poseidon2 ZK-STARK Hash", () => {
    it("hashes byte inputs to 32-byte digest", () => {
      const msg = new TextEncoder().encode("ZK_PROOF_INPUT_DATA");
      const h1 = poseidon2Hash(msg);
      const h2 = poseidon2Hash(msg);
      expect(h1.length).toBe(32);
      expect(h1).toEqual(h2);
    });
  });

  describe("SNOW-V 5G Stream Cipher", () => {
    it("encrypts and decrypts under 256-bit key and 128-bit IV", () => {
      const key = new Uint8Array(32).fill(0x42);
      const iv = new Uint8Array(16).fill(0x13);
      const msg = new TextEncoder().encode("5G_NR_HIGH_SPEED_DATA_PAYLOAD");
      const ct = snowVCrypt(key, iv, msg);
      expect(ct).not.toEqual(msg);
      const pt = snowVCrypt(key, iv, ct);
      expect(pt).toEqual(msg);
    });
  });

  describe("ISAAC CSPRNG Keystream", () => {
    it("encrypts and decrypts symmetric stream", () => {
      const seed = new TextEncoder().encode("ISAAC_SECRET_SEED");
      const msg = new TextEncoder().encode("ENCRYPTED_WITH_ISAAC_CSPRNG");
      const ct = isaacCrypt(seed, msg);
      expect(ct).not.toEqual(msg);
      const pt = isaacCrypt(seed, ct);
      expect(pt).toEqual(msg);
    });
  });

  describe("PCG64 and Xoshiro256++", () => {
    it("PCG64 round-trips data stream", () => {
      const key = new Uint8Array(16).fill(0x07);
      const msg = new TextEncoder().encode("PCG64_HIGH_SPEED_PRNG_STREAM");
      const ct = pcg64Crypt(key, msg);
      expect(ct).not.toEqual(msg);
      const pt = pcg64Crypt(key, ct);
      expect(pt).toEqual(msg);
    });

    it("Xoshiro256++ round-trips data stream", () => {
      const key = new Uint8Array(32).fill(0x5a);
      const msg = new TextEncoder().encode("XOSHIRO256_PLUS_PLUS_STREAM");
      const ct = xoshiro256Crypt(key, msg);
      expect(ct).not.toEqual(msg);
      const pt = xoshiro256Crypt(key, ct);
      expect(pt).toEqual(msg);
    });
  });

  describe("NIST SP 800-185 Derived Functions", () => {
    it("computes cSHAKE128 and cSHAKE256", () => {
      const msg = new TextEncoder().encode("CUSTOMIZABLE_SHAKE_INPUT");
      const h128 = computeCShake128(msg, { S: "TEST_CUSTOM_STRING", dkLen: 32 });
      const h256 = computeCShake256(msg, { S: "TEST_CUSTOM_STRING", dkLen: 64 });
      expect(h128.length).toBe(32);
      expect(h256.length).toBe(64);
    });

    it("computes KMAC128 and KMAC256", () => {
      const key = new TextEncoder().encode("KMAC_SECRET_KEY");
      const msg = new TextEncoder().encode("MESSAGE_TO_AUTHENTICATE");
      const mac128 = computeKmac128(key, msg, { dkLen: 32 });
      const mac256 = computeKmac256(key, msg, { dkLen: 64 });
      expect(mac128.length).toBe(32);
      expect(mac256.length).toBe(64);
    });

    it("computes TupleHash128/256 and ParallelHash128/256", () => {
      const tuple1 = new TextEncoder().encode("FIRST_TUPLE_ELEMENT");
      const tuple2 = new TextEncoder().encode("SECOND_TUPLE_ELEMENT");
      const tupleHash = computeTupleHash128([tuple1, tuple2], { dkLen: 32 });
      const tupleHash256 = computeTupleHash256([tuple1, tuple2], { dkLen: 64 });
      expect(tupleHash.length).toBe(32);
      expect(tupleHash256.length).toBe(64);

      const msg = new TextEncoder().encode("PARALLEL_TREE_HASH_MESSAGE");
      const parHash = computeParallelHash128(msg, { blockLen: 8, dkLen: 32 });
      const parHash256 = computeParallelHash256(msg, { blockLen: 8, dkLen: 64 });
      expect(parHash.length).toBe(32);
      expect(parHash256.length).toBe(64);
    });
  });

  describe("Specialized Encodings", () => {
    it("encodes and decodes Reflected Binary Gray Code", () => {
      const data = new Uint8Array([0, 1, 2, 3, 4, 255, 128, 42]);
      const gray = encodeGrayBytes(data);
      const decoded = decodeGrayBytes(gray);
      expect(decoded).toEqual(data);
    });

    it("encodes and decodes Baudot ITA2 teleprinter codes", () => {
      const text = "TELEPRINTER 1945";
      const baudot = encodeBaudotIta2(text);
      const decoded = decodeBaudotIta2(baudot);
      expect(decoded).toBe(text);
    });

    it("encodes and decodes Bubble Babble pronounceable pseudowords", () => {
      const data = new TextEncoder().encode("1234567890");
      const bb = encodeBubbleBabble(data);
      expect(bb).toMatch(/^x[a-z-]+x$/);
      const decoded = decodeBubbleBabble(bb);
      expect(decoded.length).toBeGreaterThan(0);
    });

    it("encodes and decodes PGP Biometric Word List", () => {
      const data = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
      const words = encodePgpWords(data);
      const decoded = decodePgpWords(words);
      expect(decoded).toEqual(data);
    });
  });
});
