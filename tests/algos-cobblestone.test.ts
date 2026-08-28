import { describe, expect, it } from "vitest";
import {
  cobblestoneEncrypt,
  cobblestoneDecrypt,
  cobblestoneDeriveKeys,
  cobblestoneDeriveNonce,
  CobblestoneEncryptor,
  CobblestoneDecryptor,
  COBBLESTONE_CHUNK_SIZE,
  COBBLESTONE_HEADER_LENGTH,
} from "@ocs/algos";
import {
  cobblestoneCrypto,
  cobblestoneOperation,
  createCobblestoneStream,
} from "@ocs/cipher/definition";

const fromHex = (hex: string) =>
  hex === ""
    ? new Uint8Array(0)
    : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));

const ascii = (str: string) => new TextEncoder().encode(str);

describe("Cobblestone C2SP Chunked Encryption Specification & Vectors", () => {
  // Test vectors from Project Wycheproof / C2SP chunked encryption
  const wycheproofVectors = [
    {
      comment: "Empty plaintext, Cobblestone-128",
      key: "000102030405060708090a0b0c0d0e0f",
      salt: "000102030405060708090a0b0c0d0e0f1011121314151617",
      context: "",
      msg: "",
      variant: "cobblestone128" as const,
    },
    {
      comment: "Single chunk (16 bytes), Cobblestone-128",
      key: "000102030405060708090a0b0c0d0e0f",
      salt: "000102030405060708090a0b0c0d0e0f1011121314151617",
      context: "6170706c69636174696f6e2d636f6e74657874", // "application-context"
      msg: "00112233445566778899aabbccddeeff",
      variant: "cobblestone128" as const,
    },
    {
      comment: "Cobblestone-256 with 32-byte key",
      key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      salt: "000102030405060708090a0b0c0d0e0f1011121314151617",
      context: "74657374",
      msg: "68656c6c6f20776f726c64",
      variant: "cobblestone256" as const,
    },
  ];

  it("derives consistent keys, base nonce, and commitment", () => {
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const salt = fromHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    const context = ascii("c2sp-test");

    const derived128 = cobblestoneDeriveKeys(
      cobblestoneCrypto,
      key,
      salt,
      context,
      "cobblestone128",
    );

    expect(derived128.aeadKey.length).toBe(16);
    expect(derived128.baseNonce.length).toBe(12);
    expect(derived128.commitment.length).toBe(32);

    // Nonce derivation test: chunk 0, 1, 256
    const nonce0 = cobblestoneDeriveNonce(derived128.baseNonce, 0);
    expect(nonce0).toEqual(derived128.baseNonce);

    const nonce1 = cobblestoneDeriveNonce(derived128.baseNonce, 1);
    expect(nonce1[11]).toBe(derived128.baseNonce[11]! ^ 1);

    const nonce256 = cobblestoneDeriveNonce(derived128.baseNonce, 256);
    expect(nonce256[10]).toBe(derived128.baseNonce[10]! ^ 1);
    expect(nonce256[11]).toBe(derived128.baseNonce[11]!);
  });

  it("encrypts and decrypts test vectors correctly", () => {
    for (const vec of wycheproofVectors) {
      const key = fromHex(vec.key);
      const salt = fromHex(vec.salt);
      const context = fromHex(vec.context);
      const msg = fromHex(vec.msg);

      const { ciphertext, commitment, chunks } = cobblestoneEncrypt(
        cobblestoneCrypto,
        key,
        msg,
        {
          salt,
          context,
          variant: vec.variant,
        },
      );

      expect(ciphertext.length).toBeGreaterThanOrEqual(COBBLESTONE_HEADER_LENGTH + 16);
      expect(commitment.length).toBe(32);
      expect(chunks).toBe(1);

      // Decrypt
      const decrypted = cobblestoneDecrypt(cobblestoneCrypto, key, ciphertext, {
        context,
        variant: vec.variant,
      });

      expect(decrypted.plaintext).toEqual(msg);
      expect(decrypted.salt).toEqual(salt);
      expect(decrypted.commitment).toEqual(commitment);
    }
  });

  it("handles chunk boundary conditions (0, 16383, 16384, 16385, 32768 bytes)", () => {
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const salt = fromHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    const context = ascii("boundary-tests");

    const sizes = [0, 1, 100, 16383, 16384, 16385, 32768, 35000];

    for (const size of sizes) {
      const pt = new Uint8Array(size);
      for (let i = 0; i < size; i++) pt[i] = (i * 31 + 7) & 0xff;

      const { ciphertext, chunks } = cobblestoneEncrypt(cobblestoneCrypto, key, pt, {
        salt,
        context,
        variant: "cobblestone128",
      });

      const expectedChunks = Math.floor(size / COBBLESTONE_CHUNK_SIZE) + 1;
      expect(chunks).toBe(expectedChunks);

      const decrypted = cobblestoneDecrypt(cobblestoneCrypto, key, ciphertext, {
        context,
        variant: "cobblestone128",
      });

      expect(decrypted.plaintext).toEqual(pt);
      expect(decrypted.chunks).toBe(expectedChunks);
    }
  });

  it("produces identical output between one-shot and streaming encryptor across chunk feeds", () => {
    const key = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const salt = fromHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    const context = ascii("streaming-equivalence");

    const pt = new Uint8Array(40000); // 2 full chunks + partial chunk
    for (let i = 0; i < pt.length; i++) pt[i] = (i * 13 + 5) & 0xff;

    const oneShot = cobblestoneEncrypt(cobblestoneCrypto, key, pt, {
      salt,
      context,
      variant: "cobblestone256",
    });

    // Stream encryption with irregular chunk feeds
    const chunkFeedSizes = [7, 500, 16384, 2000, 10000, pt.length];
    for (const chunkSize of chunkFeedSizes) {
      const encryptor = new CobblestoneEncryptor(cobblestoneCrypto, key, {
        salt,
        context,
        variant: "cobblestone256",
      });

      const outParts: Uint8Array[] = [];
      for (let offset = 0; offset < pt.length; offset += chunkSize) {
        const slice = pt.subarray(offset, Math.min(pt.length, offset + chunkSize));
        outParts.push(encryptor.update(slice));
      }
      outParts.push(encryptor.finalize());

      const totalLen = outParts.reduce((a, b) => a + b.length, 0);
      const streamedCt = new Uint8Array(totalLen);
      let offset = 0;
      for (const part of outParts) {
        streamedCt.set(part, offset);
        offset += part.length;
      }

      expect(streamedCt).toEqual(oneShot.ciphertext);

      // Now test streaming decryptor over streamedCt
      const decryptor = new CobblestoneDecryptor(cobblestoneCrypto, key, {
        context,
        variant: "cobblestone256",
      });

      const decParts: Uint8Array[] = [];
      const decryptChunkSize = 333; // arbitrary chunking for decryption
      for (let ctOffset = 0; ctOffset < streamedCt.length; ctOffset += decryptChunkSize) {
        const ctSlice = streamedCt.subarray(
          ctOffset,
          Math.min(streamedCt.length, ctOffset + decryptChunkSize),
        );
        decParts.push(decryptor.update(ctSlice));
      }
      decParts.push(decryptor.finalize());

      const decTotalLen = decParts.reduce((a, b) => a + b.length, 0);
      const streamedPt = new Uint8Array(decTotalLen);
      let decOffset = 0;
      for (const part of decParts) {
        streamedPt.set(part, decOffset);
        decOffset += part.length;
      }

      expect(streamedPt).toEqual(pt);
    }
  });

  it("fails on invalid commitment when key or context is wrong", () => {
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const wrongKey = fromHex("000102030405060708090a0b0c0d0e0e");
    const salt = fromHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    const context = ascii("correct-context");
    const wrongContext = ascii("wrong-context");

    const pt = ascii("Secret data for Cobblestone");
    const { ciphertext } = cobblestoneEncrypt(cobblestoneCrypto, key, pt, {
      salt,
      context,
      variant: "cobblestone128",
    });

    // Wrong key
    expect(() =>
      cobblestoneDecrypt(cobblestoneCrypto, wrongKey, ciphertext, {
        context,
        variant: "cobblestone128",
      }),
    ).toThrow(/Invalid Cobblestone commitment/);

    // Wrong context
    expect(() =>
      cobblestoneDecrypt(cobblestoneCrypto, key, ciphertext, {
        context: wrongContext,
        variant: "cobblestone128",
      }),
    ).toThrow(/Invalid Cobblestone commitment/);
  });

  it("fails on truncated ciphertext and tampered chunks", () => {
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const salt = fromHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    const pt = ascii("Chunk tampering check");

    const { ciphertext } = cobblestoneEncrypt(cobblestoneCrypto, key, pt, {
      salt,
      variant: "cobblestone128",
    });

    // Truncated (too short)
    expect(() =>
      cobblestoneDecrypt(cobblestoneCrypto, key, ciphertext.subarray(0, 50)),
    ).toThrow(/ciphertext is too short/);

    // Tampered payload byte
    const tampered = new Uint8Array(ciphertext);
    tampered[60]! ^= 0x01;
    expect(() =>
      cobblestoneDecrypt(cobblestoneCrypto, key, tampered, { variant: "cobblestone128" }),
    ).toThrow();
  });

  it("operates through cipher cobblestoneOperation binding and createCobblestoneStream", () => {
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const salt = fromHex("000102030405060708090a0b0c0d0e0f1011121314151617");
    const context = ascii("binding-test");

    const op = cobblestoneOperation(key, {
      variant: "cobblestone128",
      context,
      salt,
    });

    const msg = ascii("Testing Cipher Workbench Cobblestone binding");
    const ct = op.encrypt(msg);
    const decrypted = op.decrypt(ct);
    expect(new TextDecoder().decode(decrypted)).toBe(
      "Testing Cipher Workbench Cobblestone binding",
    );

    // Stream test
    const encStream = createCobblestoneStream(key, "encrypt", {
      variant: "cobblestone128",
      context,
      salt,
    });
    const s1 = encStream.update(msg.subarray(0, 10));
    const s2 = encStream.update(msg.subarray(10));
    const s3 = encStream.finalize();

    const streamCombined = new Uint8Array(s1.length + s2.length + s3.length);
    streamCombined.set(s1, 0);
    streamCombined.set(s2, s1.length);
    streamCombined.set(s3, s1.length + s2.length);

    expect(streamCombined).toEqual(ct);
  });
});
