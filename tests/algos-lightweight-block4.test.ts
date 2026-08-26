import { describe, expect, it } from "vitest";

import { createLilliput, createRoadRunneR, roadrunnerKeyLength } from "../packages/algos/src/index";
import { LIGHTWEIGHT_BLOCK4_VECTORS } from "./lightweight-block4-vectors";

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (text: string): Uint8Array =>
  Uint8Array.from((text.match(/../g) ?? []).map((p) => parseInt(p, 16)));

/**
 * RoadRunneR and Lilliput-80. Neither has an oracle: OpenSSL has neither, no dependency here
 * implements either, and Bouncy Castle carries neither an engine nor a vector for them. What stands
 * behind them is the designers' own published vectors, and **every case is decrypted from the
 * published ciphertext rather than re-encrypted from our own output** -- which is what catches an
 * inverse that is self-consistent and wrong, the failure mode that has bitten Kalyna, BelT, IDEA and
 * MISTY1 in this repo already.
 */
const ROADRUNNER_VECTORS = LIGHTWEIGHT_BLOCK4_VECTORS.filter((v) => v.variant !== undefined);
const LILLIPUT = LIGHTWEIGHT_BLOCK4_VECTORS.find((v) => v.tool === "lilliput")!;

describe("RoadRunneR", () => {
  it("covers both key sizes twice over", () => {
    expect(ROADRUNNER_VECTORS).toHaveLength(4);
    expect(new Set(ROADRUNNER_VECTORS.map((v) => v.variant)).size).toBe(2);
  });

  it.each(ROADRUNNER_VECTORS)(
    "RoadRunneR-$variant encrypts $plaintext under $key",
    ({ variant, key, plaintext, ciphertext }) => {
      const cipher = createRoadRunneR(unhex(key), variant!);
      const out = new Uint8Array(8);
      cipher.encryptBlock(unhex(plaintext), out);
      expect(hex(out)).toBe(ciphertext);
    },
  );

  it.each(ROADRUNNER_VECTORS)(
    "RoadRunneR-$variant decrypts the published $ciphertext",
    ({ variant, key, plaintext, ciphertext }) => {
      const cipher = createRoadRunneR(unhex(key), variant!);
      const out = new Uint8Array(8);
      cipher.decryptBlock(unhex(ciphertext), out);
      expect(hex(out)).toBe(plaintext);
    },
  );

  /**
   * The two key sizes are not one cipher with a shorter key, and this is the assertion that says so.
   *
   * At 128 bits each layer takes an aligned 32-bit word; at 80 bits the cursor advances one byte at a
   * time modulo ten, so a layer's material straddles the wrap. Padding the 80-bit key to sixteen bytes
   * and running the wider variant is the natural shortcut, and it gives a different answer.
   */
  it("does not treat an 80-bit key as a padded 128-bit one", () => {
    const short = unhex("0123456789abcdef0123");
    const padded = new Uint8Array(16);
    padded.set(short);
    const a = new Uint8Array(8);
    const b = new Uint8Array(8);
    createRoadRunneR(short, "64-80").encryptBlock(unhex("fedcba9876543210"), a);
    createRoadRunneR(padded, "64-128").encryptBlock(unhex("fedcba9876543210"), b);
    expect(hex(a)).not.toBe(hex(b));
  });

  it("round-trips every byte value at both key sizes", () => {
    for (const variant of ["64-80", "64-128"] as const) {
      const key = new Uint8Array(roadrunnerKeyLength(variant));
      for (let i = 0; i < key.length; i++) key[i] = (i * 37 + 11) & 0xff;
      const cipher = createRoadRunneR(key, variant);
      for (let value = 0; value < 256; value += 17) {
        const block = new Uint8Array(8).fill(value);
        const enciphered = new Uint8Array(8);
        const back = new Uint8Array(8);
        cipher.encryptBlock(block, enciphered);
        cipher.decryptBlock(enciphered, back);
        expect(hex(back), `${variant} at ${value}`).toBe(hex(block));
      }
    }
  });

  it("refuses a key of the other variant's length", () => {
    expect(() => createRoadRunneR(new Uint8Array(16), "64-80")).toThrow(/exactly 10 bytes/);
    expect(() => createRoadRunneR(new Uint8Array(10), "64-128")).toThrow(/exactly 16 bytes/);
  });

  it("reports each variant's key length", () => {
    expect(roadrunnerKeyLength("64-80")).toBe(10);
    expect(roadrunnerKeyLength("64-128")).toBe(16);
  });
});

describe("Lilliput-80", () => {
  const { key: KEY, plaintext: PLAINTEXT, ciphertext: CIPHERTEXT } = LILLIPUT;

  it("encrypts the designers' vector", () => {
    const out = new Uint8Array(8);
    createLilliput(unhex(KEY)).encryptBlock(unhex(PLAINTEXT), out);
    expect(hex(out)).toBe(CIPHERTEXT);
  });

  it("decrypts the published ciphertext", () => {
    const out = new Uint8Array(8);
    createLilliput(unhex(KEY)).decryptBlock(unhex(CIPHERTEXT), out);
    expect(hex(out)).toBe(PLAINTEXT);
  });

  it("round-trips across a spread of blocks", () => {
    const cipher = createLilliput(unhex(KEY));
    for (let value = 0; value < 256; value += 13) {
      const block = new Uint8Array(8);
      for (let i = 0; i < 8; i++) block[i] = (value + i * 31) & 0xff;
      const enciphered = new Uint8Array(8);
      const back = new Uint8Array(8);
      cipher.encryptBlock(block, enciphered);
      cipher.decryptBlock(enciphered, back);
      expect(hex(back), `at ${value}`).toBe(hex(block));
    }
  });

  /**
   * The final round has no permutation layer.
   *
   * That is the detail a reader would "fix" -- thirty rounds of Feistel-then-permute reads more
   * regular than twenty-nine plus a bare one. Applying the permutation thirty times still inverts
   * perfectly, so only a published vector catches it; this asserts the vector rather than the shape,
   * which is the honest way round.
   */
  it("depends on every key nibble", () => {
    const base = unhex(KEY);
    const reference = new Uint8Array(8);
    createLilliput(base).encryptBlock(unhex(PLAINTEXT), reference);
    for (let byte = 0; byte < base.length; byte++) {
      for (const bit of [0x01, 0x10]) {
        const altered = Uint8Array.from(base);
        altered[byte] = altered[byte]! ^ bit;
        const out = new Uint8Array(8);
        createLilliput(altered).encryptBlock(unhex(PLAINTEXT), out);
        expect(hex(out), `key byte ${byte} bit ${bit}`).not.toBe(hex(reference));
      }
    }
  });

  it("refuses a key that is not 10 bytes", () => {
    expect(() => createLilliput(new Uint8Array(16))).toThrow(/exactly 10 bytes/);
    expect(() => createLilliput(new Uint8Array(9))).toThrow(/exactly 10 bytes/);
  });
});
