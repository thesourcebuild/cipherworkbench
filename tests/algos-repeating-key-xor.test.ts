import { describe, expect, it } from "vitest";
import { RepeatingKeyXorStream, repeatingKeyXor } from "@ocs/algos/repeating-key-xor";

const ascii = (value: string): Uint8Array => new TextEncoder().encode(value);
const hex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));

const PLAINTEXT = ascii(
  "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal",
);
const KEY = ascii("ICE");
const CRYPTOPALS_CIPHERTEXT = hex(
  "0b3637272a2b2e63622c2e69692a2369" +
    "3a2a3c6324202d623d63343c2a262263" +
    "24272765272a282b2f20430a652e2c65" +
    "2a3124333a653e2b2027630c692b2028" +
    "3165286326302e27282f",
);

describe("repeating-key XOR", () => {
  it("matches the Cryptopals Set 1 Challenge 5 reference vector", () => {
    expect(repeatingKeyXor(PLAINTEXT, KEY)).toEqual(CRYPTOPALS_CIPHERTEXT);
  });

  it("uses the same operation for encryption and decryption", () => {
    expect(repeatingKeyXor(CRYPTOPALS_CIPHERTEXT, KEY)).toEqual(PLAINTEXT);
  });

  it("preserves the key offset across arbitrary chunk boundaries", () => {
    for (const sizes of [[1], [2, 3], [4, 1, 7], [16, 5, 2, 31]]) {
      const stream = new RepeatingKeyXorStream(KEY);
      const output = new Uint8Array(PLAINTEXT.length);
      let inputAt = 0;
      let sizeAt = 0;
      expect(stream.process(new Uint8Array(0))).toHaveLength(0);
      while (inputAt < PLAINTEXT.length) {
        const length = Math.min(sizes[sizeAt++ % sizes.length]!, PLAINTEXT.length - inputAt);
        output.set(stream.process(PLAINTEXT.subarray(inputAt, inputAt + length)), inputAt);
        inputAt += length;
      }
      expect(output, sizes.join(",")).toEqual(CRYPTOPALS_CIPHERTEXT);
    }
  });

  it("rejects an empty key in one-shot and streaming forms", () => {
    expect(() => repeatingKeyXor(PLAINTEXT, new Uint8Array(0))).toThrow(/non-empty key/i);
    expect(() => new RepeatingKeyXorStream(new Uint8Array(0))).toThrow(/non-empty key/i);
  });
});
