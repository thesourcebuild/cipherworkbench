/**
 * Skein, against the 1.3 golden KAT.
 *
 * 29 vectors across all three state sizes and seven output lengths -- see `tests/skein-vectors.ts` for
 * their provenance. No oracle exists here for Skein either, so the breadth of output lengths is doing
 * the work: the length is mixed into the configuration block, so each one exercises a different
 * initial chaining value on top of the same message path.
 */
import { describe, expect, it } from "vitest";
import { createSkein, skein, skeinMac, SKEIN_STATE_SIZES } from "@ocs/algos";
import { SKEIN_VECTORS } from "./skein-vectors";
import { SKEIN_MAC_VECTORS } from "./skein-mac-vectors";

const fromHex = (hex: string) =>
  hex === ""
    ? new Uint8Array(0)
    : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const ascii = (text: string) => new TextEncoder().encode(text);

describe("Skein -- the 1.3 golden KAT", () => {
  it("matches every vector", () => {
    for (const { stateBits, outputBits, message, hex } of SKEIN_VECTORS) {
      const label = `Skein-${stateBits}-${outputBits} over ${message.length / 2} bytes`;
      expect(toHex(skein(fromHex(message), stateBits / 8, outputBits / 8)), label).toBe(hex);
    }
  });

  it("covers all three state sizes and more than one output length for each", () => {
    // The fixture is generated, so what it covers is asserted rather than assumed.
    for (const stateBits of [256, 512, 1024]) {
      const forState = SKEIN_VECTORS.filter((v) => v.stateBits === stateBits);
      expect(forState.length, `${stateBits}-bit state`).toBeGreaterThan(3);
      expect(new Set(forState.map((v) => v.outputBits)).size, `${stateBits} lengths`).toBeGreaterThan(
        1,
      );
    }
  });

  it("is parameterized by output length, not truncated", () => {
    /**
     * The property that decides how the hash family files Skein, asserted directly: the output length
     * goes into the configuration block, so Skein-512-256 is an unrelated value rather than the first
     * half of Skein-512-512. Getting this wrong is invisible in a single-length test.
     */
    const message = new TextEncoder().encode("output length is part of the function");
    const short = skein(message, 64, 32);
    const long = skein(message, 64, 64);
    expect(toHex(short)).not.toBe(toHex(long.subarray(0, 32)));

    // Two state sizes at one output length are also unrelated.
    expect(toHex(skein(message, 32, 32))).not.toBe(toHex(short));
  });

  it("streams to the same digest as one shot, at every split around the block size", () => {
    /**
     * Skein must keep a whole block buffered, because UBI's "final" flag is only knowable once the
     * next byte arrives. The splits that catch a wrong flush are the ones landing exactly on the
     * block size, which is why 32, 64 and 128 are all in the list.
     */
    const message = new Uint8Array(400);
    for (let i = 0; i < message.length; i++) message[i] = (i * 29 + 7) & 0xff;

    for (const stateBytes of SKEIN_STATE_SIZES) {
      const expected = toHex(skein(message, stateBytes, stateBytes));
      for (const size of [1, 5, 31, 32, 63, 64, 127, 128, 399]) {
        const h = createSkein(stateBytes, stateBytes);
        for (let at = 0; at < message.length; at += size) {
          h.update(message.subarray(at, Math.min(at + size, message.length)));
        }
        expect(toHex(h.digest()), `${stateBytes * 8}-bit state, chunks of ${size}`).toBe(expected);
      }
    }
  });

  it("hashes a message that is an exact multiple of the block size", () => {
    // The case a flush-eagerly implementation gets wrong: the last full block must carry the final
    // flag, not an empty block after it.
    for (const stateBytes of SKEIN_STATE_SIZES) {
      const exact = new Uint8Array(stateBytes * 2);
      exact.fill(0xab);
      const h = createSkein(stateBytes, 32);
      h.update(exact.subarray(0, stateBytes));
      h.update(exact.subarray(stateBytes));
      expect(toHex(h.digest())).toBe(toHex(skein(exact, stateBytes, 32)));
      // And it differs from the same message one byte longer, which shares its first block.
      const longer = new Uint8Array(stateBytes * 2 + 1);
      longer.set(exact);
      longer[stateBytes * 2] = 0xab;
      expect(toHex(skein(longer, stateBytes, 32))).not.toBe(toHex(skein(exact, stateBytes, 32)));
    }
  });

  it("produces output longer than its state by re-running UBI with a counter", () => {
    // Output generation is a UBI call per block over an incrementing counter, so a 200-byte output
    // from a 64-byte state needs four of them and no two blocks may repeat.
    const out = skein(new TextEncoder().encode("long output"), 64, 200);
    expect(out).toHaveLength(200);
    const blocks = [0, 64, 128].map((at) => toHex(out.subarray(at, at + 64)));
    expect(new Set(blocks).size).toBe(3);
  });

  it("names the state sizes and rejects a bad output length", () => {
    expect(SKEIN_STATE_SIZES).toEqual([32, 64, 128]);
    expect(() => createSkein(48, 32)).toThrow(/32, 64 or 128/);
    expect(() => createSkein(64, 0)).toThrow(/positive/);
  });

  it("refuses reuse after digest", () => {
    const h = createSkein(64, 64);
    h.digest();
    expect(() => h.digest()).toThrow(/twice/);
    expect(() => h.update(new Uint8Array(1))).toThrow(/after digest/);
  });
});


describe("Skein-MAC -- the 1.3 golden KAT", () => {
  /**
   * Skein's own keyed mode, and the reason Skein needs no HMAC.
   *
   * `G0 = UBI(0, K, T_key)` runs before the configuration block, so the key changes the initial
   * chaining value rather than wrapping the message in two hashes. Fifty published vectors across all
   * three state sizes, output lengths from 160 to 2056 bits, and -- the part worth having -- keys both
   * shorter and *longer* than the state.
   */
  it("matches every vector", () => {
    expect(SKEIN_MAC_VECTORS.length).toBeGreaterThan(40);
    for (const { stateBits, outputBits, message, key, hex } of SKEIN_MAC_VECTORS) {
      const label = `Skein-${stateBits}-${outputBits}, ${key.length / 2}-byte key, ${message.length / 2}-byte message`;
      expect(
        toHex(skeinMac(fromHex(key), fromHex(message), stateBits / 8, outputBits / 8)),
        label,
      ).toBe(hex);
    }
  });

  it("covers keys longer than the state, which HMAC cannot have", () => {
    /**
     * The structural difference from HMAC, asserted on the fixture: HMAC hashes an over-long key down
     * to one digest first, so past the block size extra key bytes stop adding anything. UBI absorbs the
     * key in blocks instead, so a 65-byte key under a 32-byte state is genuinely 65 bytes of key -- and
     * the vector set has to contain such a case for that to be tested at all.
     */
    const overlong = SKEIN_MAC_VECTORS.filter((v) => v.key.length / 2 > v.stateBits / 8);
    expect(overlong.length).toBeGreaterThan(0);
  });

  it("is not the same as hashing the key and message together", () => {
    // A keyed mode that ignored its key, or appended it to the message, would still pass a
    // single-vector test. This says the key goes somewhere else entirely.
    const key = fromHex("0011223344556677");
    const message = ascii("skein mac");
    const together = new Uint8Array(key.length + message.length);
    together.set(key);
    together.set(message, key.length);

    expect(toHex(skeinMac(key, message, 64, 64))).not.toBe(toHex(skein(message, 64, 64)));
    expect(toHex(skeinMac(key, message, 64, 64))).not.toBe(toHex(skein(together, 64, 64)));
  });

  it("streams to the same tag as one shot", () => {
    const key = fromHex("00112233445566778899aabbccddeeff");
    const message = new Uint8Array(300);
    for (let i = 0; i < message.length; i++) message[i] = (i * 17 + 9) & 0xff;

    for (const stateBytes of SKEIN_STATE_SIZES) {
      const expected = toHex(skeinMac(key, message, stateBytes, stateBytes));
      for (const size of [1, 31, 32, 63, 64, 127, 128, 299]) {
        const h = createSkein(stateBytes, stateBytes, key);
        for (let at = 0; at < message.length; at += size) {
          h.update(message.subarray(at, Math.min(at + size, message.length)));
        }
        expect(toHex(h.digest()), `${stateBytes * 8}-bit state in ${size}s`).toBe(expected);
      }
    }
  });

  it("treats an empty key as no key at all", () => {
    // The specification skips the key block when there is no key, so this must equal the plain hash --
    // and an implementation that ran a zero-length UBI pass anyway would differ.
    const message = ascii("no key");
    expect(toHex(skeinMac(new Uint8Array(0), message, 64, 64))).toBe(
      toHex(skein(message, 64, 64)),
    );
  });
});
