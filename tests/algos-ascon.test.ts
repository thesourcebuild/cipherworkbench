/**
 * Ascon, against the reference known-answer tests.
 *
 * NIST standardised Ascon in SP 800-232 and there is no second implementation available here -- not
 * OpenSSL, not `hash-wasm`, not noble -- so the check is breadth of published vectors instead: 43
 * hash lengths, 13 XOF lengths and 144 AEAD combinations, taken from the Ascon team's own KAT files.
 * See `tests/ascon-kat.ts` for exactly which and why those.
 */
import { describe, expect, it } from "vitest";
import {
  ASCON_AEAD_TAG_LEN,
  ASCON_PRF_SHORT_MAX,
  asconAead128Decrypt,
  asconAead128Encrypt,
  asconHash256,
  asconMac,
  asconPrf,
  asconPrfShort,
  asconXof128,
  createAsconHash256,
  createAsconMac,
  createAsconPrf,
  createAsconXof128,
} from "@ocs/algos";
import {
  ASCON_AEAD128_KAT,
  ASCON_HASH256_KAT,
  ASCON_XOF128_KAT,
  asconKatMessage,
} from "./ascon-kat";
import {
  ASCON_KEYED_KEY,
  ASCON_MAC_KAT,
  ASCON_PRF_KAT,
  ASCON_PRF_KAT_LEN,
  ASCON_PRF_SHORT_KAT,
  ASCON_PRF_SHORT_KAT_LEN,
  asconKeyedKatMessage,
} from "./ascon-keyed-kat";

const fromHex = (hex: string) =>
  hex === ""
    ? new Uint8Array(0)
    : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

describe("Ascon-Hash256", () => {
  it("matches every selected reference vector", () => {
    expect(ASCON_HASH256_KAT.length).toBeGreaterThan(40);
    for (const { length, hex } of ASCON_HASH256_KAT) {
      expect(toHex(asconHash256(asconKatMessage(length))), `length ${length}`).toBe(hex);
    }
  });

  it("covers every length across the first four rate boundaries", () => {
    // The 8-byte rate is where a sponge's padding goes wrong, so the vector set must not have gaps
    // below 34 bytes. Asserted rather than assumed, because the fixture is generated.
    const lengths = new Set(ASCON_HASH256_KAT.map((v) => v.length));
    for (let n = 0; n <= 34; n++) expect(lengths.has(n), `length ${n}`).toBe(true);
  });

  it("streams to the same digest as one shot", () => {
    const message = asconKatMessage(300);
    const expected = toHex(asconHash256(message));
    for (const size of [1, 3, 7, 8, 9, 16, 64, 299]) {
      const h = createAsconHash256();
      for (let at = 0; at < message.length; at += size) {
        h.update(message.subarray(at, Math.min(at + size, message.length)));
      }
      expect(toHex(h.digest()), `chunks of ${size}`).toBe(expected);
    }
  });

  it("refuses reuse after digest", () => {
    const h = createAsconHash256();
    h.digest();
    expect(() => h.digest()).toThrow(/twice/);
    expect(() => h.update(new Uint8Array(1))).toThrow(/after digest/);
  });
});

describe("Ascon-XOF128", () => {
  it("matches the reference vectors at the KAT's 64-byte output length", () => {
    for (const { length, hex } of ASCON_XOF128_KAT) {
      expect(toHex(asconXof128(asconKatMessage(length), 64)), `length ${length}`).toBe(hex);
    }
  });

  it("is a prefix-stable XOF: a shorter output is the longer one truncated", () => {
    /**
     * The property that distinguishes an XOF from a family of hashes, and the one Ascon-XOF128 has
     * where Ascon-Hash256 deliberately does not -- the hash's IV encodes its 256-bit output size, so
     * `Hash256` is not `XOF128` cut down.
     */
    const message = asconKatMessage(20);
    const long = asconXof128(message, 96);
    for (const n of [1, 8, 9, 32, 64, 95]) {
      expect(toHex(asconXof128(message, n)), `${n} bytes`).toBe(toHex(long.subarray(0, n)));
    }
    expect(toHex(asconHash256(message))).not.toBe(toHex(long.subarray(0, 32)));
  });

  it("squeezes across the rate boundary correctly", () => {
    // Output longer than the 8-byte rate needs a permutation between blocks; a version that squeezed
    // 8 bytes and then repeated them would pass a round trip and fail here.
    const out = asconXof128(asconKatMessage(1), 24);
    expect(toHex(out.subarray(0, 8))).not.toBe(toHex(out.subarray(8, 16)));
    expect(toHex(out.subarray(8, 16))).not.toBe(toHex(out.subarray(16, 24)));
  });

  it("rejects a non-positive output length", () => {
    expect(() => createAsconXof128(0)).toThrow(/positive/);
  });
});

describe("Ascon-AEAD128", () => {
  it("matches every selected reference vector", () => {
    expect(ASCON_AEAD128_KAT.length).toBeGreaterThan(100);
    for (const { key, nonce, pt, ad, ct } of ASCON_AEAD128_KAT) {
      const sealed = asconAead128Encrypt(
        fromHex(key),
        fromHex(nonce),
        fromHex(pt),
        fromHex(ad),
      );
      expect(toHex(sealed), `pt ${pt.length / 2} ad ${ad.length / 2}`).toBe(ct);
    }
  });

  it("decrypts every selected reference vector back", () => {
    for (const { key, nonce, pt, ad, ct } of ASCON_AEAD128_KAT) {
      const opened = asconAead128Decrypt(
        fromHex(key),
        fromHex(nonce),
        fromHex(ct),
        fromHex(ad),
      );
      expect(opened, `pt ${pt.length / 2} ad ${ad.length / 2}`).not.toBeNull();
      expect(toHex(opened!)).toBe(pt);
    }
  });

  it("returns null for a tampered ciphertext, a wrong tag and altered associated data", () => {
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const nonce = fromHex("101112131415161718191a1b1c1d1e1f");
    const message = new TextEncoder().encode("twenty-three bytes here");
    const ad = new TextEncoder().encode("header");
    const sealed = asconAead128Encrypt(key, nonce, message, ad);

    for (const at of [0, 5, message.length - 1, sealed.length - 1]) {
      const tampered = Uint8Array.from(sealed);
      tampered[at] = tampered[at]! ^ 1;
      expect(asconAead128Decrypt(key, nonce, tampered, ad), `byte ${at}`).toBeNull();
    }

    // Right ciphertext, wrong associated data. Nothing about the ciphertext changed, so this is
    // purely the tag doing its job.
    expect(asconAead128Decrypt(key, nonce, sealed, new TextEncoder().encode("Header"))).toBeNull();
    expect(asconAead128Decrypt(key, nonce, sealed, new Uint8Array(0))).toBeNull();

    // And a wrong key.
    const otherKey = Uint8Array.from(key);
    otherKey[0] = otherKey[0]! ^ 1;
    expect(asconAead128Decrypt(otherKey, nonce, sealed, ad)).toBeNull();
  });

  it("returns null rather than throwing for input too short to hold a tag", () => {
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const nonce = fromHex("101112131415161718191a1b1c1d1e1f");
    expect(asconAead128Decrypt(key, nonce, new Uint8Array(ASCON_AEAD_TAG_LEN - 1))).toBeNull();
    // Exactly a tag decrypts to the empty message, which is a legitimate vector.
    const empty = asconAead128Encrypt(key, nonce, new Uint8Array(0));
    expect(empty).toHaveLength(ASCON_AEAD_TAG_LEN);
    expect(asconAead128Decrypt(key, nonce, empty)).toHaveLength(0);
  });

  it("names the key and nonce sizes it needs", () => {
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const nonce = fromHex("101112131415161718191a1b1c1d1e1f");
    expect(() => asconAead128Encrypt(new Uint8Array(24), nonce, new Uint8Array(0))).toThrow(
      /16-byte key/,
    );
    expect(() => asconAead128Encrypt(key, new Uint8Array(12), new Uint8Array(0))).toThrow(
      /16-byte nonce/,
    );
  });

  it("separates the associated data from the message", () => {
    /**
     * The domain-separation bit, asserted where it shows: moving bytes from the message to the
     * associated data must change the tag, or the two phases are running into each other.
     */
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const nonce = fromHex("101112131415161718191a1b1c1d1e1f");
    const all = new TextEncoder().encode("abcdefghijklmnop");
    const split = asconAead128Encrypt(key, nonce, all.subarray(8), all.subarray(0, 8));
    const whole = asconAead128Encrypt(key, nonce, all, new Uint8Array(0));
    expect(toHex(split)).not.toBe(toHex(whole));
  });
});


/**
 * Ascon's keyed modes: Ascon-MAC, Ascon-PRF and Ascon-PRFShort.
 *
 * From the v1.3 submission and **not** SP 800-232, which standardised the AEAD, the hash and the two
 * XOFs only. They are the designers' own constructions, published with known-answer files -- which is
 * what makes them checkable, and the reason they are here at all.
 */
describe("Ascon's keyed modes", () => {
  const KEY = fromHex(ASCON_KEYED_KEY);

  it("Ascon-MAC matches every selected reference vector", () => {
    expect(ASCON_MAC_KAT.length).toBeGreaterThan(60);
    for (const { length, hex } of ASCON_MAC_KAT) {
      expect(toHex(asconMac(KEY, asconKeyedKatMessage(length))), `length ${length}`).toBe(hex);
    }
  });

  it("Ascon-PRF matches every selected reference vector at 64 bytes of output", () => {
    for (const { length, hex } of ASCON_PRF_KAT) {
      expect(
        toHex(asconPrf(KEY, asconKeyedKatMessage(length), ASCON_PRF_KAT_LEN)),
        `length ${length}`,
      ).toBe(hex);
    }
  });

  it("Ascon-PRFShort matches the whole reference file", () => {
    // Seventeen vectors: every input length from 0 to 16, which is the entire domain.
    expect(ASCON_PRF_SHORT_KAT).toHaveLength(17);
    for (const { length, hex } of ASCON_PRF_SHORT_KAT) {
      expect(
        toHex(asconPrfShort(KEY, asconKeyedKatMessage(length), ASCON_PRF_SHORT_KAT_LEN)),
        `length ${length}`,
      ).toBe(hex);
    }
  });

  it("covers both sides of the 32-byte absorb rate and the 16-byte squeeze", () => {
    // Asserted because the fixture is generated: the lengths that matter are the ones either side of
    // 32 and 64 bytes in, and the output crossing 16 bytes out.
    const lengths = new Set(ASCON_MAC_KAT.map((v) => v.length));
    for (const n of [0, 1, 31, 32, 33, 63, 64, 65]) expect(lengths.has(n), `length ${n}`).toBe(true);
    expect(ASCON_PRF_KAT_LEN).toBeGreaterThan(16);
  });

  it("Ascon-PRF's shorter output is a prefix of its longer one", () => {
    /**
     * The property that distinguishes it from KMAC and Skein, where the length is bound into the
     * computation. Ascon-PRF squeezes a stream, so 16 bytes really is the first 16 of 64 -- which is
     * what makes it usable for deriving several values from one key.
     */
    const message = asconKeyedKatMessage(40);
    const long = asconPrf(KEY, message, 64);
    for (const n of [1, 8, 16, 17, 32, 63]) {
      expect(toHex(asconPrf(KEY, message, n)), `${n} bytes`).toBe(toHex(long.subarray(0, n)));
    }
  });

  it("Ascon-MAC is Ascon-PRF with a different domain, not a truncation of it", () => {
    // Both squeeze 16 bytes over the same key and message; the variant number in the IV differs, so
    // the answers must not agree. An implementation that shared one IV would pass its own round trip.
    const message = asconKeyedKatMessage(10);
    expect(toHex(asconMac(KEY, message))).not.toBe(toHex(asconPrf(KEY, message, 16)));
  });

  it("Ascon-PRFShort binds the input length, so padding changes the tag", () => {
    // Four bytes and the same four bytes zero-extended to eight are different inputs, because the
    // length goes into the initialising value. This is why PRFShort cannot be expressed as the PRF.
    const short = Uint8Array.of(1, 2, 3, 4);
    const padded = Uint8Array.of(1, 2, 3, 4, 0, 0, 0, 0);
    expect(toHex(asconPrfShort(KEY, short))).not.toBe(toHex(asconPrfShort(KEY, padded)));
    // And it is not the full PRF either.
    expect(toHex(asconPrfShort(KEY, short))).not.toBe(toHex(asconPrf(KEY, short, 16)));
  });

  it("streams to the same tag as one shot", () => {
    const message = new Uint8Array(200);
    for (let i = 0; i < message.length; i++) message[i] = (i * 23 + 11) & 0xff;

    for (const size of [1, 7, 31, 32, 33, 64, 199]) {
      const mac = createAsconMac(KEY);
      const prf = createAsconPrf(KEY, 48);
      for (let at = 0; at < message.length; at += size) {
        const chunk = message.subarray(at, Math.min(at + size, message.length));
        mac.update(chunk);
        prf.update(chunk);
      }
      expect(toHex(mac.digest()), `MAC in ${size}s`).toBe(toHex(asconMac(KEY, message)));
      expect(toHex(prf.digest()), `PRF in ${size}s`).toBe(toHex(asconPrf(KEY, message, 48)));
    }
  });

  it("names its key and input limits", () => {
    expect(ASCON_PRF_SHORT_MAX).toBe(16);
    expect(() => asconMac(new Uint8Array(24), new Uint8Array(0))).toThrow(/16-byte key/);
    expect(() => asconPrf(new Uint8Array(8), new Uint8Array(0), 16)).toThrow(/16-byte key/);
    expect(() => asconPrfShort(KEY, new Uint8Array(17))).toThrow(/at most 16 bytes/);
    expect(() => asconPrfShort(KEY, new Uint8Array(4), 17)).toThrow(/1 to 16 bytes/);
    expect(() => createAsconPrf(KEY, 0)).toThrow(/positive/);
  });
});
