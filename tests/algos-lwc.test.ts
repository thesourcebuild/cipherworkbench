import { describe, expect, it } from "vitest";
import {
  createEsch,
  createPhotonBeetleHash,
  createRomulusH,
  createXoodyakHash,
  elephantDecrypt,
  elephantEncrypt,
  esch,
  giftCofbDecrypt,
  giftCofbEncrypt,
  grain128AeadDecrypt,
  grain128AeadEncrypt,
  isapDecrypt,
  isapEncrypt,
  photonBeetleDecrypt,
  photonBeetleEncrypt,
  photonBeetleHash,
  romulusDecrypt,
  romulusEncrypt,
  romulusH,
  schwaemmDecrypt,
  schwaemmEncrypt,
  tinyJambuDecrypt,
  tinyJambuEncrypt,
  xoodyakDecrypt,
  xoodyakEncrypt,
  xoodyakHash,
} from "@ocs/algos";
import {
  AEAD_ELEPHANT_DELIRIUM,
  AEAD_ELEPHANT_DUMBO,
  AEAD_ELEPHANT_JUMBO,
  AEAD_GIFTCOFB,
  AEAD_GRAIN128AEAD,
  AEAD_ISAP_A_128,
  AEAD_ISAP_A_128A,
  AEAD_ISAP_K_128,
  AEAD_ISAP_K_128A,
  AEAD_PHOTONBEETLE128,
  AEAD_PHOTONBEETLE32,
  AEAD_ROMULUS_M,
  AEAD_ROMULUS_N,
  AEAD_ROMULUS_T,
  AEAD_SCHWAEMM128_128,
  AEAD_SCHWAEMM192_192,
  AEAD_SCHWAEMM256_128,
  AEAD_SCHWAEMM256_256,
  AEAD_TINYJAMBU128,
  AEAD_TINYJAMBU192,
  AEAD_TINYJAMBU256,
  AEAD_XOODYAK,
  HASH_ESCH256,
  HASH_ESCH384,
  HASH_PHOTONBEETLE,
  HASH_ROMULUS_H,
  HASH_XOODYAK,
  type LwcAeadVector,
  type LwcHashVector,
} from "./lwc-vectors";

/**
 * The nine NIST lightweight finalists, against their submissions' own known-answer files.
 *
 * None of the nine has an oracle: OpenSSL implements none of them and no dependency in this tree does
 * either. So published vectors are all there is -- and the answer to that is *breadth*, which is why
 * `tests/lwc-vectors.ts` carries 61 AEAD records per algorithm chosen at the rate boundaries rather
 * than a handful chosen for being short. Between them the nine designs use rates of 4, 8, 16, 18, 20,
 * 22, 24 and 25 bytes, and every one of those is straddled here.
 *
 * During development the *whole* files ran -- 1089 records per algorithm in both directions, about
 * 53,000 assertions -- with exactly one failure across all nine: PHOTON-Beetle-Hash at a message of
 * exactly sixteen bytes, where "was the tail block full" and "is there a tail block" give different
 * domain constants. That is the shape of bug this family produces, and it is why the committed slice
 * covers lengths one either side of every boundary rather than sampling.
 *
 * ## Every case runs both ways, and the reason is not symmetry
 *
 * Six of the nine reconstruct state from the *plaintext* on the way back, not from the ciphertext -- so
 * decryption is a different expression rather than the same one rearranged. Romulus's `irho` and
 * Schwaemm's final-block reconstruction are the clearest cases: both are self-consistent under any
 * mistake, and only a published plaintext catches them.
 */

const unhex = (text: string): Uint8Array =>
  text === "" ? new Uint8Array(0) : Uint8Array.from(text.match(/../g)!.map((p) => parseInt(p, 16)));

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();

type Encrypt = (key: Uint8Array, nonce: Uint8Array, pt: Uint8Array, ad: Uint8Array) => Uint8Array;
type Decrypt = (
  key: Uint8Array,
  nonce: Uint8Array,
  data: Uint8Array,
  ad: Uint8Array,
) => Uint8Array | null;

/** One AEAD against one fixture: every record, both directions, plus a corrupted-tag rejection. */
function checkAead(
  label: string,
  vectors: readonly LwcAeadVector[],
  encrypt: Encrypt,
  decrypt: Decrypt,
): void {
  expect(vectors.length, `${label} fixture is too thin`).toBeGreaterThanOrEqual(60);
  for (const v of vectors) {
    const key = unhex(v.key);
    const nonce = unhex(v.nonce);
    const pt = unhex(v.pt);
    const ad = unhex(v.ad);
    expect(hex(encrypt(key, nonce, pt, ad)), `${label} #${v.count} encrypt`).toBe(v.ct);
    const opened = decrypt(key, nonce, unhex(v.ct), ad);
    expect(opened, `${label} #${v.count} decrypt rejected a valid ciphertext`).not.toBeNull();
    expect(hex(opened!), `${label} #${v.count} decrypt`).toBe(hex(pt));
  }

  /**
   * A flipped bit in the tag must be refused, and it is checked on the *longest* record.
   *
   * The last byte is the last byte of the tag for every one of these constructions, and the length is
   * what makes it a real check: a construction that ignored the message entirely would still pass a
   * rejection test on an empty one.
   */
  const longest = vectors.reduce((a, b) => (b.pt.length > a.pt.length ? b : a));
  const tampered = unhex(longest.ct);
  tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 0x01;
  expect(
    decrypt(unhex(longest.key), unhex(longest.nonce), tampered, unhex(longest.ad)),
    `${label} accepted a corrupted tag`,
  ).toBeNull();
}

function checkHash(
  label: string,
  vectors: readonly LwcHashVector[],
  digest: (message: Uint8Array) => Uint8Array,
): void {
  expect(vectors.length, `${label} fixture is too thin`).toBeGreaterThanOrEqual(50);
  for (const v of vectors) {
    expect(hex(digest(unhex(v.msg))), `${label} #${v.count}`).toBe(v.md);
  }
}

describe("Xoodyak", () => {
  it("reproduces every AEAD vector, both ways", () => {
    checkAead("Xoodyak", AEAD_XOODYAK, xoodyakEncrypt, xoodyakDecrypt);
  });

  it("reproduces every hash vector", () => {
    checkHash("Xoodyak-Hash", HASH_XOODYAK, (m) => xoodyakHash(m, 32));
  });

  /**
   * Cyclist squeezes, so a longer digest *extends* a shorter one rather than replacing it.
   *
   * Worth pinning because two other hashes in this repo behave the other way -- KMAC and Skein bind the
   * requested length into the computation -- and someone truncating by hand needs to know which kind
   * they have.
   */
  it("extends rather than replaces when asked for more output", () => {
    const message = new TextEncoder().encode("Cipher Workbench");
    expect(hex(xoodyakHash(message, 64)).slice(0, 64)).toBe(hex(xoodyakHash(message, 32)));
  });
});

describe("SPARKLE", () => {
  const CASES = [
    ["Schwaemm128-128", "128-128", AEAD_SCHWAEMM128_128],
    ["Schwaemm256-128", "256-128", AEAD_SCHWAEMM256_128],
    ["Schwaemm192-192", "192-192", AEAD_SCHWAEMM192_192],
    ["Schwaemm256-256", "256-256", AEAD_SCHWAEMM256_256],
  ] as const;

  it("reproduces every Schwaemm vector at all four instances, both ways", () => {
    for (const [label, variant, vectors] of CASES) {
      checkAead(
        label,
        vectors,
        (k, n, p, a) => schwaemmEncrypt(variant, k, n, p, a),
        (k, n, d, a) => schwaemmDecrypt(variant, k, n, d, a),
      );
    }
    // Four instances, and no two share a (key, nonce, tag) shape -- see the metadata's own test.
    expect(new Set(CASES.map(([, v]) => v)).size).toBe(4);
  });

  it("reproduces every Esch vector at both widths", () => {
    checkHash("Esch256", HASH_ESCH256, (m) => esch(256, m));
    checkHash("Esch384", HASH_ESCH384, (m) => esch(384, m));
  });
});

describe("GIFT-COFB", () => {
  it("reproduces every vector, both ways", () => {
    checkAead("GIFT-COFB", AEAD_GIFTCOFB, giftCofbEncrypt, giftCofbDecrypt);
  });
});

describe("PHOTON-Beetle", () => {
  it("reproduces every vector at both rates, both ways", () => {
    checkAead(
      "PHOTON-Beetle-AEAD[32]",
      AEAD_PHOTONBEETLE32,
      (k, n, p, a) => photonBeetleEncrypt(4, k, n, p, a),
      (k, n, d, a) => photonBeetleDecrypt(4, k, n, d, a),
    );
    checkAead(
      "PHOTON-Beetle-AEAD[128]",
      AEAD_PHOTONBEETLE128,
      (k, n, p, a) => photonBeetleEncrypt(16, k, n, p, a),
      (k, n, d, a) => photonBeetleDecrypt(16, k, n, d, a),
    );
  });

  it("reproduces every hash vector", () => {
    checkHash("PHOTON-Beetle-Hash", HASH_PHOTONBEETLE, photonBeetleHash);
  });

  /**
   * The sixteen-byte message, called out because it is the one first-attempt failure in this family.
   *
   * The first sixteen bytes of the message *become* the state, so at exactly sixteen there is a state
   * and no tail block -- and the domain constant is 2, not the 1 that "the tail block was full" gives.
   * Every other length was correct. Asserted here on its own so a regression names itself.
   */
  it("hashes a message of exactly one state's width", () => {
    const sixteen = HASH_PHOTONBEETLE.find((v) => v.msg.length === 32);
    expect(sixteen, "the 16-byte hash vector is missing from the fixture").toBeDefined();
    expect(hex(photonBeetleHash(unhex(sixteen!.msg)))).toBe(sixteen!.md);
  });
});

describe("Romulus", () => {
  const CASES = [
    ["Romulus-N", "n", AEAD_ROMULUS_N],
    ["Romulus-M", "m", AEAD_ROMULUS_M],
    ["Romulus-T", "t", AEAD_ROMULUS_T],
  ] as const;

  it("reproduces every vector in all three modes, both ways", () => {
    for (const [label, mode, vectors] of CASES) {
      checkAead(
        label,
        vectors,
        (k, n, p, a) => romulusEncrypt(mode, k, n, p, a),
        (k, n, d, a) => romulusDecrypt(mode, k, n, d, a),
      );
    }
  });

  it("reproduces every Romulus-H vector", () => {
    checkHash("Romulus-H", HASH_ROMULUS_H, romulusH);
  });

  /**
   * The three modes are three different functions over the same key, nonce and message.
   *
   * Not a tautology worth skipping: all three drive the same tweakable cipher with the same counter, so
   * a mode selector that reached the wrong arm would produce a perfectly valid ciphertext under a
   * different mode -- and the round trip would pass.
   */
  it("gives three unrelated ciphertexts for the three modes", () => {
    const key = new Uint8Array(16).fill(0x11);
    const nonce = new Uint8Array(16).fill(0x22);
    const message = new TextEncoder().encode("Romulus, three modes, one cipher.");
    const outputs = CASES.map(([, mode]) => hex(romulusEncrypt(mode, key, nonce, message, new Uint8Array(0))));
    expect(new Set(outputs).size).toBe(3);
  });
});

describe("Elephant", () => {
  const CASES = [
    ["Dumbo", "dumbo", AEAD_ELEPHANT_DUMBO, 8],
    ["Jumbo", "jumbo", AEAD_ELEPHANT_JUMBO, 8],
    ["Delirium", "delirium", AEAD_ELEPHANT_DELIRIUM, 16],
  ] as const;

  it("reproduces every vector at all three instances, both ways", () => {
    for (const [label, variant, vectors, tagLen] of CASES) {
      checkAead(
        label,
        vectors,
        (k, n, p, a) => elephantEncrypt(variant, k, n, p, a),
        (k, n, d, a) => elephantDecrypt(variant, k, n, d, a),
      );
      // The tag length differs between the instances, which the fixture itself has to reflect.
      const empty = vectors.find((v) => v.pt === "")!;
      expect(empty.ct.length / 2, `${label} tag length`).toBe(tagLen);
    }
  });
});

describe("ISAP", () => {
  const CASES = [
    ["ISAP-A-128A", "a-128a", AEAD_ISAP_A_128A],
    ["ISAP-A-128", "a-128", AEAD_ISAP_A_128],
    ["ISAP-K-128A", "k-128a", AEAD_ISAP_K_128A],
    ["ISAP-K-128", "k-128", AEAD_ISAP_K_128],
  ] as const;

  it("reproduces every vector at all four variants, both ways", () => {
    for (const [label, variant, vectors] of CASES) {
      checkAead(
        label,
        vectors,
        (k, n, p, a) => isapEncrypt(variant, k, n, p, a),
        (k, n, d, a) => isapDecrypt(variant, k, n, d, a),
      );
    }
  });

  /**
   * The two round-count profiles are different functions, and so are the two permutations.
   *
   * ISAP-A-128A and ISAP-A-128 differ only in `sB` and `sE`; a variant selector that ignored the
   * profile would give one of them the other's answer, which is a wrong value that verifies.
   */
  it("gives four unrelated ciphertexts for the four variants", () => {
    const key = new Uint8Array(16).fill(0x33);
    const nonce = new Uint8Array(16).fill(0x44);
    const message = new TextEncoder().encode("ISAP, four variants.");
    const outputs = CASES.map(([, variant]) =>
      hex(isapEncrypt(variant, key, nonce, message, new Uint8Array(0))),
    );
    expect(new Set(outputs).size).toBe(4);
  });
});

describe("Grain-128AEAD", () => {
  it("reproduces every vector, both ways", () => {
    checkAead("Grain-128AEAD", AEAD_GRAIN128AEAD, grain128AeadEncrypt, grain128AeadDecrypt);
  });

  /**
   * The associated-data length prefix is DER-shaped, and the boundary is at 128 bytes.
   *
   * Under 128 it is one byte; at or above it is `0x80 | count` followed by the length. The fixture only
   * reaches 32 bytes of associated data, so this is the assertion that covers the other branch -- by
   * requiring that 127 and 128 bytes of associated data give different tags for the same message, which
   * a missing prefix would not.
   */
  it("distinguishes associated data across the length-prefix boundary", () => {
    const key = new Uint8Array(16).fill(0x55);
    const nonce = new Uint8Array(12).fill(0x66);
    const message = new Uint8Array(4);
    const shortAd = new Uint8Array(127).fill(0xaa);
    const longAd = new Uint8Array(128).fill(0xaa);
    const a = hex(grain128AeadEncrypt(key, nonce, message, shortAd));
    const b = hex(grain128AeadEncrypt(key, nonce, message, longAd));
    expect(a).not.toBe(b);
    // And both must still round-trip, which a malformed prefix would break asymmetrically.
    expect(hex(grain128AeadDecrypt(key, nonce, unhex(a), shortAd)!)).toBe(hex(message));
    expect(hex(grain128AeadDecrypt(key, nonce, unhex(b), longAd)!)).toBe(hex(message));
  });
});

/**
 * The four hashes stream, and this is what makes that claim true rather than plausible.
 *
 * All four treat their *final* block differently from an interior one, so all four have to decide the
 * boundary before they know whether more input is coming. Three hold a block back and Romulus-H does
 * not -- its reference pads a zero-length tail where the others pad a full one -- and getting that
 * backwards is wrong for exactly the lengths that are multiples of the rate, which is why the sweep is
 * every length rather than a sample.
 *
 * The rates are 4, 16 and 32 bytes; the chunk sizes cross all of them, including sizes that are neither
 * a multiple nor a divisor of any rate.
 */
describe("the lightweight hashes, streamed", () => {
  interface Hasher {
    update(chunk: Uint8Array): void;
    digest(): Uint8Array;
  }

  const CASES: readonly [string, () => Hasher, (m: Uint8Array) => Uint8Array][] = [
    ["Xoodyak-Hash", () => createXoodyakHash(32), (m) => xoodyakHash(m, 32)],
    ["Esch256", () => createEsch(256), (m) => esch(256, m)],
    ["Esch384", () => createEsch(384), (m) => esch(384, m)],
    ["PHOTON-Beetle-Hash", createPhotonBeetleHash, photonBeetleHash],
    ["Romulus-H", createRomulusH, romulusH],
  ];

  it("agrees with the one-shot form at every length to 200, in thirteen chunk sizes", () => {
    for (const [name, create, oneShot] of CASES) {
      for (let len = 0; len <= 200; len++) {
        const message = new Uint8Array(len);
        for (let i = 0; i < len; i++) message[i] = (i * 7 + 3) & 0xff;
        const want = hex(oneShot(message));

        const whole = create();
        whole.update(message);
        expect(hex(whole.digest()), `${name} at ${len} bytes, one chunk`).toBe(want);

        for (const chunk of [1, 2, 3, 4, 5, 7, 16, 17, 18, 25, 31, 32, 33]) {
          const h = create();
          for (let off = 0; off < len; off += chunk) {
            h.update(message.subarray(off, Math.min(off + chunk, len)));
          }
          expect(hex(h.digest()), `${name} at ${len} bytes, ${chunk}-byte chunks`).toBe(want);
        }
      }
    }
  });
});

describe("TinyJAMBU", () => {
  const CASES = [
    ["TinyJAMBU-128", 128, AEAD_TINYJAMBU128],
    ["TinyJAMBU-192", 192, AEAD_TINYJAMBU192],
    ["TinyJAMBU-256", 256, AEAD_TINYJAMBU256],
  ] as const;

  it("reproduces every vector at all three key sizes, both ways", () => {
    for (const [label, bits, vectors] of CASES) {
      checkAead(
        label,
        vectors,
        (k, n, p, a) => tinyJambuEncrypt(bits, k, n, p, a),
        (k, n, d, a) => tinyJambuDecrypt(bits, k, n, d, a),
      );
    }
  });

  it("refuses a key of the wrong length for the selected size", () => {
    const nonce = new Uint8Array(12);
    expect(() => tinyJambuEncrypt(192, new Uint8Array(16), nonce, new Uint8Array(0), new Uint8Array(0))).toThrow(
      /24-byte key/,
    );
    expect(() => tinyJambuEncrypt(128, new Uint8Array(16), new Uint8Array(16), new Uint8Array(0), new Uint8Array(0))).toThrow(
      /12-byte nonce/,
    );
  });
});
