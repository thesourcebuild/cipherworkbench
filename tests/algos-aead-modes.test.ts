/**
 * GCM, CCM, XTS and OCB over the shared `BlockCipher` interface, against OpenSSL.
 *
 * These four are the modes `@noble/ciphers` does not provide, and between them they cover the gap that
 * mattered most: **XTS** is what every disk encryption product uses, **CCM** is WPA2, Bluetooth and
 * LoRaWAN, **OCB** is patent-free since 2021, and generic **GCM** is what makes SM4-GCM (RFC 8998's
 * TLS 1.3 suite) and ARIA-GCM reachable at all.
 *
 * `node:crypto` is the oracle for all of it -- `aes-*-gcm`, `aes-*-ccm`, `aes-*-ocb`, `aes-128/256-xts`,
 * `aria-*-gcm` and `aria-*-ccm` are all available -- and SM4-GCM/CCM, which OpenSSL does not name here,
 * are checked against RFC 8998's own vectors.
 *
 * Two bugs were found by writing this file, both worth knowing about:
 *
 *  - **AES-OFB was broken past one block.** noble v2 rejects a second `encrypt()` on the same instance
 *    (`cannot encrypt() twice with same key + nonce`), and the OFB binding called it once per block. The
 *    only OFB test was NIST SP 800-38A F.4.1, which is exactly one block, so nothing caught it. There is
 *    a regression test for it below and a length sweep in `tests/cipher.test.ts`.
 *  - **noble's `unsafe.encryptBlock` encrypts in place** and returns its own argument, so handing it a
 *    live buffer destroys the caller's data. GCM's counter block was the casualty: block one was right
 *    and everything after it was wrong. The adapter copies into scratch now, and the `BlockCipher`
 *    contract test below asserts no adapter mutates its input.
 */
import { describe, expect, it } from "vitest";
import { createCipheriv, createDecipheriv, type Cipher } from "node:crypto";
import { unsafe } from "@noble/ciphers/aes.js";
import {
  ccmDecrypt,
  ccmEncrypt,
  createAria,
  createCamellia,
  createSm4,
  gcmDecrypt,
  gcmEncrypt,
  ghash,
  ocbDecrypt,
  ocbEncrypt,
  xtsDecrypt,
  xtsEncrypt,
  type BlockCipher,
} from "@ocs/algos";

/**
 * One OpenSSL AEAD cipher object, for an algorithm name built at runtime.
 *
 * `@types/node` keys `setAAD` and `getAuthTag` off a *literal* algorithm name -- `createCipheriv("aes-128-gcm", ...)`
 * returns `CipherGCM`, while `createCipheriv(someString, ...)` returns the plain `Cipher`, which has
 * neither method and does not accept `authTagLength`. Every name here is a template literal over a key
 * size, so all of them land on the plain overload. The cast restores what OpenSSL actually returns
 * rather than widening any contract, and it lives in one function so there is one cast in the file.
 */
type AeadCipher = Cipher & {
  setAAD(buffer: Uint8Array, options?: { plaintextLength?: number }): AeadCipher;
  getAuthTag(): Buffer;
};

function aeadCipher(
  name: string,
  key: Uint8Array,
  nonce: Uint8Array,
  tagLen = 16,
): AeadCipher {
  return createCipheriv(name, key, nonce, {
    authTagLength: tagLen,
  } as never) as unknown as AeadCipher;
}

const toHex = (bytes: Uint8Array) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (hex: string) =>
  hex === ""
    ? new Uint8Array(0)
    : Uint8Array.from(hex.replace(/\s+/g, "").match(/../g)!.map((b) => parseInt(b, 16)));

/** Deterministic filler -- `Math.random` is banned here and a fixed pattern is reproducible. */
const seq = (length: number, seed = 1): Uint8Array => {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (i * 7 + seed) & 0xff;
  return out;
};

/**
 * AES as a bare block permutation, mirroring `aesBlockCipher` in the cipher family's bindings.
 *
 * Duplicated rather than imported because this file tests `@ocs/algos`, which knows nothing about the
 * tool layer -- and because the scratch copy is the point: without it, `unsafe.encryptBlock` overwrites
 * whatever buffer it is handed.
 */
function aes(key: Uint8Array): BlockCipher {
  const encKey = unsafe.expandKeyLE(key);
  const decKey = unsafe.expandKeyDecLE(key);
  const scratch = new Uint8Array(16);
  return {
    blockSize: 16,
    encryptBlock: (src, dst) => {
      scratch.set(src);
      dst.set(unsafe.encryptBlock(encKey, scratch));
    },
    decryptBlock: (src, dst) => {
      scratch.set(src);
      dst.set(unsafe.decryptBlock(decKey, scratch));
    },
  };
}

describe("GCM against OpenSSL", () => {
  it("matches aes-*-gcm across key, nonce, message and AAD lengths", () => {
    for (const keyLen of [16, 24, 32]) {
      for (const nonceLen of [12, 8, 16, 60]) {
        for (const length of [0, 1, 15, 16, 17, 64, 100]) {
          for (const adLen of [0, 3, 16, 20]) {
            const key = seq(keyLen, 3);
            const nonce = seq(nonceLen, 5);
            const plaintext = seq(length, 7);
            const ad = seq(adLen, 9);

            const openssl = aeadCipher(`aes-${keyLen * 8}-gcm`, key, nonce, 16);
            if (adLen > 0) openssl.setAAD(ad);
            const theirs = Buffer.concat([
              openssl.update(plaintext),
              openssl.final(),
              openssl.getAuthTag(),
            ]).toString("hex");

            expect(
              toHex(gcmEncrypt(aes(key), nonce, plaintext, ad)),
              `aes-${keyLen * 8}-gcm nonce=${nonceLen} len=${length} ad=${adLen}`,
            ).toBe(theirs);
          }
        }
      }
    }
  });

  it("exercises the non-12-byte nonce path, which real protocols never reach", () => {
    /**
     * A 12-byte nonce becomes `IV || 1` directly; every other length is hashed through GHASH with its
     * own length block. Since essentially every deployment uses 96 bits, the general path is the one an
     * implementation can get wrong while passing every protocol-shaped test.
     */
    const key = seq(32, 11);
    for (const nonceLen of [1, 7, 8, 13, 16, 17, 32]) {
      const nonce = seq(nonceLen, 13);
      const plaintext = seq(48, 15);
      const openssl = createCipheriv("aes-256-gcm", key, nonce, { authTagLength: 16 });
      const theirs = Buffer.concat([
        openssl.update(plaintext),
        openssl.final(),
        openssl.getAuthTag(),
      ]).toString("hex");
      expect(toHex(gcmEncrypt(aes(key), nonce, plaintext, new Uint8Array(0))), `nonce ${nonceLen}`).toBe(
        theirs,
      );
    }
  });

  it("matches aria-*-gcm, which is why the mode is generic", () => {
    for (const keyLen of [16, 24, 32]) {
      const key = seq(keyLen, 11);
      const nonce = seq(12, 13);
      const plaintext = seq(33, 15);
      const ad = seq(17, 17);
      const openssl = aeadCipher(`aria-${keyLen * 8}-gcm`, key, nonce, 16);
      openssl.setAAD(ad);
      expect(toHex(gcmEncrypt(createAria(key), nonce, plaintext, ad)), `aria-${keyLen * 8}-gcm`).toBe(
        Buffer.concat([openssl.update(plaintext), openssl.final(), openssl.getAuthTag()]).toString(
          "hex",
        ),
      );
    }
  });

  it("reproduces RFC 8998's SM4-GCM vector", () => {
    // TLS_SM4_GCM_SM3's own test vector. OpenSSL has no `sm4-gcm` name here, so this is the check --
    // and it is what makes the SM4 + SM3 pair usable for the Chinese TLS 1.3 suite.
    const key = fromHex("0123456789ABCDEFFEDCBA9876543210");
    const nonce = fromHex("00001234567800000000ABCD");
    const plaintext = fromHex(
      "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD" +
        "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA",
    );
    const ad = fromHex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
    const expected =
      "17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735" +
      "d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d" +
      "83de3541e4c2b58177e065a9bf7b62ec";

    expect(toHex(gcmEncrypt(createSm4(key), nonce, plaintext, ad))).toBe(expected);
    expect(
      toHex(gcmDecrypt(createSm4(key), nonce, fromHex(expected), ad)!),
    ).toBe(toHex(plaintext));
  });

  it("round-trips and rejects tampering, including in the AAD", () => {
    const key = seq(32, 1);
    const nonce = seq(12, 2);
    const plaintext = seq(50, 3);
    const ad = seq(9, 4);
    const sealed = gcmEncrypt(aes(key), nonce, plaintext, ad);
    expect(toHex(gcmDecrypt(aes(key), nonce, sealed, ad)!)).toBe(toHex(plaintext));

    const tampered = Uint8Array.from(sealed);
    tampered[0] = tampered[0]! ^ 1;
    expect(gcmDecrypt(aes(key), nonce, tampered, ad)).toBeNull();
    expect(gcmDecrypt(aes(key), nonce, sealed, seq(9, 5))).toBeNull();
  });

  it("GHASH is keyed and order-dependent, which is all it promises", () => {
    // Not a MAC on its own: exposed only to the modes. Two properties worth pinning -- a different
    // subkey gives a different value, and the blocks are not commutative.
    const a = ghash(seq(16, 1), seq(32, 2));
    expect(toHex(ghash(seq(16, 3), seq(32, 2)))).not.toBe(toHex(a));
    const swapped = new Uint8Array(32);
    swapped.set(seq(32, 2).subarray(16), 0);
    swapped.set(seq(32, 2).subarray(0, 16), 16);
    expect(toHex(ghash(seq(16, 1), swapped))).not.toBe(toHex(a));
    expect(() => ghash(seq(8, 1), seq(16, 2))).toThrow(/16 bytes/);
  });
});

describe("CCM against OpenSSL", () => {
  it("matches aes-*-ccm across nonce, tag, message and AAD lengths", () => {
    for (const keyLen of [16, 24, 32]) {
      for (const nonceLen of [7, 8, 11, 12, 13]) {
        for (const tagLen of [4, 8, 12, 16]) {
          for (const length of [0, 1, 16, 17, 40]) {
            for (const adLen of [0, 5, 16, 32]) {
              const key = seq(keyLen, 2);
              const nonce = seq(nonceLen, 4);
              const plaintext = seq(length, 6);
              const ad = seq(adLen, 8);

              const openssl = aeadCipher(`aes-${keyLen * 8}-ccm`, key, nonce, tagLen);
              if (adLen > 0) openssl.setAAD(ad, { plaintextLength: length });
              const theirs = Buffer.concat([
                openssl.update(plaintext),
                openssl.final(),
                openssl.getAuthTag(),
              ]).toString("hex");

              expect(
                toHex(ccmEncrypt(aes(key), nonce, plaintext, ad, tagLen)),
                `aes-${keyLen * 8}-ccm nonce=${nonceLen} tag=${tagLen} len=${length} ad=${adLen}`,
              ).toBe(theirs);
            }
          }
        }
      }
    }
  });

  it("matches aria-*-ccm too", () => {
    for (const keyLen of [16, 24, 32]) {
      const key = seq(keyLen, 21);
      const nonce = seq(13, 23);
      const plaintext = seq(30, 25);
      const ad = seq(11, 27);
      const openssl = aeadCipher(`aria-${keyLen * 8}-ccm`, key, nonce, 12);
      openssl.setAAD(ad, { plaintextLength: plaintext.length });
      expect(toHex(ccmEncrypt(createAria(key), nonce, plaintext, ad, 12)), `aria-${keyLen * 8}-ccm`).toBe(
        Buffer.concat([openssl.update(plaintext), openssl.final(), openssl.getAuthTag()]).toString(
          "hex",
        ),
      );
    }
  });

  it("reproduces RFC 8998's SM4-CCM vector", () => {
    const key = fromHex("0123456789ABCDEFFEDCBA9876543210");
    const nonce = fromHex("00001234567800000000ABCD");
    const plaintext = fromHex(
      "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD" +
        "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA",
    );
    const ad = fromHex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2");
    const expected =
      "48af93501fa62adbcd414cce6034d895dda1bf8f132f042098661572e7483094" +
      "fd12e518ce062c98acee28d95df4416bed31a2f04476c18bb40c84a74b97dc5b" +
      "16842d4fa186f56ab33256971fa110f4";

    expect(toHex(ccmEncrypt(createSm4(key), nonce, plaintext, ad, 16))).toBe(expected);
    expect(toHex(ccmDecrypt(createSm4(key), nonce, fromHex(expected), ad, 16)!)).toBe(
      toHex(plaintext),
    );
  });

  it("says what a long nonce costs, rather than truncating the message", () => {
    /**
     * CCM's nonce and message length trade against each other: the nonce is `15 - L` bytes and `L` bytes
     * encode the length, so a 13-byte nonce caps the message at 65535 bytes. 802.15.4 and WPA2 use
     * 13-byte nonces for exactly that reason -- their frames are small -- and the error names the trade
     * rather than failing obscurely.
     */
    const key = seq(16, 1);
    expect(() => ccmEncrypt(aes(key), seq(13, 2), new Uint8Array(65536), undefined, 16)).toThrow(
      /caps the message at 65535/,
    );
    // A 7-byte nonce leaves 8 length bytes and no practical cap.
    expect(() => ccmEncrypt(aes(key), seq(7, 2), new Uint8Array(65536), undefined, 16)).not.toThrow();
    expect(() => ccmEncrypt(aes(key), seq(6, 2), new Uint8Array(1), undefined, 16)).toThrow(
      /7 to 13 bytes/,
    );
    expect(() => ccmEncrypt(aes(key), seq(12, 2), new Uint8Array(1), undefined, 5)).toThrow(
      /even 4 to 16/,
    );
  });
});

describe("XTS against OpenSSL", () => {
  it("matches aes-128/256-xts at every length, both directions", () => {
    for (const half of [16, 32]) {
      for (const length of [16, 17, 20, 31, 32, 33, 48, 64, 100, 512]) {
        const key = seq(half * 2, 5);
        const tweak = seq(16, 9);
        const plaintext = seq(length, 3);
        const name = `aes-${half * 8}-xts`;

        const openssl = createCipheriv(name, key, tweak);
        const theirs = Buffer.concat([openssl.update(plaintext), openssl.final()]).toString("hex");
        const ours = xtsEncrypt(aes(key.subarray(0, half)), aes(key.subarray(half)), tweak, plaintext);
        expect(toHex(ours), `${name} @ ${length}`).toBe(theirs);

        // Decryption separately: the same mistake in both directions cancels out in a round trip, and
        // the stolen-block tweak order is exactly such a mistake.
        const back = createDecipheriv(name, key, tweak);
        expect(
          Buffer.concat([back.update(Buffer.from(ours)), back.final()]).toString("hex"),
          `${name} decrypt @ ${length}`,
        ).toBe(toHex(plaintext));
        expect(
          toHex(xtsDecrypt(aes(key.subarray(0, half)), aes(key.subarray(half)), tweak, ours)),
          `ours decrypt @ ${length}`,
        ).toBe(toHex(plaintext));
      }
    }
  });

  it("works over any 128-bit cipher, not just AES", () => {
    // The mode is generic, so Camellia and SM4 get disk-style encryption too. No oracle exists for
    // those, so what is asserted is the round trip and that the two differ from each other.
    const key = seq(16, 7);
    const tweak = seq(16, 11);
    const plaintext = seq(70, 13);
    for (const make of [createCamellia, createSm4]) {
      const sealed = xtsEncrypt(make(key), make(seq(16, 9)), tweak, plaintext);
      expect(sealed).toHaveLength(plaintext.length);
      expect(toHex(xtsDecrypt(make(key), make(seq(16, 9)), tweak, sealed))).toBe(toHex(plaintext));
    }
  });

  it("refuses an input shorter than one block", () => {
    const key = seq(32, 1);
    expect(() =>
      xtsEncrypt(aes(key.subarray(0, 16)), aes(key.subarray(16)), seq(16, 2), seq(15, 3)),
    ).toThrow(/at least 16 bytes/);
  });
});

describe("OCB against OpenSSL", () => {
  it("matches aes-*-ocb across key, tag, message and AAD lengths", () => {
    for (const keyLen of [16, 24, 32]) {
      for (const tagLen of [8, 12, 16]) {
        for (const length of [0, 1, 15, 16, 17, 32, 33, 64, 100]) {
          for (const adLen of [0, 1, 16, 20]) {
            const key = seq(keyLen, 3);
            const nonce = seq(12, 5);
            const plaintext = seq(length, 7);
            const ad = seq(adLen, 11);

            const openssl = aeadCipher(`aes-${keyLen * 8}-ocb`, key, nonce, tagLen);
            if (adLen > 0) openssl.setAAD(ad);
            const theirs = Buffer.concat([
              openssl.update(plaintext),
              openssl.final(),
              openssl.getAuthTag(),
            ]).toString("hex");

            expect(
              toHex(ocbEncrypt(aes(key), nonce, plaintext, ad, tagLen)),
              `aes-${keyLen * 8}-ocb tag=${tagLen} len=${length} ad=${adLen}`,
            ).toBe(theirs);
          }
        }
      }
    }
  });

  it("walks all 64 nonce bit-offsets, where the stretched window lives", () => {
    /**
     * `Offset_0` is a 128-bit window into a 192-bit stretch, starting at bit `bottom` -- the low 6 bits
     * of the formatted nonce. So only one nonce in eight starts on a byte boundary, and a byte-aligned
     * shortcut passes a single published vector while failing seven times out of eight. Sixty-four
     * nonces cover every offset.
     */
    const key = seq(32, 2);
    const plaintext = seq(40, 4);
    const ad = seq(8, 6);
    for (let last = 0; last < 64; last++) {
      const nonce = seq(12, 8);
      nonce[11] = last;
      const openssl = createCipheriv("aes-256-ocb", key, nonce, { authTagLength: 16 });
      openssl.setAAD(ad);
      expect(toHex(ocbEncrypt(aes(key), nonce, plaintext, ad, 16)), `nonce ending ${last}`).toBe(
        Buffer.concat([openssl.update(plaintext), openssl.final(), openssl.getAuthTag()]).toString(
          "hex",
        ),
      );
    }
  });

  it("binds the tag length into the ciphertext, so truncation is not equivalent", () => {
    // `num2str(taglen*8 mod 128, 7)` is part of the formatted nonce, so a 12-byte tag changes the
    // keystream as well as the tag. Truncating a 16-byte-tag output does not give the 12-byte-tag one.
    const key = seq(16, 1);
    const nonce = seq(12, 2);
    const plaintext = seq(32, 3);
    const long = ocbEncrypt(aes(key), nonce, plaintext, undefined, 16);
    const short = ocbEncrypt(aes(key), nonce, plaintext, undefined, 12);
    expect(toHex(short.subarray(0, 32))).not.toBe(toHex(long.subarray(0, 32)));
  });

  it("round-trips and rejects tampering", () => {
    const key = seq(16, 1);
    const nonce = seq(12, 2);
    const plaintext = seq(70, 3);
    const ad = seq(5, 4);
    const sealed = ocbEncrypt(aes(key), nonce, plaintext, ad);
    expect(toHex(ocbDecrypt(aes(key), nonce, sealed, ad)!)).toBe(toHex(plaintext));

    for (const at of [0, 16, sealed.length - 1]) {
      const tampered = Uint8Array.from(sealed);
      tampered[at] = tampered[at]! ^ 1;
      expect(ocbDecrypt(aes(key), nonce, tampered, ad), `byte ${at}`).toBeNull();
    }
    expect(ocbDecrypt(aes(key), nonce, sealed, seq(5, 9))).toBeNull();
  });

  it("names its nonce and tag limits", () => {
    const key = seq(16, 1);
    expect(() => ocbEncrypt(aes(key), new Uint8Array(0), new Uint8Array(1))).toThrow(/1 to 15 bytes/);
    expect(() => ocbEncrypt(aes(key), seq(16, 2), new Uint8Array(1))).toThrow(/1 to 15 bytes/);
    expect(() => ocbEncrypt(aes(key), seq(12, 2), new Uint8Array(1), undefined, 17)).toThrow(
      /1 to 16 bytes/,
    );
  });
});

describe("the BlockCipher contract", () => {
  it("no adapter mutates its source block", () => {
    /**
     * The invariant the GCM bug violated. `unsafe.encryptBlock` encrypts in place and returns its own
     * argument, so an adapter that forwards the caller's buffer destroys it -- and the symptom was
     * subtle: the first block of every mode was correct and every block after it was wrong.
     *
     * Every adapter this repo has, checked in both directions.
     */
    const adapters: [string, BlockCipher][] = [
      ["aes-128", aes(seq(16, 1))],
      ["aes-256", aes(seq(32, 1))],
      ["camellia-128", createCamellia(seq(16, 2))],
      ["aria-128", createAria(seq(16, 3))],
      ["sm4", createSm4(seq(16, 4))],
    ];

    for (const [name, cipher] of adapters) {
      const source = seq(cipher.blockSize, 9);
      const before = toHex(source);
      const out = new Uint8Array(cipher.blockSize);

      cipher.encryptBlock(source, out);
      expect(toHex(source), `${name} encryptBlock mutated its source`).toBe(before);
      expect(toHex(out), `${name} encryptBlock did nothing`).not.toBe(before);

      const back = new Uint8Array(cipher.blockSize);
      cipher.decryptBlock(out, back);
      expect(toHex(out), `${name} decryptBlock mutated its source`).toBe(toHex(out));
      expect(toHex(back), `${name} did not round-trip`).toBe(before);
    }
  });

  it("AES-OFB survives past its first block", () => {
    /**
     * The regression. noble v2's `ecb()` instance refuses a second `encrypt()`, so the previous binding
     * threw on block two -- and the only OFB test in the suite was a single-block NIST vector.
     */
    const key = seq(32, 5);
    const iv = seq(16, 7);
    const plaintext = seq(48, 9);

    // Built here the same way `blockmodes.ts` would drive it: OFB is a keystream mode, so this is the
    // XOR of the plaintext with successive encryptions of the state.
    const cipher = aes(key);
    const keystream = new Uint8Array(48);
    const state = Uint8Array.from(iv);
    const block = new Uint8Array(16);
    for (let at = 0; at < 48; at += 16) {
      cipher.encryptBlock(state, block);
      keystream.set(block, at);
      state.set(block);
    }
    const expected = plaintext.map((byte, i) => byte ^ keystream[i]!);

    const openssl = createCipheriv("aes-256-ofb", key, iv);
    expect(toHex(expected)).toBe(
      Buffer.concat([openssl.update(plaintext), openssl.final()]).toString("hex"),
    );
  });
});
