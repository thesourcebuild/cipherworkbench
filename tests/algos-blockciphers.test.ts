import crypto from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  createDes,
  createSm4,
  createTripleDes,
  decryptBlockMode,
  encryptBlockMode,
  isWeakDesKey,
  padPkcs7,
  unpadPkcs7,
  type BlockCipher,
  type BlockMode,
} from "@ocs/algos";

const fromHex = (hex: string) =>
  Uint8Array.from((hex.match(/../g) ?? []).map((byte) => parseInt(byte, 16)));
const toHex = (bytes: Uint8Array) =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

/**
 * OpenSSL, through `node:crypto`, as the oracle for every block cipher this repo implements.
 *
 * This is the file that makes a hand-written DES trustworthy. A round-trip test proves only that the
 * implementation is self-consistent -- a transcription error in one of DES's eight S-boxes gives a
 * cipher that encrypts and decrypts perfectly and agrees with nothing else in existence. Comparing
 * against a different implementation is the only check that catches it, and it catches it on the first
 * vector rather than the thousandth.
 *
 * `crypto.getCiphers()` on this build offers `des-ede3-*` and `des-ede-*` but not `des-*`: OpenSSL 3
 * moved single DES to the legacy provider. Single DES is therefore checked two other ways -- the
 * published FIPS vector, and the identity DES(K) == 3DES(K, K, K), which rides on the 3DES comparison
 * that does have an oracle.
 */
function opensslEncrypt(
  algorithm: string,
  key: Uint8Array,
  iv: Uint8Array | null,
  data: Uint8Array,
  padding: boolean,
): Uint8Array {
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  cipher.setAutoPadding(padding);
  return new Uint8Array(Buffer.concat([cipher.update(data), cipher.final()]));
}

function opensslDecrypt(
  algorithm: string,
  key: Uint8Array,
  iv: Uint8Array | null,
  data: Uint8Array,
  padding: boolean,
): Uint8Array {
  const decipher = crypto.createDecipheriv(algorithm, key, iv);
  decipher.setAutoPadding(padding);
  return new Uint8Array(Buffer.concat([decipher.update(data), decipher.final()]));
}

/** Deterministic bytes, so a failure is reproducible rather than "sometimes". */
function pseudoRandom(length: number, seed: number): Uint8Array {
  const out = new Uint8Array(length);
  let state = seed >>> 0 || 1;
  for (let i = 0; i < length; i++) {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out[i] = state & 0xff;
  }
  return out;
}

/**
 * Every mode against OpenSSL, at lengths that straddle the boundaries.
 *
 * The lengths are the point: 0, 1, one byte short of a block, exactly a block, and a few blocks plus
 * a remainder. Padding bugs live at "exactly a block" (where PKCS#7 adds a whole extra one) and stream
 * modes break on a partial final block, so a suite that only tried 32 bytes would pass while both were
 * wrong.
 */
const LENGTHS = [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 100] as const;

function checkAgainstOpenssl(options: {
  label: string;
  cipher: (key: Uint8Array) => BlockCipher;
  key: Uint8Array;
  openssl: (mode: BlockMode) => string | undefined;
  modes: readonly BlockMode[];
}): void {
  const { label, cipher, key, openssl, modes } = options;

  for (const mode of modes) {
    const algorithm = openssl(mode);
    if (algorithm === undefined) continue;
    const needsIv = mode !== "ecb";
    const pads = mode === "ecb" || mode === "cbc";

    it(`${label} ${mode.toUpperCase()} matches OpenSSL's ${algorithm}`, () => {
      const instance = cipher(key);
      const iv = needsIv ? pseudoRandom(instance.blockSize, 99) : null;

      for (const length of LENGTHS) {
        // OpenSSL will not encrypt an empty input without padding: there is nothing to emit and
        // nothing to pad to, so the comparison has nothing to compare.
        if (length === 0 && !pads) continue;
        const data = pseudoRandom(length, length + 1);

        const ours = encryptBlockMode(instance, mode, data, {
          ...(iv ? { iv } : {}),
        });
        const theirs = opensslEncrypt(algorithm, key, iv, data, pads);
        expect(toHex(ours), `${label}/${mode}/${length} encrypt`).toBe(toHex(theirs));

        // And back, through the other implementation's output, which is what proves the two agree
        // rather than merely producing the same length.
        const back = decryptBlockMode(instance, mode, theirs, { ...(iv ? { iv } : {}) });
        expect(toHex(back), `${label}/${mode}/${length} decrypt`).toBe(toHex(data));

        const theirsBack = opensslDecrypt(algorithm, key, iv, ours, pads);
        expect(toHex(theirsBack), `${label}/${mode}/${length} openssl decrypt`).toBe(toHex(data));
      }
    });
  }
}

describe("Triple DES against OpenSSL", () => {
  // 24-byte key: OpenSSL's des-ede3.
  checkAgainstOpenssl({
    label: "3DES (3-key)",
    cipher: createTripleDes,
    key: pseudoRandom(24, 7),
    // No CTR: OpenSSL exposes no des-ede3-ctr, and 3DES-CTR is not a standardised combination, so
    // there would be nothing to check it against.
    modes: ["ecb", "cbc", "cfb", "ofb"],
    openssl: (mode) => `des-ede3-${mode}`,
  });

  // 16-byte key: the two-key variant, K3 = K1. OpenSSL calls it des-ede.
  checkAgainstOpenssl({
    label: "3DES (2-key)",
    cipher: createTripleDes,
    key: pseudoRandom(16, 11),
    modes: ["ecb", "cbc", "cfb", "ofb"],
    openssl: (mode) => `des-ede-${mode}`,
  });
});

describe("SM4 against OpenSSL", () => {
  checkAgainstOpenssl({
    label: "SM4",
    cipher: createSm4,
    key: pseudoRandom(16, 13),
    // All five, because OpenSSL exposes all five for SM4.
    modes: ["ecb", "cbc", "cfb", "ofb", "ctr"],
    openssl: (mode) => `sm4-${mode}`,
  });

  it("matches the worked example in GB/T 32907-2016", () => {
    // The standard's own vector, where the key and the plaintext are the same 16 bytes. OpenSSL
    // reproduces it too, so this line is checked twice over by two independent routes.
    const sm4 = createSm4(fromHex("0123456789abcdeffedcba9876543210"));
    const out = new Uint8Array(16);
    sm4.encryptBlock(fromHex("0123456789abcdeffedcba9876543210"), out);
    expect(toHex(out)).toBe("681edf34d206965e86b3e94f536e4246");

    const back = new Uint8Array(16);
    sm4.decryptBlock(out, back);
    expect(toHex(back)).toBe("0123456789abcdeffedcba9876543210");
  });

  it("refuses a key that is not 16 bytes", () => {
    expect(() => createSm4(new Uint8Array(24))).toThrow(/16-byte key/);
  });
});

describe("single DES", () => {
  it("matches the published FIPS vector", () => {
    // The worked example every DES description quotes: "Now is t" under key 0123456789ABCDEF.
    const des = createDes(fromHex("0123456789abcdef"));
    const out = new Uint8Array(8);
    des.encryptBlock(fromHex("4e6f772069732074"), out);
    expect(toHex(out)).toBe("3fa40e8a984d4815");

    const back = new Uint8Array(8);
    des.decryptBlock(out, back);
    expect(toHex(back)).toBe("4e6f772069732074");
  });

  it("is exactly 3DES with all three keys equal", () => {
    /**
     * The identity that gives single DES an oracle it would otherwise lack.
     *
     * EDE with K1 == K2 == K3 collapses: the middle decryption undoes the first encryption. So this
     * assertion carries single DES on the back of the 3DES comparison above, which OpenSSL does check
     * -- and it is also the property that lets a 3DES implementation read single-DES data, which is
     * why the mode exists in that order at all.
     */
    const key = fromHex("133457799bbcdff1");
    const single = createDes(key);
    const tripled = createTripleDes(new Uint8Array([...key, ...key, ...key]));

    for (const length of [8, 16, 64]) {
      const data = pseudoRandom(length, length);
      const iv = pseudoRandom(8, 5);
      for (const mode of ["ecb", "cbc", "cfb", "ofb"] as const) {
        const a = encryptBlockMode(single, mode, data, mode === "ecb" ? {} : { iv });
        const b = encryptBlockMode(tripled, mode, data, mode === "ecb" ? {} : { iv });
        expect(toHex(a), `${mode}/${length}`).toBe(toHex(b));
      }
    }
  });

  it("names the weak keys without refusing them", () => {
    // Legal keys that make DES its own inverse. Reported by a lint rule rather than blocked, in
    // keeping with "refuse only what the algorithm genuinely cannot do".
    expect(isWeakDesKey(fromHex("0101010101010101"))).toBe(true);
    expect(isWeakDesKey(fromHex("FEFEFEFEFEFEFEFE"))).toBe(true);
    expect(isWeakDesKey(fromHex("01fe01fe01fe01fe"))).toBe(true);
    expect(isWeakDesKey(fromHex("133457799bbcdff1"))).toBe(false);

    // And the defining property of a weak key: encrypting twice returns the plaintext.
    const weak = createDes(fromHex("0101010101010101"));
    const once = new Uint8Array(8);
    const twice = new Uint8Array(8);
    weak.encryptBlock(fromHex("0011223344556677"), once);
    weak.encryptBlock(once, twice);
    expect(toHex(twice)).toBe("0011223344556677");
  });

  it("refuses a key of the wrong length, saying what it wanted", () => {
    expect(() => createDes(new Uint8Array(7))).toThrow(/8-byte key/);
    expect(() => createTripleDes(new Uint8Array(8))).toThrow(/16- or 24-byte key/);
  });
});

describe("PKCS#7", () => {
  it("adds a whole block when the input already fits", () => {
    // Not waste: without it, a message ending in 0x01 could not be told from one padded by a byte.
    expect(toHex(padPkcs7(fromHex("0011223344556677"), 8))).toBe(
      "00112233445566770808080808080808",
    );
    expect(toHex(padPkcs7(new Uint8Array(0), 8))).toBe("0808080808080808");
  });

  it("round-trips at every offset for both block sizes", () => {
    for (const blockSize of [8, 16]) {
      for (let length = 0; length < 40; length++) {
        const data = pseudoRandom(length, length + 3);
        const padded = padPkcs7(data, blockSize);
        expect(padded.length % blockSize, `${blockSize}/${length}`).toBe(0);
        expect(toHex(unpadPkcs7(padded, blockSize)), `${blockSize}/${length}`).toBe(toHex(data));
      }
    }
  });

  it("agrees with OpenSSL about what padding a message gets", () => {
    // Checked through a cipher, because that is the only place the padding is observable: encrypt
    // without padding on our side and with padding on theirs, and the ciphertexts match only if the
    // padded plaintexts did.
    const key = pseudoRandom(24, 21);
    const cipher = createTripleDes(key);
    for (const length of [0, 1, 7, 8, 9, 16]) {
      const data = pseudoRandom(length, length + 9);
      const ours = encryptBlockMode(cipher, "ecb", padPkcs7(data, 8), { padding: "none" });
      const theirs = opensslEncrypt("des-ede3-ecb", key, null, data, true);
      expect(toHex(ours), `length ${length}`).toBe(toHex(theirs));
    }
  });

  it("rejects invalid padding rather than returning plausible garbage", () => {
    // What a wrong key produces. Returning whatever the last byte claims would hand back a
    // meaningless plaintext of a believable length, which is worse than an error.
    expect(() => unpadPkcs7(fromHex("0011223344556609"), 8)).toThrow(/not valid/);
    expect(() => unpadPkcs7(fromHex("0011223344556600"), 8)).toThrow(/not valid/);
    expect(() => unpadPkcs7(fromHex("0011223344550303"), 8)).toThrow(/not valid/);
    expect(() => unpadPkcs7(fromHex("00112233"), 8)).toThrow(/whole number/);
  });
});

describe("the mode layer's own rules", () => {
  const cipher = createTripleDes(pseudoRandom(24, 3));

  it("needs an IV of exactly one block, and says so", () => {
    for (const mode of ["cbc", "cfb", "ofb", "ctr"] as const) {
      expect(() => encryptBlockMode(cipher, mode, new Uint8Array(8), {})).toThrow(/needs an IV/);
      expect(() =>
        encryptBlockMode(cipher, mode, new Uint8Array(8), { iv: new Uint8Array(4) }),
      ).toThrow(/exactly 8 bytes/);
    }
  });

  it("takes no IV for ECB, which is the whole problem with it", () => {
    // Identical plaintext blocks give identical ciphertext blocks. Asserted because it is the
    // observable form of the thing `C001` warns about.
    const doubled = new Uint8Array(16);
    doubled.set(fromHex("0011223344556677"), 0);
    doubled.set(fromHex("0011223344556677"), 8);
    const out = toHex(encryptBlockMode(cipher, "ecb", doubled, { padding: "none" }));
    expect(out.slice(0, 16)).toBe(out.slice(16, 32));
  });

  it("CTR is its own inverse and increments the whole block", () => {
    // No OpenSSL des-ede3-ctr to compare against, so the two properties that matter are asserted
    // directly: symmetry, and that the counter carries past 0xff rather than stopping.
    const iv = fromHex("00000000000000ff");
    const data = pseudoRandom(24, 31);
    const encrypted = encryptBlockMode(cipher, "ctr", data, { iv });
    expect(toHex(decryptBlockMode(cipher, "ctr", encrypted, { iv }))).toBe(toHex(data));

    // Blocks 2 and 3 use counters 0x...0100 and 0x...0101; a carry that failed would repeat 0x...00ff
    // and produce a repeated keystream, so the two 8-byte halves would relate to each other.
    const zeros = new Uint8Array(24);
    const keystream = toHex(encryptBlockMode(cipher, "ctr", zeros, { iv }));
    expect(new Set([keystream.slice(0, 16), keystream.slice(16, 32), keystream.slice(32)]).size).toBe(
      3,
    );
  });

  it("CFB and OFB leave the length alone", () => {
    // The reason they are the modes to use when a ciphertext has to be the size of its plaintext.
    for (const mode of ["cfb", "ofb", "ctr"] as const) {
      for (const length of [1, 7, 9, 100]) {
        const data = pseudoRandom(length, length);
        const out = encryptBlockMode(cipher, mode, data, { iv: pseudoRandom(8, 1) });
        expect(out.length, `${mode}/${length}`).toBe(length);
      }
    }
  });
});
