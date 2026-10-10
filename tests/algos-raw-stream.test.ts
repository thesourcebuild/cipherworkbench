import { describe, expect, it } from "vitest";
import { chacha8, chacha12, chacha20, chacha20orig } from "@noble/ciphers/chacha.js";
import { salsa20, xsalsa20 } from "@noble/ciphers/salsa.js";
import {
  a51Crypt,
  a51Encrypt,
  a52Encrypt,
  crypto1Crypt,
  dectDscCrypt,
  geaCrypt,
  grain128,
  grainV1,
  hc128,
  hc256,
  isaacCrypt,
  mickeyEncrypt,
  pcg64Crypt,
  rabbitCrypt,
  rc4,
  rc4DropCrypt,
  snow3gCrypt,
  snowVCrypt,
  sosemanukCrypt,
  spritzCrypt,
  triviumCrypt,
  xoshiro256Crypt,
  zuc,
} from "@ocs/algos";
import {
  RAW_STREAM_CIPHER_IDS,
  createRawStreamCipher,
  type RawStreamCipherId,
  type RawStreamCipherOptions,
} from "@ocs/algos/raw-stream";

const bytes = (length: number, salt: number): Uint8Array =>
  Uint8Array.from({ length }, (_, i) => (i * 197 + salt * 131 + (i >>> 3)) & 0xff);

const hex = (value: string): Uint8Array =>
  Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));

const frameNumber = (nonce: Uint8Array): number =>
  (nonce[0] ?? 0) | ((nonce[1] ?? 0) << 8) | ((nonce[2] ?? 0) << 16);

const equalBytes = (left: Uint8Array, right: Uint8Array): boolean => {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i++) if (left[i] !== right[i]) return false;
  return true;
};

interface ParityCase {
  id: RawStreamCipherId;
  key: Uint8Array;
  nonce: Uint8Array;
  options?: RawStreamCipherOptions;
  oneShot(data: Uint8Array): Uint8Array;
}

const cases: ParityCase[] = [
  {
    id: "chacha20",
    key: bytes(32, 1),
    nonce: bytes(12, 2),
    options: { counter: 7 },
    oneShot: (data) => chacha20(bytes(32, 1), bytes(12, 2), data, undefined, 7),
  },
  {
    id: "chacha12",
    key: bytes(32, 3),
    nonce: bytes(12, 4),
    options: { counter: 11 },
    oneShot: (data) => chacha12(bytes(32, 3), bytes(12, 4), data, undefined, 11),
  },
  {
    id: "chacha8",
    key: bytes(32, 5),
    nonce: bytes(12, 6),
    options: { counter: 13 },
    oneShot: (data) => chacha8(bytes(32, 5), bytes(12, 6), data, undefined, 13),
  },
  {
    id: "chacha20orig",
    key: bytes(32, 7),
    nonce: bytes(8, 8),
    options: { counter: 17 },
    oneShot: (data) => chacha20orig(bytes(32, 7), bytes(8, 8), data, undefined, 17),
  },
  {
    id: "salsa20",
    key: bytes(32, 9),
    nonce: bytes(8, 10),
    oneShot: (data) => salsa20(bytes(32, 9), bytes(8, 10), data),
  },
  {
    id: "xsalsa20",
    key: bytes(32, 11),
    nonce: bytes(24, 12),
    oneShot: (data) => xsalsa20(bytes(32, 11), bytes(24, 12), data),
  },
  {
    id: "zuc128",
    key: bytes(16, 13),
    nonce: bytes(16, 14),
    oneShot: (data) => zuc("zuc128", bytes(16, 13), bytes(16, 14), data),
  },
  {
    id: "zuc256",
    key: bytes(32, 15),
    nonce: bytes(25, 16),
    oneShot: (data) => zuc("zuc256", bytes(32, 15), bytes(25, 16), data),
  },
  {
    id: "hc128",
    key: bytes(16, 17),
    nonce: bytes(16, 18),
    oneShot: (data) => hc128(bytes(16, 17), bytes(16, 18), data),
  },
  {
    id: "hc256",
    key: bytes(32, 19),
    nonce: bytes(32, 20),
    oneShot: (data) => hc256(bytes(32, 19), bytes(32, 20), data),
  },
  {
    id: "grainv1",
    key: bytes(10, 21),
    nonce: bytes(8, 22),
    oneShot: (data) => grainV1(bytes(10, 21), bytes(8, 22), data),
  },
  {
    id: "grain128",
    key: bytes(16, 23),
    nonce: bytes(12, 24),
    oneShot: (data) => grain128(bytes(16, 23), bytes(12, 24), data),
  },
  {
    id: "rabbit",
    key: bytes(16, 25),
    nonce: bytes(8, 26),
    oneShot: (data) => rabbitCrypt(bytes(16, 25), bytes(8, 26), data),
  },
  {
    id: "trivium",
    key: bytes(10, 27),
    nonce: bytes(10, 28),
    oneShot: (data) => triviumCrypt(bytes(10, 27), bytes(10, 28), data),
  },
  {
    id: "sosemanuk",
    key: bytes(16, 29),
    nonce: bytes(16, 30),
    oneShot: (data) => sosemanukCrypt(bytes(16, 29), bytes(16, 30), data),
  },
  {
    id: "snow3g",
    key: bytes(16, 31),
    nonce: bytes(16, 32),
    oneShot: (data) => snow3gCrypt(bytes(16, 31), bytes(16, 32), data),
  },
  {
    id: "snow-v",
    key: bytes(32, 33),
    nonce: bytes(16, 34),
    oneShot: (data) => snowVCrypt(bytes(32, 33), bytes(16, 34), data),
  },
  {
    id: "a5-1",
    key: bytes(8, 35),
    nonce: bytes(3, 36),
    oneShot: (data) => a51Encrypt(bytes(8, 35), frameNumber(bytes(3, 36)), data),
  },
  {
    id: "rc4-drop",
    key: bytes(16, 37),
    nonce: new Uint8Array(0),
    oneShot: (data) => rc4DropCrypt(bytes(16, 37), 768, data),
  },
  {
    id: "isaac",
    key: bytes(32, 38),
    nonce: new Uint8Array(0),
    oneShot: (data) => isaacCrypt(bytes(32, 38), data),
  },
  {
    id: "pcg64",
    key: bytes(16, 39),
    nonce: new Uint8Array(0),
    oneShot: (data) => pcg64Crypt(bytes(16, 39), data),
  },
  {
    id: "xoshiro256",
    key: bytes(32, 40),
    nonce: new Uint8Array(0),
    oneShot: (data) => xoshiro256Crypt(bytes(32, 40), data),
  },
  {
    id: "spritz",
    key: bytes(16, 41),
    nonce: bytes(8, 42),
    oneShot: (data) => spritzCrypt(bytes(16, 41), bytes(8, 42), data),
  },
  {
    id: "crypto1",
    key: bytes(6, 43),
    nonce: bytes(4, 44),
    oneShot: (data) => crypto1Crypt(bytes(6, 43), bytes(4, 44), data),
  },
  {
    id: "dect-dsc",
    key: bytes(8, 44),
    nonce: bytes(5, 45),
    oneShot: (data) => dectDscCrypt(bytes(8, 44), bytes(5, 45), data),
  },
  {
    id: "gea",
    key: bytes(8, 46),
    nonce: bytes(4, 47),
    oneShot: (data) => geaCrypt(bytes(8, 46), bytes(4, 47), data),
  },
  {
    id: "mickey",
    key: bytes(10, 48),
    nonce: bytes(10, 49),
    oneShot: (data) => mickeyEncrypt(bytes(10, 48), bytes(10, 49), data),
  },
  {
    id: "a5-2",
    key: bytes(8, 50),
    nonce: bytes(3, 51),
    oneShot: (data) => a52Encrypt(bytes(8, 50), frameNumber(bytes(3, 51)), data),
  },
  {
    id: "rc4",
    key: bytes(16, 52),
    nonce: new Uint8Array(0),
    options: { drop: 3072 },
    oneShot: (data) => rc4(bytes(16, 52), data, 3072),
  },
];

function fragmented(
  testCase: ParityCase,
  input: Uint8Array,
  sizes: readonly number[],
): Uint8Array {
  const engine = createRawStreamCipher(
    testCase.id,
    testCase.key,
    testCase.nonce,
    testCase.options,
  );
  const output = new Uint8Array(input.length);
  expect(engine.process(new Uint8Array(0))).toHaveLength(0);
  let at = 0;
  let sizeAt = 0;
  while (at < input.length) {
    const length = Math.min(sizes[sizeAt++ % sizes.length]!, input.length - at);
    const chunk = engine.process(input.subarray(at, at + length));
    expect(chunk).toHaveLength(length);
    output.set(chunk, at);
    at += length;
    if ((sizeAt & 3) === 0) expect(engine.process(new Uint8Array(0))).toHaveLength(0);
  }
  return output;
}

describe("incremental raw stream ciphers", () => {
  it("matches the published GSM A5/1 downlink vector", () => {
    // Marc Briceno, Ian Goldberg and David Wagner's pedagogical A5/1 reference:
    // Kc bytes=12 23 45 67 89 ab cd ef, COUNT=0x134, first 114 A-to-B bits.
    const actual = a51Crypt(hex("1223456789abcdef"), 0x134, 15);
    const expected = hex("534eaa582fe8151ab6e1855a728c00");
    expect(actual.subarray(0, 14)).toEqual(expected.subarray(0, 14));
    expect(actual[14]! & 0xc0).toBe(expected[14]);
  });

  it("matches the published SNOW-V pattern vector", () => {
    // Ekdahl et al., "A new SNOW stream cipher called SNOW-V", ePrint 2018/1143,
    // reference key/IV and first 128 keystream bytes.
    const key = hex("505152535455565758595a5b5c5d5e5f0a1a2a3a4a5a6a7a8a9aaabacadaeafa");
    const iv = hex("0123456789abcdeffedcba9876543210");
    const expected = hex(
      "aa81eafb8b8616ce3e5ce2222461c50a6ab4487756de4bd31c904f3d978afe56" +
        "334f10dddf2b9531769a71050be4385fc2b6192c7a857be8b4fc28b709f08f11" +
        "f20649e2eef24980f86c4c113641fed2f3f6fa2b91951206b801db15466517a6" +
        "330adda6b35b265efd722e8677b48bfc15b44118de52d073b0ad0fe7594d6291",
    );
    expect(snowVCrypt(key, iv, new Uint8Array(expected.length))).toEqual(expected);
  });

  it("matches Jenkins's seeded ISAAC result page and byte order", () => {
    // Bob Jenkins's randvect.txt prints the second generated page in ascending array order.
    // rand() consumes each page in reverse; these are that page's final eight words, reversed
    // and serialized little-endian after skipping the first 256 standard outputs.
    const stream = isaacCrypt(new Uint8Array(1024), new Uint8Array(1024 + 32));
    expect(stream.subarray(1024)).toEqual(
      hex("0f71687adaab54655707c1905f435e0bb81f7dafd33f9101108d156a4afdf6b8"),
    );
  });

  it("covers exactly every raw stream tool id", () => {
    expect(cases.map((testCase) => testCase.id)).toEqual([...RAW_STREAM_CIPHER_IDS]);
  });

  it("matches one-shot output across arbitrary byte boundaries", () => {
    const input = bytes(2053, 91);
    const boundaries = [1, 2, 3, 5, 7, 15, 16, 17, 31, 63, 64, 65, 127, 257] as const;
    for (const testCase of cases) {
      const expected = testCase.oneShot(input);
      expect(
        createRawStreamCipher(
          testCase.id,
          testCase.key,
          testCase.nonce,
          testCase.options,
        ).process(input),
        `${testCase.id}: single update`,
      ).toEqual(expected);
      expect(
        fragmented(testCase, input, boundaries),
        `${testCase.id}: fragmented updates`,
      ).toEqual(expected);
    }
  });

  it("continues ISAAC after its first 1,024-byte result page", () => {
    const seed = bytes(32, 73);
    const stream = isaacCrypt(seed, new Uint8Array(4096));
    expect(stream.subarray(0, 1024)).not.toEqual(stream.subarray(1024, 2048));

    const testCase = cases.find((candidate) => candidate.id === "isaac")!;
    const input = bytes(4096, 74);
    expect(fragmented({ ...testCase, key: seed }, input, [1023, 1, 2, 1025, 7])).toEqual(
      isaacCrypt(seed, input),
    );
  });

  it("absorbs Crypto-1's 32-bit initialization value", () => {
    const key = hex("a0a1a2a3a4a5");
    const input = new Uint8Array(32);
    const first = crypto1Crypt(key, hex("01020304"), input);
    const second = crypto1Crypt(key, hex("01020305"), input);
    expect(first).not.toEqual(second);
    expect(createRawStreamCipher("crypto1", key, hex("01020304")).process(input)).toEqual(
      first,
    );
  });

  it("streams representative multi-megabyte inputs without retaining prior chunks", () => {
    const input = bytes(3 * 1024 * 1024 + 37, 99);
    for (const id of ["chacha20", "rc4"] as const) {
      const testCase = cases.find((candidate) => candidate.id === id)!;
      const actual = fragmented(testCase, input, [8191, 65536, 3, 131071]);
      expect(equalBytes(actual, testCase.oneShot(input)), id).toBe(true);
    }
  });
});
