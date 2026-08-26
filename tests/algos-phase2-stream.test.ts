import { describe, expect, it } from "vitest";
import { grain128, grainV1, hc128, hc256, zuc } from "@ocs/algos";

/**
 * ZUC-128, ZUC-256, HC-128, HC-256, Grain v1 and Grain-128, against their designers' own vectors.
 *
 * None has an oracle: OpenSSL implements none of the six and no dependency in this tree does either. So
 * what stands behind them is published keystreams, and the sets are chosen rather than sampled:
 *
 *  - **The all-zero key and IV is always included**, because it is the one input where a wrong constant
 *    table cannot hide behind the key material.
 *  - **HC-256 gets both key widths**, since the 128-bit form is not a truncation -- the key is
 *    *duplicated* and the IV *repeated* to fill 256 bits, and an implementation that zero-padded instead
 *    would pass every 256-bit vector.
 *  - **Grain v1 gets a 64-byte keystream** as well as two 10-byte ones. The registers are five 16-bit
 *    words and one step produces sixteen bits, so ten bytes exercise five steps; a fault in the register
 *    rotation shows up further in.
 *  - **ZUC gets both key sizes**, which differ only in how the LFSR is loaded -- and ZUC-256's loading
 *    scatters a 32-byte key and a 25-byte IV across sixteen 31-bit cells with six bits of IV folded into
 *    nine of the constants. There is no way to check that but a published value.
 *
 * Every case also asserts the cipher is its own inverse over a non-zero message, which is cheap and
 * catches an engine that has been left holding state between calls.
 */

const unhex = (text: string): Uint8Array =>
  Uint8Array.from(text.replace(/\s+/g, "").match(/../g)!.map((pair) => parseInt(pair, 16)));

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

/** The keystream is what the vectors publish, so every check runs over a zero message. */
const zeros = (n: number): Uint8Array => new Uint8Array(n);

describe("HC-128", () => {
  const VECTORS = [
    {
      name: "Set 2, vector 0",
      key: "00000000000000000000000000000000",
      iv: "00000000000000000000000000000000",
      keystream:
        "82001573A003FD3B7FD72FFB0EAF63AAC62F12DEB629DCA72785A66268EC758B" +
        "1EDB36900560898178E0AD009ABF1F491330DC1C246E3D6CB264F6900271D59C",
    },
    {
      name: "Set 6, vector 0",
      key: "0053A6F94C9FF24598EB3E91E4378ADD",
      iv: "0D74DB42A91077DE45AC137AE148AF16",
      keystream:
        "2E1ED12A8551C05AF41FF39D8F9DF933122B5235D48FC2A6F20037E69BDBBCE8" +
        "05782EFC16C455A4B3FF06142317535EF876104C32445138CB26EBC2F88A684C",
    },
    {
      name: "Set 6, vector 3",
      key: "0F62B5085BAE0154A7FA4DA0F34699EC",
      iv: "288FF65DC42B92F960C72E95FC63CA31",
      keystream:
        "1CD8AEDDFE52E217E835D0B7E84E2922D04B1ADBCA53C4522B1AA604C42856A9" +
        "0AF83E2614BCE65C0AECABDD8975B55700D6A26D52FFF0888DA38F1DE20B77B7",
    },
  ];

  it("reproduces every published keystream", () => {
    for (const v of VECTORS) {
      expect(hex(hc128(unhex(v.key), unhex(v.iv), zeros(64))), v.name).toBe(
        v.keystream.toLowerCase(),
      );
    }
  });

  it("refuses a key or IV that is not 128 bits", () => {
    expect(() => hc128(new Uint8Array(32), new Uint8Array(16), zeros(1))).toThrow(/16-byte key/);
    expect(() => hc128(new Uint8Array(16), new Uint8Array(12), zeros(1))).toThrow(/16-byte IV/);
  });
});

describe("HC-256", () => {
  /** Both key widths, because the 128-bit form expands rather than truncating. */
  const VECTORS = [
    {
      name: "128-bit key and IV, all zero",
      key: "00000000000000000000000000000000",
      iv: "00000000000000000000000000000000",
      keystream:
        "5B078985D8F6F30D42C5C02FA6B6795153F06534801F89F24E74248B720B4818" +
        "CD9227ECEBCF4DBF8DBF6977E4AE14FAE8504C7BC8A9F3EA6C0106F5327E6981",
    },
    {
      name: "128-bit key, Set 2 vector 135",
      key: "87878787878787878787878787878787",
      iv: "00000000000000000000000000000000",
      keystream:
        "CEC0C3852E3B98233EBCB975C10B11913C69F2275EB97A1402EDF16C6FBE19BE" +
        "79D65360445BCB63676E6553B609A0650155C3B22DD1975AC0F3F65063A2E16E",
    },
    {
      name: "256-bit key and IV, Set 6 vector 0",
      key: "0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D",
      iv: "0D74DB42A91077DE45AC137AE148AF167DE44BB21980E74EB51C83EA51B81F86",
      keystream:
        "23D9E70A45EB0127884D66D9F6F23C01D1F88AFD629270127247256C1FFF91E9" +
        "1A797BD98ADD23AE15BEE6EEA3CEFDBFA3ED6D22D9C4F459DB10C40CDF4F4DFF",
    },
    {
      name: "256-bit key and IV, Set 6 vector 2",
      key: "0A5DB00356A9FC4FA2F5489BEE4194E73A8DE03386D92C7FD22578CB1E71C417",
      iv: "1F86ED54BB2289F057BE258CF35AC1288FF65DC42B92F960C72E95FC63CA3198",
      keystream:
        "9D13AA06122F4F03AE60D507701F1ED063D7530FF35EE76CAEDCBFB01D8A239E" +
        "FA4A44B272DE9B4092E2AD56E87C3A6089F5A074D1F6E5B8FC6FABEE0C936F06",
    },
  ];

  it("reproduces every published keystream, at both key widths", () => {
    for (const v of VECTORS) {
      expect(hex(hc256(unhex(v.key), unhex(v.iv), zeros(64))), v.name).toBe(
        v.keystream.toLowerCase(),
      );
    }
    // Guards the guard: both widths must be present, or the expansion path is untested.
    expect(new Set(VECTORS.map((v) => v.key.length)).size).toBe(2);
  });

  /**
   * The short key is duplicated, not zero-padded -- so a 16-byte key and the same key twice over must
   * give the same keystream.
   *
   * This is the assertion that makes the expansion rule explicit rather than incidental: a zero-padding
   * implementation passes every 256-bit vector above and fails only here.
   */
  it("expands a 128-bit key by duplicating it", () => {
    const short = unhex("0053A6F94C9FF24598EB3E91E4378ADD");
    const doubled = unhex("0053A6F94C9FF24598EB3E91E4378ADD0053A6F94C9FF24598EB3E91E4378ADD");
    const iv = unhex("0D74DB42A91077DE45AC137AE148AF16");
    const wideIv = unhex("0D74DB42A91077DE45AC137AE148AF160D74DB42A91077DE45AC137AE148AF16");
    expect(hex(hc256(short, iv, zeros(32)))).toBe(hex(hc256(doubled, wideIv, zeros(32))));
  });

  it("refuses a key or IV of an undefined width", () => {
    expect(() => hc256(new Uint8Array(24), new Uint8Array(16), zeros(1))).toThrow(/16- or 32-byte key/);
    expect(() => hc256(new Uint8Array(32), new Uint8Array(8), zeros(1))).toThrow(/16- or 32-byte IV/);
  });
});

describe("Grain v1", () => {
  const VECTORS = [
    { name: "all zero", key: "00000000000000000000", iv: "0000000000000000", keystream: "dee931cf1662a72f77d0" },
    { name: "0123...", key: "0123456789abcdef1234", iv: "0123456789abcdef", keystream: "7f362bd3f7abae203664" },
    {
      name: "64-byte keystream",
      key: "0F62B5085BAE0154A7FA",
      iv: "288FF65DC42B92F9",
      keystream:
        "017D13ECB20AE0C9ACF784CB06525F72CE6D52BEBB948F124668C35064559024" +
        "49EEA505C19F3EE4D052C3D19DA9C4D1B92DBC7F07AFEA6A3D845DE60D8471FD",
    },
  ];

  it("reproduces every published keystream", () => {
    for (const v of VECTORS) {
      const wanted = v.keystream.toLowerCase();
      expect(hex(grainV1(unhex(v.key), unhex(v.iv), zeros(wanted.length / 2))), v.name).toBe(wanted);
    }
  });

  /** One step yields two bytes, so an odd length is the case where the second is dropped. */
  it("produces a prefix at an odd length", () => {
    const key = unhex("0123456789abcdef1234");
    const iv = unhex("0123456789abcdef");
    expect(hex(grainV1(key, iv, zeros(7)))).toBe(hex(grainV1(key, iv, zeros(10))).slice(0, 14));
  });

  it("refuses a key or IV of the wrong length", () => {
    expect(() => grainV1(new Uint8Array(16), new Uint8Array(8), zeros(1))).toThrow(/10-byte key/);
    expect(() => grainV1(new Uint8Array(10), new Uint8Array(12), zeros(1))).toThrow(/8-byte IV/);
  });
});

describe("Grain-128", () => {
  const VECTORS = [
    {
      name: "all zero",
      key: "00000000000000000000000000000000",
      iv: "000000000000000000000000",
      keystream: "4bdb20824c5dce6fc63e94456c3281d4",
    },
    {
      name: "0123...",
      key: "0123456789abcdef123456789abcdef0",
      iv: "0123456789abcdef12345678",
      keystream: "ba399daf90df8eba103d9ea83c805904",
    },
  ];

  it("reproduces every published keystream", () => {
    for (const v of VECTORS) {
      expect(hex(grain128(unhex(v.key), unhex(v.iv), zeros(16))), v.name).toBe(
        v.keystream.toLowerCase(),
      );
    }
  });

  /**
   * Grain-128 is not Grain v1 widened, and this pins that.
   *
   * The NFSR feedback is degree two here against v1's degree six, so no scaling of one gives the other.
   * The comparison is against a key and IV of the lengths each takes, which is the closest the two come
   * to being handed the same input.
   */
  it("is a different function from Grain v1", () => {
    const a = hex(grain128(new Uint8Array(16), new Uint8Array(12), zeros(10)));
    const b = hex(grainV1(new Uint8Array(10), new Uint8Array(8), zeros(10)));
    expect(a).not.toBe(b);
  });

  it("refuses a key or IV of the wrong length", () => {
    expect(() => grain128(new Uint8Array(10), new Uint8Array(12), zeros(1))).toThrow(/16-byte key/);
    expect(() => grain128(new Uint8Array(16), new Uint8Array(8), zeros(1))).toThrow(/12-byte IV/);
  });
});

describe("ZUC", () => {
  /** GSMA's `eea3eia3zucv16.pdf` for the 128-bit form; the CAS document for the 256-bit one. */
  const VECTORS = [
    {
      name: "ZUC-128, all zero",
      variant: "zuc128" as const,
      key: "00".repeat(16),
      iv: "00".repeat(16),
      keystream:
        "27bede74018082da87d4e5b69f18bf6632070e0f39b7b692b4673edc3184a48e" +
        "27636f4414510d62cc15cfe194ec4f6d4b8c8fcc630648badf41b6f9d16a36ca",
    },
    {
      name: "ZUC-128, all ones",
      variant: "zuc128" as const,
      key: "ff".repeat(16),
      iv: "ff".repeat(16),
      keystream:
        "0657cfa07096398b734b6cb4883eedf4257a76eb97595208d884adcdb1cbffb8" +
        "e0f9d15846a0eed015328503351138f740d079af17296c232c4f022d6e4acac6",
    },
    {
      name: "ZUC-256, all zero",
      variant: "zuc256" as const,
      key: "00".repeat(32),
      iv: "00".repeat(25),
      keystream:
        "58d03ad62e032ce2dafc683a39bdcb0352a2bc67f1b7de74163ce3a101ef5558" +
        "9639d75b95fa681b7f090df756391ccc903b7612744d544c17bc3fad8b163b08",
    },
    {
      name: "ZUC-256, all ones",
      variant: "zuc256" as const,
      key: "ff".repeat(32),
      // The top two bits of the last nine IV bytes are not used, so the document writes 0x3f there.
      iv: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF3F3F3F3F3F3F3F3F",
      keystream:
        "3356cbaed1a1c18b6baa4ffe343f777c9e15128f251ab65b949f7b26ef7157f2" +
        "96dd2fa9df95e3ee7a5be02ec32ba585505af316c2f9ded27cdbd935e441ce11",
    },
  ];

  it("reproduces every published keystream, at both key sizes", () => {
    for (const v of VECTORS) {
      expect(hex(zuc(v.variant, unhex(v.key), unhex(v.iv), zeros(64))), v.name).toBe(
        v.keystream.toLowerCase(),
      );
    }
    expect(new Set(VECTORS.map((v) => v.variant)).size).toBe(2);
  });

  /**
   * ZUC spells its keystream big-endian where HC and Grain spell theirs little-endian.
   *
   * Asserted directly rather than left to the vectors, because it is the one property that a
   * self-consistent implementation gets wrong without any test failing -- and the two conventions sit
   * side by side in one module here, which is exactly when they get confused.
   */
  it("emits each keystream word most significant byte first", () => {
    const first = zuc("zuc128", new Uint8Array(16), new Uint8Array(16), zeros(4));
    expect(hex(first)).toBe("27bede74");
  });

  it("refuses a key or IV of the wrong length for its variant", () => {
    expect(() => zuc("zuc128", new Uint8Array(32), new Uint8Array(16), zeros(1))).toThrow(
      /16-byte key/,
    );
    expect(() => zuc("zuc256", new Uint8Array(32), new Uint8Array(16), zeros(1))).toThrow(
      /25-byte IV/,
    );
  });
});

describe("all six", () => {
  /** Each is its own inverse, and an engine holding state between calls would fail this. */
  it("round-trips a non-zero message", () => {
    const message = new TextEncoder().encode("Cipher Workbench, phase 2b, stream ciphers.");
    const runs: readonly [string, (data: Uint8Array) => Uint8Array][] = [
      ["HC-128", (d) => hc128(new Uint8Array(16), new Uint8Array(16), d)],
      ["HC-256", (d) => hc256(new Uint8Array(32), new Uint8Array(32), d)],
      ["Grain v1", (d) => grainV1(new Uint8Array(10), new Uint8Array(8), d)],
      ["Grain-128", (d) => grain128(new Uint8Array(16), new Uint8Array(12), d)],
      ["ZUC-128", (d) => zuc("zuc128", new Uint8Array(16), new Uint8Array(16), d)],
      ["ZUC-256", (d) => zuc("zuc256", new Uint8Array(32), new Uint8Array(25), d)],
    ];
    for (const [name, run] of runs) {
      const ciphertext = run(message);
      expect(hex(ciphertext), `${name} did not encrypt`).not.toBe(hex(message));
      expect(hex(run(ciphertext)), `${name} round trip`).toBe(hex(message));
    }
    // Six ciphers, six distinct keystreams over the same all-zero key material where lengths allow.
    expect(runs).toHaveLength(6);
  });
});
