import { describe, expect, it } from "vitest";
import {
  DEFAULT_HMAC_HASH,
  HMAC_HASHES,
  MAC_MANIFESTS,
  MAC_TOOLS,
  OPTION_CUSTOMIZATION,
  OPTION_HASH,
  OPTION_KEY,
  OPTION_KMAC_VARIANT,
  OPTION_OUTPUT_LENGTH,
  OPTION_SKEIN_STATE,
  OPTION_TRUNCATE,
  requireHmacHash,
  requireMacTool,
  type MacSpec,
} from "@ocs/mac";
import {
  applyAllFixes,
  createSpec,
  describeSpec,
  lint,
  macToolDefinition,
  resolveMac,
} from "@ocs/mac/definition";
import { MAC_TOOL_IDS } from "@ocs/mac";
import { encodeHex, isAvailableOn, rechunk, runStream, validateCatalogue } from "@ocs/engine";
// The hash family's eager metadata, for the one assertion that compares the two families' views of a
// hash's block size. Strings only -- no implementation is reachable from it.
import { HASH_ALGORITHMS } from "@ocs/hash";
// The same frozen golden values `tests/algos-nonchash.test.ts` checks the algorithm against.
import { HIGHWAY_128, HIGHWAY_256, HIGHWAY_64 } from "./nonchash-vectors";
import { hmac as nobleHmac } from "@noble/hashes/hmac.js";
import { blake2b, blake2s } from "@noble/hashes/blake2.js";
import { md5, ripemd160, sha1 } from "@noble/hashes/legacy.js";
import { sha224, sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { sha3_256, sha3_512 } from "@noble/hashes/sha3.js";
import { blake224, blake256, blake384, blake512 } from "@noble/hashes/blake1.js";
import { createSm3, skein, sm3, tiger } from "@ocs/algos";
import { SKEIN_MAC_VECTORS } from "./skein-mac-vectors";
import {
  ASCON_MAC_KAT,
  ASCON_PRF_KAT,
  ASCON_PRF_KAT_LEN,
  ASCON_PRF_SHORT_KAT,
  ASCON_PRF_SHORT_KAT_LEN,
  asconKeyedKatMessage,
} from "./ascon-keyed-kat";

const ascii = (text: string) => new TextEncoder().encode(text);
const fromHex = (hex: string) =>
  // The empty string is a legitimate input -- several golden-KAT vectors hash nothing at all.
  hex === "" ? new Uint8Array(0) : Uint8Array.from(hex.match(/../g)!.map((b) => parseInt(b, 16)));

function specFor(variant: string, options: MacSpec["options"] = {}): MacSpec {
  const base = createSpec({ variant });
  return { ...base, options: { ...base.options, ...options } };
}

/** A key as the `bytes` option stores it: hex text plus its encoding. */
function keyed(hex: string, extra: MacSpec["options"] = {}): MacSpec["options"] {
  return { [OPTION_KEY]: hex, keyEncoding: "hex", ...extra };
}

async function tag(variant: string, options: MacSpec["options"], message: Uint8Array) {
  const tool = macToolDefinition(variant);
  const result = await tool.compute(specFor(variant, options), message);
  expect(result.error, `${variant} reported: ${result.error}`).toBeUndefined();
  return encodeHex(result.bytes!);
}

// ── HMAC: RFC 4231 ──────────────────────────────────────────────────────────

describe("HMAC — RFC 4231 test cases", () => {
  /**
   * The published suite for HMAC-SHA-224/256/384/512. Cases 1-5 plus the two
   * oversized-key cases, which are the ones that exercise the key-hashing branch — a key
   * longer than the block is digested down first, and that path is easy to omit.
   */
  const CASES: readonly {
    name: string;
    key: string;
    data: string;
    sha256: string;
    sha512: string;
  }[] = [
    {
      name: "case 1 — 20-byte key",
      key: "0b".repeat(20),
      data: "4869205468657265",
      sha256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
      sha512:
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
    },
    {
      name: "case 2 — short key",
      key: "4a656665",
      data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
      sha256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
      sha512:
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
    },
    {
      name: "case 3 — 50 bytes of 0xdd",
      key: "aa".repeat(20),
      data: "dd".repeat(50),
      sha256: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
      sha512:
        "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
    },
    {
      name: "case 6 — 131-byte key, hashed down",
      key: "aa".repeat(131),
      data: "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374",
      sha256: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
      sha512:
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
    },
  ];

  for (const testCase of CASES) {
    it(`HMAC-SHA-256, ${testCase.name}`, async () => {
      expect(
        await tag(
          "hmac",
          keyed(testCase.key, { [OPTION_HASH]: "sha256" }),
          fromHex(testCase.data),
        ),
      ).toBe(testCase.sha256);
    });

    it(`HMAC-SHA-512, ${testCase.name}`, async () => {
      expect(
        await tag(
          "hmac",
          keyed(testCase.key, { [OPTION_HASH]: "sha512" }),
          fromHex(testCase.data),
        ),
      ).toBe(testCase.sha512);
    });
  }

  it("HMAC-SHA-1 matches RFC 2202 case 1", async () => {
    expect(
      await tag("hmac", keyed("0b".repeat(20), { [OPTION_HASH]: "sha1" }), ascii("Hi There")),
    ).toBe("b617318655057264e28bc0b6fb378c8ef146be00");
  });

  it("HMAC-MD5 matches RFC 2202 case 1", async () => {
    expect(
      await tag("hmac", keyed("0b".repeat(16), { [OPTION_HASH]: "md5" }), ascii("Hi There")),
    ).toBe("9294727a3638bb1c13f48ef8158bfc9d");
  });

  it("HMAC-SM3 agrees with an independently written HMAC over the same SM3", async () => {
    /**
     * HMAC-SM3 is the one HMAC path with its own code: SM3 is not a noble `CHash`, so
     * `bindings.ts` builds the construction directly from RFC 2104 rather than calling
     * noble's `hmac`. Code with no other caller needs its own check.
     *
     * The check is differential rather than a fixed vector. `nobleHmacOverSm3` below wraps
     * our SM3 in the shape noble's `hmac` expects, so noble's HMAC — separately written,
     * and validated against RFC 4231 by the cases above — computes the same construction
     * over the same compression function. Agreement means the hand-rolled ipad/opad
     * padding and key normalisation are right; it cannot be faked by a shared mistake,
     * because the two HMACs share no code.
     */
    for (const [keyHex, message] of [
      ["0b".repeat(32), "Hi There"],
      ["4a656665", "what do ya want for nothing?"],
      // A key longer than SM3's 64-byte block, to exercise the hash-the-key-down branch.
      ["aa".repeat(131), "Test Using Larger Than Block-Size Key"],
      // And one shorter than the block, to exercise zero-padding.
      ["ab", "short key"],
    ] as const) {
      const mine = await tag("hmac", keyed(keyHex, { [OPTION_HASH]: "sm3" }), ascii(message));
      expect(mine, `${keyHex.slice(0, 8)}… / ${message}`).toBe(
        encodeHex(nobleHmacOverSm3(fromHex(keyHex), ascii(message))),
      );
    }
  });

  it("HMAC-SM3 reproduces the RFC 2202 case-2 inputs", async () => {
    // The same key and message RFC 2202 uses for HMAC-MD5 case 2, under SM3. Recorded as a
    // fixed value so a regression shows up even if the differential check above were
    // removed.
    expect(
      await tag(
        "hmac",
        keyed("4a656665", { [OPTION_HASH]: "sm3" }),
        ascii("what do ya want for nothing?"),
      ),
    ).toBe("2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882");
  });

  it("produces a tag of the hash's length for every offered hash", async () => {
    for (const hash of HMAC_HASHES) {
      const result = await tag(
        "hmac",
        keyed("00".repeat(32), { [OPTION_HASH]: hash.id }),
        ascii("x"),
      );
      expect(result.length / 2, hash.id).toBe(hash.outputLen);
    }
  });
});

// ── KMAC: NIST SP 800-185 ───────────────────────────────────────────────────

describe("KMAC — NIST SP 800-185 samples", () => {
  const KEY = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
  const SHORT = "00010203";
  const LONG = Array.from({ length: 200 }, (_, i) => i.toString(16).padStart(2, "0")).join("");
  const CUSTOM = "My Tagged Application";

  it("KMAC128 sample 1 — no customization, 32-byte output", async () => {
    expect(
      await tag(
        "kmac",
        keyed(KEY, { [OPTION_KMAC_VARIANT]: "kmac128", [OPTION_OUTPUT_LENGTH]: 32 }),
        fromHex(SHORT),
      ),
    ).toBe("e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e");
  });

  it("KMAC128 sample 2 — with customization", async () => {
    expect(
      await tag(
        "kmac",
        keyed(KEY, {
          [OPTION_KMAC_VARIANT]: "kmac128",
          [OPTION_OUTPUT_LENGTH]: 32,
          [OPTION_CUSTOMIZATION]: CUSTOM,
        }),
        fromHex(SHORT),
      ),
    ).toBe("3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5");
  });

  it("KMAC256 sample 4 — customization, 64-byte output", async () => {
    expect(
      await tag(
        "kmac",
        keyed(KEY, {
          [OPTION_KMAC_VARIANT]: "kmac256",
          [OPTION_OUTPUT_LENGTH]: 64,
          [OPTION_CUSTOMIZATION]: CUSTOM,
        }),
        fromHex(SHORT),
      ),
    ).toBe(
      "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
    );
  });

  it("KMAC256 sample 5 — 200-byte message, no customization", async () => {
    expect(
      await tag(
        "kmac",
        keyed(KEY, { [OPTION_KMAC_VARIANT]: "kmac256", [OPTION_OUTPUT_LENGTH]: 64 }),
        fromHex(LONG),
      ),
    ).toBe(
      "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69",
    );
  });

  it("binds the output length into the computation, unlike HMAC truncation", async () => {
    /**
     * The distinction the `outputLength` help text makes, as an assertion. KMAC is built on
     * cSHAKE and the requested length is part of the domain separation, so asking for 32
     * bytes is NOT the same as asking for 64 and keeping the first 32. Getting this
     * backwards would produce values that look right and match nothing.
     */
    const short = await tag(
      "kmac",
      keyed(KEY, { [OPTION_KMAC_VARIANT]: "kmac128", [OPTION_OUTPUT_LENGTH]: 32 }),
      fromHex(SHORT),
    );
    const long = await tag(
      "kmac",
      keyed(KEY, { [OPTION_KMAC_VARIANT]: "kmac128", [OPTION_OUTPUT_LENGTH]: 64 }),
      fromHex(SHORT),
    );
    expect(long.slice(0, 64)).not.toBe(short);
  });

  it("gives unrelated tags for different customization strings under one key", async () => {
    const a = await tag(
      "kmac",
      keyed(KEY, { [OPTION_OUTPUT_LENGTH]: 32, [OPTION_CUSTOMIZATION]: "email" }),
      fromHex(SHORT),
    );
    const b = await tag(
      "kmac",
      keyed(KEY, { [OPTION_OUTPUT_LENGTH]: 32, [OPTION_CUSTOMIZATION]: "file" }),
      fromHex(SHORT),
    );
    expect(a).not.toBe(b);
  });
});

// ── Poly1305: RFC 8439 ──────────────────────────────────────────────────────

describe("Poly1305 — RFC 8439", () => {
  it("section 2.5.2 worked example", async () => {
    expect(
      await tag(
        "poly1305",
        keyed("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
        ascii("Cryptographic Forum Research Group"),
      ),
    ).toBe("a8061dc1305136c6c22b8baf0c0127a9");
  });

  it("always produces a 16-byte tag", async () => {
    for (const message of ["", "a", "x".repeat(17), "y".repeat(1000)]) {
      const result = await tag("poly1305", keyed("00".repeat(32)), ascii(message));
      expect(result.length, `message length ${message.length}`).toBe(32);
    }
  });

  it("refuses a key that is not exactly 32 bytes, naming the length given", async () => {
    const tool = macToolDefinition("poly1305");
    const result = await tool.compute(specFor("poly1305", keyed("00".repeat(16))), ascii("x"));
    expect(result.bytes).toBeUndefined();
    expect(result.error).toContain("32");
    expect(result.error).toContain("16");
  });
});

// ── AES-CMAC: RFC 4493 ──────────────────────────────────────────────────────

describe("AES-CMAC — RFC 4493 examples", () => {
  const K = "2b7e151628aed2a6abf7158809cf4f3c";

  it("example 1 — empty message", async () => {
    expect(await tag("cmac", keyed(K), new Uint8Array(0))).toBe(
      "bb1d6929e95937287fa37d129b756746",
    );
  });

  it("example 2 — one full block", async () => {
    expect(await tag("cmac", keyed(K), fromHex("6bc1bee22e409f96e93d7e117393172a"))).toBe(
      "070a16b46b4d4144f79bdd9dd04a287c",
    );
  });

  it("example 3 — a partial final block, exercising the second subkey", async () => {
    expect(
      await tag(
        "cmac",
        keyed(K),
        fromHex(
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
        ),
      ),
    ).toBe("dfa66747de9ae63030ca32611497c827");
  });

  it("accepts all three AES key sizes", async () => {
    for (const size of [16, 24, 32]) {
      const result = await tag("cmac", keyed("11".repeat(size)), ascii("x"));
      expect(result.length, `${size}-byte key`).toBe(32);
    }
  });

  it("refuses a 20-byte key", async () => {
    const tool = macToolDefinition("cmac");
    const result = await tool.compute(specFor("cmac", keyed("22".repeat(20))), ascii("x"));
    expect(result.error).toMatch(/16, 24, 32/);
  });
});

/**
 * Our SM3, wrapped in the shape noble's `hmac` expects, so noble can compute HMAC-SM3
 * independently of our own construction. Test-only — nothing in `packages/` does this.
 */
function nobleHmacOverSm3(key: Uint8Array, message: Uint8Array): Uint8Array {
  const chash = ((msg: Uint8Array) => sm3(msg)) as never as Parameters<typeof nobleHmac>[0];
  Object.assign(chash, {
    outputLen: 32,
    blockLen: 64,
    create: () => {
      const engine = createSm3();
      return {
        blockLen: 64,
        outputLen: 32,
        update(chunk: Uint8Array) {
          engine.update(chunk);
          return this;
        },
        digest: () => engine.digest(),
        digestInto(out: Uint8Array) {
          out.set(engine.digest());
          return out;
        },
        destroy() {},
        clone() {
          throw new Error("clone is not needed for this test");
        },
      };
    },
  });
  return nobleHmac(chash, key, message);
}

// ── KMAC: NIST SP 800-185 ───────────────────────────────────────────────────

describe("KMAC — NIST SP 800-185 samples", () => {
  const KEY = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
  const SHORT = "00010203";
  const LONG = Array.from({ length: 200 }, (_, i) => i.toString(16).padStart(2, "0")).join("");
  const CUSTOM = "My Tagged Application";

  it("KMAC128 sample 1 — no customization, 32-byte output", async () => {
    expect(
      await tag(
        "kmac",
        keyed(KEY, { [OPTION_KMAC_VARIANT]: "kmac128", [OPTION_OUTPUT_LENGTH]: 32 }),
        fromHex(SHORT),
      ),
    ).toBe("e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e");
  });

  it("KMAC128 sample 2 — with customization", async () => {
    expect(
      await tag(
        "kmac",
        keyed(KEY, {
          [OPTION_KMAC_VARIANT]: "kmac128",
          [OPTION_OUTPUT_LENGTH]: 32,
          [OPTION_CUSTOMIZATION]: CUSTOM,
        }),
        fromHex(SHORT),
      ),
    ).toBe("3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5");
  });

  it("KMAC256 sample 4 — customization, 64-byte output", async () => {
    expect(
      await tag(
        "kmac",
        keyed(KEY, {
          [OPTION_KMAC_VARIANT]: "kmac256",
          [OPTION_OUTPUT_LENGTH]: 64,
          [OPTION_CUSTOMIZATION]: CUSTOM,
        }),
        fromHex(SHORT),
      ),
    ).toBe(
      "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd",
    );
  });

  it("KMAC256 sample 5 — 200-byte message, no customization", async () => {
    expect(
      await tag(
        "kmac",
        keyed(KEY, { [OPTION_KMAC_VARIANT]: "kmac256", [OPTION_OUTPUT_LENGTH]: 64 }),
        fromHex(LONG),
      ),
    ).toBe(
      "75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69",
    );
  });

  it("binds the output length into the computation, unlike HMAC truncation", async () => {
    /**
     * The distinction the `outputLength` help text makes, as an assertion. KMAC is built on
     * cSHAKE and the requested length is part of the domain separation, so asking for 32
     * bytes is NOT the same as asking for 64 and keeping the first 32. Getting this
     * backwards would produce values that look right and match nothing.
     */
    const short = await tag(
      "kmac",
      keyed(KEY, { [OPTION_KMAC_VARIANT]: "kmac128", [OPTION_OUTPUT_LENGTH]: 32 }),
      fromHex(SHORT),
    );
    const long = await tag(
      "kmac",
      keyed(KEY, { [OPTION_KMAC_VARIANT]: "kmac128", [OPTION_OUTPUT_LENGTH]: 64 }),
      fromHex(SHORT),
    );
    expect(long.slice(0, 64)).not.toBe(short);
  });

  it("gives unrelated tags for different customization strings under one key", async () => {
    const a = await tag(
      "kmac",
      keyed(KEY, { [OPTION_OUTPUT_LENGTH]: 32, [OPTION_CUSTOMIZATION]: "email" }),
      fromHex(SHORT),
    );
    const b = await tag(
      "kmac",
      keyed(KEY, { [OPTION_OUTPUT_LENGTH]: 32, [OPTION_CUSTOMIZATION]: "file" }),
      fromHex(SHORT),
    );
    expect(a).not.toBe(b);
  });
});

// ── Poly1305: RFC 8439 ──────────────────────────────────────────────────────

describe("Poly1305 — RFC 8439", () => {
  it("section 2.5.2 worked example", async () => {
    expect(
      await tag(
        "poly1305",
        keyed("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
        ascii("Cryptographic Forum Research Group"),
      ),
    ).toBe("a8061dc1305136c6c22b8baf0c0127a9");
  });

  it("always produces a 16-byte tag", async () => {
    for (const message of ["", "a", "x".repeat(17), "y".repeat(1000)]) {
      const result = await tag("poly1305", keyed("00".repeat(32)), ascii(message));
      expect(result.length, `message length ${message.length}`).toBe(32);
    }
  });

  it("refuses a key that is not exactly 32 bytes, naming the length given", async () => {
    const tool = macToolDefinition("poly1305");
    const result = await tool.compute(specFor("poly1305", keyed("00".repeat(16))), ascii("x"));
    expect(result.bytes).toBeUndefined();
    expect(result.error).toContain("32");
    expect(result.error).toContain("16");
  });
});

// ── AES-CMAC: RFC 4493 ──────────────────────────────────────────────────────

describe("AES-CMAC — RFC 4493 examples", () => {
  const K = "2b7e151628aed2a6abf7158809cf4f3c";

  it("example 1 — empty message", async () => {
    expect(await tag("cmac", keyed(K), new Uint8Array(0))).toBe(
      "bb1d6929e95937287fa37d129b756746",
    );
  });

  it("example 2 — one full block", async () => {
    expect(await tag("cmac", keyed(K), fromHex("6bc1bee22e409f96e93d7e117393172a"))).toBe(
      "070a16b46b4d4144f79bdd9dd04a287c",
    );
  });

  it("example 3 — a partial final block, exercising the second subkey", async () => {
    expect(
      await tag(
        "cmac",
        keyed(K),
        fromHex(
          "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
        ),
      ),
    ).toBe("dfa66747de9ae63030ca32611497c827");
  });

  it("accepts all three AES key sizes", async () => {
    for (const size of [16, 24, 32]) {
      const result = await tag("cmac", keyed("11".repeat(size)), ascii("x"));
      expect(result.length, `${size}-byte key`).toBe(32);
    }
  });

  it("refuses a 20-byte key", async () => {
    const tool = macToolDefinition("cmac");
    const result = await tool.compute(specFor("cmac", keyed("22".repeat(20))), ascii("x"));
    expect(result.error).toMatch(/16, 24, 32/);
  });
});

// ── streaming ───────────────────────────────────────────────────────────────

describe("streaming", () => {
  async function* single(bytes: Uint8Array) {
    yield bytes;
  }

  it("chunked equals one-shot for every streaming tool, including the buffering fallback", async () => {
    /**
     * HMAC-SM3 cannot stream incrementally — the inner hash must finish before the outer
     * starts — so it falls back to buffering the input and computing at the end. That
     * fallback is where a wrong answer would be least visible, so it is covered here
     * alongside the genuinely incremental paths.
     */
    const input = ascii("the quick brown fox jumps over the lazy dog, at some length");

    const cases: readonly [string, MacSpec["options"]][] = [
      ["hmac", keyed("00".repeat(32), { [OPTION_HASH]: "sha256" })],
      ["hmac", keyed("00".repeat(32), { [OPTION_HASH]: "sm3" })],
      ["kmac", keyed("00".repeat(32), { [OPTION_OUTPUT_LENGTH]: 32 })],
      ["poly1305", keyed("00".repeat(32))],
    ];

    for (const [variant, options] of cases) {
      const tool = macToolDefinition(variant);
      if (!tool.createStream) continue;
      const spec = specFor(variant, options);
      const oneShot = await tool.compute(spec, input);

      for (const chunkSize of [1, 7, 16, 64]) {
        const streamed = await runStream(
          tool.createStream(spec),
          rechunk(single(input), chunkSize),
        );
        expect(encodeHex(streamed.bytes!), `${variant} @ ${chunkSize}`).toBe(
          encodeHex(oneShot.bytes!),
        );
      }
    }
  });

  it("a stream with no key consumes the input and reports the problem", async () => {
    const tool = macToolDefinition("hmac");
    const result = await runStream(
      tool.createStream!(specFor("hmac")),
      rechunk(single(ascii("anything")), 3),
    );
    expect(result.error).toMatch(/key/i);
  });

  it("truncation applies to the streamed tag too", async () => {
    const tool = macToolDefinition("hmac");
    const spec = specFor("hmac", keyed("00".repeat(32), { [OPTION_TRUNCATE]: 16 }));
    const streamed = await runStream(
      tool.createStream!(spec),
      rechunk(single(ascii("abc")), 2),
    );
    expect(streamed.bytes).toHaveLength(16);
  });

  it("only claims streaming where it exists", () => {
    for (const meta of MAC_TOOLS) {
      const tool = macToolDefinition(meta.id);
      expect(Boolean(tool.createStream), meta.id).toBe(meta.streaming);
    }
  });
});

// ── truncation ──────────────────────────────────────────────────────────────

describe("truncation", () => {
  it("keeps the leading bytes of the full tag", async () => {
    const full = await tag(
      "hmac",
      keyed("0b".repeat(20), { [OPTION_HASH]: "sha256" }),
      ascii("Hi There"),
    );
    const cut = await tag(
      "hmac",
      keyed("0b".repeat(20), { [OPTION_HASH]: "sha256", [OPTION_TRUNCATE]: 16 }),
      ascii("Hi There"),
    );
    // Unlike KMAC, truncating an HMAC really is a prefix — that is what the standards mean.
    expect(cut).toBe(full.slice(0, 32));
  });

  it("refuses to truncate to more bytes than the tag has", async () => {
    const tool = macToolDefinition("hmac");
    const result = await tool.compute(
      specFor(
        "hmac",
        keyed("00".repeat(32), { [OPTION_HASH]: "sha256", [OPTION_TRUNCATE]: 64 }),
      ),
      ascii("x"),
    );
    expect(result.error).toMatch(/only 32/);
  });
});

// ── lint rules ──────────────────────────────────────────────────────────────

describe("lint rules", () => {
  it("M001 blocks when no key is entered", () => {
    for (const meta of MAC_TOOLS) {
      const result = lint(specFor(meta.id));
      expect(result.hasErrors, meta.id).toBe(true);
      expect(
        result.diagnostics.some((d) => d.code === "M001"),
        meta.id,
      ).toBe(true);
    }
  });

  it("M001 clears once a valid key is present", () => {
    expect(lint(specFor("hmac", keyed("00".repeat(32)))).hasErrors).toBe(false);
    expect(lint(specFor("poly1305", keyed("00".repeat(32)))).hasErrors).toBe(false);
    expect(lint(specFor("cmac", keyed("00".repeat(16)))).hasErrors).toBe(false);
  });

  it("M002 escalates from silent to warning to insecure as the key shrinks", () => {
    const level = (bytes: number) =>
      lint(specFor("hmac", keyed("00".repeat(bytes)))).diagnostics.find(
        (d) => d.code === "M002",
      )?.level;
    // 32 bytes matches SHA-256's output: nothing to say. 20 is short. 8 is guessable.
    expect(level(32)).toBeUndefined();
    expect(level(20)).toBe("warning");
    expect(level(8)).toBe("insecure");
  });

  it("M003 flags a legacy hash without overclaiming, and its fix moves to SHA-256", () => {
    const spec = specFor("hmac", keyed("00".repeat(32), { [OPTION_HASH]: "md5" }));
    const found = lint(spec).diagnostics.find((d) => d.code === "M003");
    // The message must not claim HMAC-MD5 is broken, because it is not.
    expect(found?.level).toBe("warning");
    expect(found?.message).toContain("is not broken");

    const fixed = applyAllFixes(spec);
    expect(fixed.options[OPTION_HASH]).toBe("sha256");
    expect(lint(fixed).diagnostics.some((d) => d.code === "M003")).toBe(false);
  });

  it("M003 stays quiet for every modern hash", () => {
    for (const hash of HMAC_HASHES.filter((h) => !h.legacy)) {
      const spec = specFor("hmac", keyed("00".repeat(64), { [OPTION_HASH]: hash.id }));
      expect(
        lint(spec).diagnostics.some((d) => d.code === "M003"),
        hash.id,
      ).toBe(false);
    }
  });

  it("M004 permits a standardised truncation and flags a dangerous one", () => {
    const base = keyed("00".repeat(32), { [OPTION_HASH]: "sha256" });
    const level = (bytes: number) =>
      lint(specFor("hmac", { ...base, [OPTION_TRUNCATE]: bytes })).diagnostics.find(
        (d) => d.code === "M004",
      )?.level;

    // 16 bytes is exactly half of SHA-256 and what RFC 4868 specifies for IPsec.
    expect(level(16)).toBeUndefined();
    // 12 bytes is legal, below half, and worth a word.
    expect(level(12)).toBe("warning");
    // 8 bytes is below RFC 2104's 80-bit floor.
    expect(level(8)).toBe("insecure");
  });

  it("M004's fix restores the full tag", () => {
    const spec = specFor(
      "hmac",
      keyed("00".repeat(32), { [OPTION_HASH]: "sha256", [OPTION_TRUNCATE]: 4 }),
    );
    const fixed = applyAllFixes(spec);
    expect(fixed.options[OPTION_TRUNCATE]).toBeUndefined();
    expect(lint(fixed).diagnostics.some((d) => d.code === "M004")).toBe(false);
  });

  it("M005 always fires for Poly1305 and never for anything else", () => {
    for (const meta of MAC_TOOLS) {
      const key = meta.id === "cmac" ? "00".repeat(16) : "00".repeat(32);
      const codes = lint(specFor(meta.id, keyed(key))).diagnostics.map((d) => d.code);
      expect(codes.includes("M005"), meta.id).toBe(meta.id === "poly1305");
    }
  });

  it("M006 fires exactly for the tools that cannot stream", () => {
    for (const meta of MAC_TOOLS) {
      const key = meta.id === "cmac" ? "00".repeat(16) : "00".repeat(32);
      const codes = lint(specFor(meta.id, keyed(key))).diagnostics.map((d) => d.code);
      expect(codes.includes("M006"), meta.id).toBe(!meta.streaming);
    }
  });

  it("reports a bad key encoding as an error rather than throwing", () => {
    const spec = specFor("hmac", { [OPTION_KEY]: "not hex at all", keyEncoding: "hex" });
    expect(() => lint(spec)).not.toThrow();
    expect(lint(spec).hasErrors).toBe(true);
  });
});

// ── catalogue, manifests ────────────────────────────────────────────────────

describe("catalogue and manifests", () => {
  it("every tool's catalogue is internally consistent", () => {
    for (const meta of MAC_TOOLS) {
      expect(validateCatalogue(macToolDefinition(meta.id).catalogue.options), meta.id).toEqual(
        [],
      );
    }
  });

  it("marks every key option secret, so none can reach a share link", () => {
    // The one property that must hold for all four. A key not marked secret would be
    // serialised straight into a URL by `buildShareLink`, with no warning.
    for (const meta of MAC_TOOLS) {
      const catalogue = macToolDefinition(meta.id).catalogue;
      expect(catalogue.secretIds(), meta.id).toContain(OPTION_KEY);
      expect(catalogue.require(OPTION_KEY).secret, meta.id).toBe(true);
    }
  });

  it("offers no decimal output — a MAC is compared, not read as a number", () => {
    for (const manifest of MAC_MANIFESTS) {
      expect(manifest.outputEncodings).not.toContain("decimal");
    }
  });

  it("shows only its own options — HMAC's hash picker never appears on KMAC", () => {
    const hmacIds = macToolDefinition("hmac").catalogue.options.map((o) => o.id);
    const kmacIds = macToolDefinition("kmac").catalogue.options.map((o) => o.id);
    expect(hmacIds).toContain(OPTION_HASH);
    expect(hmacIds).not.toContain(OPTION_KMAC_VARIANT);
    expect(kmacIds).toContain(OPTION_KMAC_VARIANT);
    expect(kmacIds).not.toContain(OPTION_HASH);
  });
});

describe("describeSpec", () => {
  it("names the construction and the key length", () => {
    const text = describeSpec(
      specFor("hmac", keyed("00".repeat(32), { [OPTION_HASH]: "sha512" })),
    );
    expect(text).toContain("HMAC-SHA-512");
    expect(text).toContain("32-byte key");
  });

  it("says what is missing when there is no key", () => {
    expect(describeSpec(specFor("hmac"))).toMatch(/key/i);
  });

  it("mentions truncation when it applies", () => {
    const text = describeSpec(
      specFor(
        "hmac",
        keyed("00".repeat(32), { [OPTION_HASH]: "sha256", [OPTION_TRUNCATE]: 16 }),
      ),
    );
    expect(text).toContain("truncated from 32");
  });

  it("states Poly1305's single-use constraint", () => {
    expect(describeSpec(specFor("poly1305", keyed("00".repeat(32))))).toContain("single-use");
  });

  it("names the AES size for CMAC", () => {
    expect(describeSpec(specFor("cmac", keyed("00".repeat(32))))).toContain("AES-256-CMAC");
  });
});

describe("createSpec", () => {
  it("names a concrete hash for HMAC and a variant for KMAC", () => {
    expect(createSpec({ variant: "hmac" }).options[OPTION_HASH]).toBe(DEFAULT_HMAC_HASH);
    expect(createSpec({ variant: "kmac" }).options[OPTION_KMAC_VARIANT]).toBe("kmac128");
  });

  it("never pre-fills a key", () => {
    // A default key would be the worst possible default: it works, and it is public.
    for (const meta of MAC_TOOLS) {
      expect(createSpec({ variant: meta.id }).options[OPTION_KEY], meta.id).toBeUndefined();
    }
  });

  it("rejects an unknown variant", () => {
    expect(() => createSpec({ variant: "gmac" })).toThrow(/Unknown MAC tool/);
    expect(() => requireMacTool("gmac")).toThrow(/gmac/);
  });

  it("falls back to SHA-256 when a share link names a hash this tool does not offer", () => {
    // An XOF, which HMAC deliberately does not accept -- KMAC is what keys a sponge. MD2 used to be
    // the example here and is now offered, for PHP parity.
    const resolved = resolveMac(
      specFor("hmac", keyed("00".repeat(32), { [OPTION_HASH]: "shake128" })),
    );
    expect(resolved.ok).toBe(true);
    if (resolved.ok) expect(resolved.resolved.hashId).toBe("sha256");
  });

  it("round-trips through the zod schema", () => {
    const tool = macToolDefinition("hmac");
    const spec = specFor("hmac", keyed("00".repeat(32)));
    expect(tool.specSchema.parse(spec)).toEqual(spec);
  });
});

/**
 * How the text in the Key field becomes bytes.
 *
 * Its own describe block because it is not arithmetic: every value below is a correct HMAC, and the
 * only question is which key was computed over. That is the one thing about this family a user has
 * actually been caught by -- a key of `1234` matched neither the reference site nor their
 * expectation, because this tool read it as the two bytes 0x12 0x34 while the reference read four
 * characters of text.
 */
describe("the key's encoding", () => {
  /**
   * HMAC-SHA256 of "123456789" under the key `1234`, both readings.
   *
   * Verified against OpenSSL through `node:crypto`, and the first value is what
   * emn178.github.io/online-tools reports -- which is the whole point: the text reading is the one
   * this tool has to agree with by default.
   */
  const KEY_AS_TEXT = "1a317d78de6906810199224081c464ef1673ca4c19e30f5d61b4e048748dfb48";
  const KEY_AS_HEX = "208e58cc530087b5534510fceca02c2854b3ad7295be3697f7441cc3c8206c2c";

  it("HMAC reads a typed key as UTF-8 text, matching the reference site", async () => {
    // No `keyEncoding` in the spec on purpose: this asserts the *default*, which is what someone
    // who has typed a key and read the output off the screen actually gets.
    expect(await tag("hmac", { [OPTION_KEY]: "1234" }, ascii("123456789"))).toBe(KEY_AS_TEXT);
  });

  it("and reads the same characters as bytes when told to", async () => {
    expect(
      await tag("hmac", { [OPTION_KEY]: "1234", keyEncoding: "hex" }, ascii("123456789")),
    ).toBe(KEY_AS_HEX);
  });

  it("the two readings genuinely differ, so the default is not cosmetic", () => {
    expect(KEY_AS_TEXT).not.toBe(KEY_AS_HEX);
  });

  it("declares the default each tool actually wants", () => {
    // Like HMAC, the default key encoding is Text (UTF-8).
    const encodingFor = (variant: string) =>
      macToolDefinition(variant).catalogue.require(OPTION_KEY).defaultBytesEncoding;
    expect(encodingFor("hmac")).toBe("utf-8");
    for (const variant of [
      "kmac",
      "poly1305",
      "cmac",
      "siphash",
      "siphash13",
      "siphash48",
      "halfsiphash",
      "highwayhash",
      "skeinmac",
      "asconmac",
      "asconprf",
      "asconprfs",
      "chaskey",
      "pelican",
      "poly1305-aes",
    ]) {
      expect(encodingFor(variant), variant).toBe("utf-8");
    }
  });

  it("M007 says so when the key reads both ways, and its fix switches to hex", () => {
    const spec = specFor("hmac", { [OPTION_KEY]: "1234" });
    const found = lint(spec).diagnostics.find((d) => d.code === "M007");
    expect(found).toBeDefined();
    // The numbers are the point of the message -- "4 bytes, not 2" is what makes it act on.
    expect(found!.message).toContain("4 bytes");
    expect(found!.message).toContain("not 2");

    const fixed = found!.fix!.apply(spec);
    expect(lint(fixed).diagnostics.some((d) => d.code === "M007")).toBe(false);
    expect(fixed.options.keyEncoding).toBe("hex");
  });

  it("M007 stays quiet unless the reading is genuinely ambiguous", () => {
    const quiet = (options: MacSpec["options"]) =>
      lint(specFor("hmac", options)).diagnostics.every((d) => d.code !== "M007");

    // Not hex at all.
    expect(quiet({ [OPTION_KEY]: "password" })).toBe(true);
    // Hex digits but an odd length, so it could not be a byte string.
    expect(quiet({ [OPTION_KEY]: "abc" })).toBe(true);
    // Already being read as bytes: there is nothing left to warn about.
    expect(quiet({ [OPTION_KEY]: "1234", keyEncoding: "hex" })).toBe(true);
    // Base64 is its own reading and equally unambiguous.
    expect(quiet({ [OPTION_KEY]: "1234", keyEncoding: "base64" })).toBe(true);
    // And it fires on the case it exists for, so the assertions above are not vacuous.
    expect(quiet({ [OPTION_KEY]: "deadbeef" })).toBe(false);
  });

  it("M007 fires when key is read as text and is ambiguous hex across MAC tools", () => {
    for (const variant of ["hmac", "kmac", "skeinmac"]) {
      const codes = lint(specFor(variant, { [OPTION_KEY]: "deadbeef" })).diagnostics.map(
        (d) => d.code,
      );
      expect(codes, variant).toContain("M007");
    }
  });
});

describe("requireHmacHash", () => {
  it("names the hash it will not build HMAC over", () => {
    /**
     * What remains excluded, and why each one is.
     *
     * An XOF is not what SP 800-185 means by keying a sponge -- KMAC is. Skein and Ascon have their
     * own keyed modes, so HMAC over either would be an unspecified construction with nothing to check
     * it against. And a non-cryptographic hash makes HMAC theatre; PHP's `hash_hmac_algos()` omits
     * every one of those too.
     *
     * MD2 is no longer on this list: its 16-byte block does make the construction degenerate, but PHP
     * offers it and publishes a value, so refusing it only stopped someone reproducing an old MAC.
     */
    expect(() => requireHmacHash("shake128")).toThrow(/shake128/);
    expect(() => requireHmacHash("cshake256")).toThrow(/cshake256/);
    expect(() => requireHmacHash("kt128")).toThrow(/kt128/);
    expect(() => requireHmacHash("xxh64")).toThrow(/xxh64/);
    expect(() => requireHmacHash("murmur3f")).toThrow(/murmur3f/);
    /**
     * Ascon-Hash256 is the one exclusion that is a technical objection rather than a missing vector:
     * its sponge rate is 8 bytes, so HMAC's padded key would be 8 bytes and the construction would
     * cap key material at 64 bits. Ascon's own PRF and MAC modes are the specified answer.
     */
    expect(() => requireHmacHash("asconhash256")).toThrow(/asconhash256/);

    // MD2, Skein and BLAKE1 all resolve now, each for a reason recorded on `HMAC_HASHES`.
    expect(requireHmacHash("md2").blockLen).toBe(16);
    expect(requireHmacHash("skein512").blockLen).toBe(64);
    expect(requireHmacHash("blake256").blockLen).toBe(64);
  });
});

/**
 * HMAC over the hashes PHP keys, and the two Streebog widths.
 *
 * The list of hashes HMAC accepts went from sixteen to forty-eight so that everything in PHP's
 * `hash_hmac_algos()` is reachable. Thirty-two of those hashes are not noble's, so they go through the
 * generic RFC 2104 implementation in `bindings.ts` -- and this block is what makes that trustworthy:
 *
 *  1. **The generic implementation is checked against noble's** over every hash noble provides. Two
 *     independent HMACs over the same hash must agree, which pins the construction itself.
 *  2. **Every new family has a published HMAC value**, which pins the one thing (1) cannot: the block
 *     size. A wrong `blockLen` produces a stable MAC that no other tool agrees with, and it is the
 *     mistake this set exists to catch -- MD2's block is 16 bytes, Snefru's and GOST's are 32, HAVAL's
 *     is 128, and only Streebog's 64 is what a reader would guess.
 *  3. **The completeness gate** requires every name PHP will key to be offered here.
 */
describe("HMAC over the wider hash list", () => {
  /** An async source of one chunk, which `rechunk` then re-splits. */
  async function* chunks(bytes: Uint8Array) {
    yield bytes;
  }

  /**
   * php-src `ext/hash/tests/hash_hmac_basic.phpt`: one message, one key, sixteen algorithms.
   *
   * The key is the ASCII string `secret` -- six bytes, well under every block size, so this also
   * exercises the zero-padding path rather than the hash-the-key-down one.
   */
  const PHP_CONTENT =
    "This is a sample string used to test the hash_hmac function with various hashing algorithms";
  const PHP_KEY = "secret";
  const PHP_HMAC: Record<string, string> = {
    gost94: "a4a3c80bdf3f8665bf07376a34dc9c1b11af7c813f4928f62e39f0c0dc564dad",
    "haval128-3": "4d1318607f0406bd1b7bd50907772672",
    md2: "6d111dab563025e4cb5f4425c991fa12",
    md4: "10cdbfe843000c623f8b8da0d5d20b0b",
    md5: "2a632783e2812cf23de100d7d6a463ae",
    ripemd128: "26c2f694a65b1928b668cf55f65529b4",
    ripemd160: "4b3433ba596ec39692bb7ce760a9ee5fb818113f",
    ripemd256: "4e4e5ec19322895a727f272dfe68f87bc1af66cc6ce27c6c1360a5ee78a14b30",
    ripemd320:
      "f10a8ff82e828b92a5ff0a02fc9032bc61352d0d824821fc42f7e09cf5b5f41ee59fd33a730d7469",
    sha1: "5bfdb62b97e2c987405463e9f7c193139c0e1fd0",
    sha256: "49bde3496b9510a17d0edd8a4b0ac70148e32a1d51e881ec76faa96534125838",
    sha384:
      "b781415b856744834e532b9899e1aa0bec5a82cf09a838f0a833470468e2a42648a52428cfd9012385d04de5cd9bd122",
    sha512:
      "7de05636b18e2b0ca3427e03f53074af3a48a7b9df226daba4f22324c570638e7d7b26430e214799c9ce0db5ee88dad3292ca0f38bf99b8eaebed59b3a9c140a",
    snefru: "67af483046f9cf16fe19f9087929ccfc6ad176ade3290b4d33f43e0ddb07e711",
    "tiger192-3": "00a0f884f15a9e5549ed0e40ca0190522d369027e16d5b59",
    whirlpool:
      "4a0f1582b21b7aff59bfba7f9c29131c69741b2ce80acdc7d314040f3b768cf5a17e30b74cceb86fbc6b34b1692e0addd5bfd7cfc043d40c0621f1b97e26fa49",
  };

  it("matches PHP's hash_hmac for every algorithm php-src publishes", async () => {
    const message = ascii(PHP_CONTENT);
    for (const [hashId, expected] of Object.entries(PHP_HMAC)) {
      const value = await tag(
        "hmac",
        {
          [OPTION_KEY]: PHP_KEY,
          keyEncoding: "utf-8",
          [OPTION_HASH]: hashId,
        },
        message,
      );
      expect(value, hashId).toBe(expected);
    }
  });

  it("covers one algorithm from every block size the wider list introduced", () => {
    // The point of the set above, stated: 16, 32, 64 and 128-byte blocks are all represented, because
    // the block size is what a new hash gets wrong.
    const blocks = new Set(Object.keys(PHP_HMAC).map((id) => requireHmacHash(id).blockLen));
    expect([...blocks].sort((a, b) => a - b)).toEqual([16, 32, 64, 128]);
  });

  it("matches the R 50.1.113 vectors for HMAC over both Streebog widths", async () => {
    /**
     * RFC 7836 defines HMAC_GOSTR3411_2012_256 and _512 and states their parameters outright -- B = 64
     * for *both* widths, L = 32 or 64 -- but publishes no vector. These two are the Russian
     * recommendation's, as carried by Bouncy Castle's GOST3411-2012 digest tests.
     *
     * The 512-bit case is the interesting one: its digest is 64 bytes and its block is *also* 64, so
     * an implementation that assumed a 128-byte block (as SHA-512 has) fails here and nowhere else.
     */
    const key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const data = fromHex("0126bdb87800af214341456563780100");

    expect(
      await tag("hmac", keyed(key, { [OPTION_HASH]: "streebog256" }), data),
    ).toBe("a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9");

    expect(
      await tag("hmac", keyed(key, { [OPTION_HASH]: "streebog512" }), data),
    ).toBe(
      "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a773d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6",
    );
  });

  it("agrees with noble's HMAC over every hash noble provides", async () => {
    /**
     * The cross-check. `bindings.ts` keeps noble's audited `hmac` for the sixteen hashes noble has and
     * uses its own RFC 2104 implementation for the other thirty-two; this requires the two to produce
     * the same bytes wherever both can run, which is the only way the generic path earns trust for the
     * hashes noble cannot check.
     *
     * Three key lengths, because the construction branches on them: shorter than the block, exactly
     * the block, and longer -- the last being the case that must *hash* the key rather than truncate.
     */
    const nobleHashes: Record<string, Parameters<typeof nobleHmac>[0]> = {
      sha224,
      sha256,
      sha384,
      sha512,
      "sha3-256": sha3_256,
      "sha3-512": sha3_512,
      sha1,
      md5,
      ripemd160,
      blake2b,
      blake2s,
      // BLAKE1: no published HMAC vector exists, but noble has the hash, so the audited HMAC can be
      // compared against ours -- which is the whole reason these four are offered at all.
      blake224,
      blake256,
      blake384,
      blake512,
    };

    const message = ascii("cross-checking two HMAC implementations over one hash");
    for (const [hashId, hash] of Object.entries(nobleHashes)) {
      const blockLen = requireHmacHash(hashId).blockLen;
      for (const keyLen of [7, blockLen, blockLen + 41]) {
        const key = new Uint8Array(keyLen);
        for (let i = 0; i < keyLen; i++) key[i] = (i * 11 + 3) & 0xff;

        const ours = await tag(
          "hmac",
          keyed(encodeHex(key), { [OPTION_HASH]: hashId }),
          message,
        );
        expect(ours, `${hashId} with a ${keyLen}-byte key`).toBe(
          encodeHex(nobleHmac(hash, key, message)),
        );
      }
    }
  });

  it("hashes an over-long key down rather than truncating it", async () => {
    /**
     * RFC 2104's rule, asserted for a hash noble does not have -- so it is the generic implementation
     * being tested, not noble's. Truncating instead of hashing agrees for every key up to the block
     * size and diverges silently past it, which is exactly the kind of bug a short-key test misses.
     */
    const long = new Uint8Array(200);
    for (let i = 0; i < long.length; i++) long[i] = (i * 7 + 1) & 0xff;
    const truncated = long.subarray(0, 64);

    const message = ascii("over-long key");
    const withLong = await tag(
      "hmac",
      keyed(encodeHex(long), { [OPTION_HASH]: "tiger192-3" }),
      message,
    );
    const withTruncated = await tag(
      "hmac",
      keyed(encodeHex(truncated), { [OPTION_HASH]: "tiger192-3" }),
      message,
    );
    expect(withLong).not.toBe(withTruncated);

    // And it equals the MAC under the *digest* of that key, which is what the rule says.
    const digestOfKey = tiger(long);
    expect(
      await tag(
        "hmac",
        keyed(encodeHex(digestOfKey), { [OPTION_HASH]: "tiger192-3" }),
        message,
      ),
    ).toBe(withLong);
  });

  it("streams to the same tag as one shot for the hashes that are not noble's", async () => {
    /**
     * These used to be one-shot: HMAC-SM3 was hand-written with a comment saying it could not stream.
     * It can -- only the outer hash needs the inner digest, and that does not exist until the end --
     * and now every hash in the list streams, which is what lets the wider set take file input.
     */
    const message = new Uint8Array(500);
    for (let i = 0; i < message.length; i++) message[i] = (i * 13 + 5) & 0xff;

    for (const hashId of [
      "sm3",
      "tiger192-3",
      "tiger2",
      "haval256-5",
      "snefru",
      "gost94-crypto",
      "streebog512",
      "md2",
      "skein256",
      "skein512",
      "skein1024",
    ]) {
      const options = keyed("11".repeat(20), { [OPTION_HASH]: hashId });
      const oneShot = await tag("hmac", options, message);
      const tool = macToolDefinition("hmac");
      const spec = specFor("hmac", options);

      for (const chunkSize of [1, 17, 64]) {
        const streamed = await runStream(
          tool.createStream!(spec),
          rechunk(chunks(message), chunkSize),
        );
        expect(encodeHex(streamed.bytes!), `${hashId} @ ${chunkSize}`).toBe(oneShot);
      }
    }
  });

  it("keys Skein and BLAKE1 too, with what stands behind them stated", async () => {
    /**
     * These seven have no published HMAC vector anywhere -- Skein's own answer to keying is Skein-MAC,
     * which keys the UBI tweak and is a different construction, and nothing publishes an HMAC-BLAKE1
     * value. They are offered because HMAC over them is well defined and someone may need to reproduce
     * a value; the checks that do exist are named here rather than implied.
     *
     * BLAKE1 comes from noble, so the cross-check above compares an audited HMAC against ours over the
     * same hash. Skein goes through the generic path, so what is asserted is the block size -- its
     * state size, 32, 64 or 128 -- and that the tag is the length the metadata promises.
     */
    const message = ascii("keyed Skein");
    for (const [hashId, blockLen, outputLen] of [
      ["skein256", 32, 32],
      ["skein512", 64, 64],
      ["skein1024", 128, 128],
    ] as const) {
      expect(requireHmacHash(hashId).blockLen, hashId).toBe(blockLen);
      const value = await tag("hmac", keyed("33".repeat(24), { [OPTION_HASH]: hashId }), message);
      expect(value.length, hashId).toBe(outputLen * 2);
    }

    /**
     * And the property that distinguishes HMAC from Skein's native mode: HMAC hashes the key into the
     * message stream, Skein-MAC folds it into the tweak, so the two cannot agree. Asserted against the
     * plain digest of the same bytes, which is the closest thing available without implementing
     * Skein-MAC -- an HMAC that ignored its key would match it.
     */
    const plain = encodeHex(skein(message, 64, 64));
    const keyedTag = await tag(
      "hmac",
      keyed("33".repeat(24), { [OPTION_HASH]: "skein512" }),
      message,
    );
    expect(keyedTag).not.toBe(plain);
  });

  it("M003 distinguishes a broken hash from a superseded one", () => {
    /**
     * The overclaim guard. `M003` fires for everything marked legacy, but the sentence differs: MD5
     * has a demonstrated collision and Tiger does not, and a rule that told the reader Tiger was
     * broken would be false in the direction that costs trust everywhere else in the panel.
     */
    const message = (hashId: string) =>
      lint(specFor("hmac", keyed("11".repeat(32), { [OPTION_HASH]: hashId }))).diagnostics.find(
        (d) => d.code === "M003",
      )?.message;

    expect(message("md5")).toBe("HMAC-MD5 is not broken, and MD5 is.");
    expect(message("haval128-3")).toMatch(/HAVAL-128,3 is\.$/);
    expect(message("tiger192-3")).toBe("Tiger-192,3 is superseded, though HMAC over it is sound.");
    expect(message("snefru")).toMatch(/superseded/);
    expect(message("gost94")).toMatch(/superseded/);
    expect(message("ripemd160")).toMatch(/superseded/);
    // And nothing at all for the modern ones.
    expect(message("sha256")).toBeUndefined();
    expect(message("streebog512")).toBeUndefined();
    expect(message("whirlpool")).toBeUndefined();
  });

  it("marks broken only where a collision has actually been demonstrated", () => {
    // The flag drives that wording, so what it is set on is a factual claim worth pinning.
    const broken = HMAC_HASHES.filter((h) => h.broken).map((h) => h.id).sort();
    expect(broken).toEqual([
      "haval128-3",
      "haval128-4",
      "haval160-3",
      "haval160-4",
      "haval192-3",
      "haval192-4",
      "haval224-3",
      "haval224-4",
      "haval256-3",
      "haval256-4",
      "md2",
      "md4",
      "md5",
      "sha1",
    ]);
    // Every broken entry is also legacy; the reverse does not hold.
    for (const hash of HMAC_HASHES) {
      if (hash.broken) expect(hash.legacy, hash.id).toBe(true);
    }
    expect(HMAC_HASHES.some((h) => h.legacy && !h.broken)).toBe(true);
  });

  it("only keys hashes whose output fits their block, which is RFC 2104's requirement", () => {
    /**
     * The rule that decides the one interesting exclusion, written as a gate rather than a comment.
     *
     * RFC 2104 reduces an over-long key by hashing it and then zero-padding the resulting L-byte string
     * into the B-byte block. That step only exists if L <= B. Every standard hash satisfies it easily --
     * SHA-256 is 32 into 64, SHA3-256 is 32 into 136 -- and Ascon-Hash256 does not: its sponge rate is 8
     * bytes and its output is 32, so there is no way to place H(K) in a block. HMAC over it is undefined,
     * not merely weak, and any implementation offering it has invented a rule of its own.
     *
     * Note this is not an argument about sponges. SHA3-256 is a sponge and is keyed here without trouble;
     * the problem is specific to a rate smaller than the digest.
     */
    for (const hash of HMAC_HASHES) {
      expect(
        hash.outputLen,
        `${hash.id}: HMAC needs the digest (L=${hash.outputLen}) to fit the block (B=${hash.blockLen})`,
      ).toBeLessThanOrEqual(hash.blockLen);
    }

    // And the hash that fails the rule is refused for exactly that reason.
    const ascon = HASH_ALGORITHMS.find((a) => a.id === "asconhash256")!;
    expect(ascon.outputLen).toBe(32);
    expect(ascon.blockLen).toBe(8);
    expect(ascon.outputLen).toBeGreaterThan(ascon.blockLen);
    expect(() => requireHmacHash("asconhash256")).toThrow(/asconhash256/);

    /**
     * The second consequence, which is the one with teeth even for a short key: the padded key block is
     * the rate, so only 8 bytes of key ever enter the first permutation. That caps key material at 64
     * bits however long the user's key is -- against Ascon's own 128-bit claim. Ascon-MAC exists for this
     * and keeps the full claim, which is why it is a tool here and HMAC-Ascon is not.
     */
    expect(ascon.blockLen * 8).toBe(64);
    expect(requireMacTool("asconmac").outputLen).toBe(16);
  });

  it("offers HMAC over every hash PHP will key, and says why the rest are out", () => {
    /**
     * The completeness gate, in the same spirit as `php-parity.test.ts`: PHP's `hash_hmac_algos()`
     * list, transcribed, mapped onto this repo's ids. If PHP grows an HMAC-able algorithm, this fails.
     */
    const phpHmacAlgos: Record<string, string> = {
      md2: "md2",
      md4: "md4",
      md5: "md5",
      sha1: "sha1",
      sha224: "sha224",
      sha256: "sha256",
      sha384: "sha384",
      "sha512/224": "sha512-224",
      "sha512/256": "sha512-256",
      sha512: "sha512",
      "sha3-224": "sha3-224",
      "sha3-256": "sha3-256",
      "sha3-384": "sha3-384",
      "sha3-512": "sha3-512",
      ripemd128: "ripemd128",
      ripemd160: "ripemd160",
      ripemd256: "ripemd256",
      ripemd320: "ripemd320",
      whirlpool: "whirlpool",
      "tiger128,3": "tiger128-3",
      "tiger160,3": "tiger160-3",
      "tiger192,3": "tiger192-3",
      "tiger128,4": "tiger128-4",
      "tiger160,4": "tiger160-4",
      "tiger192,4": "tiger192-4",
      snefru: "snefru",
      snefru256: "snefru",
      gost: "gost94",
      "gost-crypto": "gost94-crypto",
      "haval128,3": "haval128-3",
      "haval160,3": "haval160-3",
      "haval192,3": "haval192-3",
      "haval224,3": "haval224-3",
      "haval256,3": "haval256-3",
      "haval128,4": "haval128-4",
      "haval160,4": "haval160-4",
      "haval192,4": "haval192-4",
      "haval224,4": "haval224-4",
      "haval256,4": "haval256-4",
      "haval128,5": "haval128-5",
      "haval160,5": "haval160-5",
      "haval192,5": "haval192-5",
      "haval224,5": "haval224-5",
      "haval256,5": "haval256-5",
    };

    expect(Object.keys(phpHmacAlgos)).toHaveLength(44);
    for (const [phpName, ourId] of Object.entries(phpHmacAlgos)) {
      expect(() => requireHmacHash(ourId), `${phpName} -> ${ourId}`).not.toThrow();
    }

    /**
     * And the eleven this repo adds beyond PHP's list. The first five have a published HMAC vector
     * somewhere -- RFC 4231 and SP 800-185 for the noble ones, R 50.1.113 for Streebog; the last six do
     * not, and are offered on the strength of the construction being cross-checked against noble and
     * the block size being asserted against the hash family's metadata.
     */
    for (const extra of ["sm3", "blake2b", "blake2s", "streebog256", "streebog512"]) {
      expect(() => requireHmacHash(extra), extra).not.toThrow();
    }
    for (const unvectored of [
      "skein256",
      "skein512",
      "skein1024",
      "blake224",
      "blake256",
      "blake384",
      "blake512",
    ]) {
      expect(() => requireHmacHash(unvectored), unvectored).not.toThrow();
    }
    expect(HMAC_HASHES).toHaveLength(55);
  });

  it("computes a tag for every hash in the list, at the declared length", async () => {
    // Nothing in the list may be unreachable: every id must resolve to a binding and produce exactly
    // the number of bytes the metadata promises, which is what the result panel and the verify field
    // both assume.
    const message = ascii("every entry in the list");
    for (const hash of HMAC_HASHES) {
      const value = await tag(
        "hmac",
        keyed("22".repeat(16), { [OPTION_HASH]: hash.id }),
        message,
      );
      expect(value.length, hash.id).toBe(hash.outputLen * 2);
    }
  });
});


/**
 * The four native keyed modes: Skein-MAC, Ascon-MAC, Ascon-PRF and Ascon-PRFShort.
 *
 * Each keys its primitive directly rather than nesting hashes, which is the point of having them at all
 * -- and each has published known-answer vectors, unlike HMAC over Skein. `tests/algos-skein.test.ts`
 * and `tests/algos-ascon.test.ts` run those in bulk (50 Skein-MAC vectors, 72 Ascon-MAC, 72 Ascon-PRF
 * and the whole 17-vector PRFShort file); what this block checks is the trip through options, resolver
 * and compute, plus the properties a user would notice.
 */
describe("the native keyed modes", () => {
  const ASCON_KEY = "000102030405060708090a0b0c0d0e0f";

  /** An async source of one chunk, which `rechunk` then re-splits. */
  async function* chunks(bytes: Uint8Array) {
    yield bytes;
  }

  it("Skein-MAC reproduces a golden-KAT vector through the tool", async () => {
    // A 512-bit state with a key longer than the block -- the case HMAC cannot express, since it would
    // hash such a key down first.
    const vector = SKEIN_MAC_VECTORS.find(
      (v) => v.stateBits === 512 && v.key.length / 2 > 64 && v.outputBits === 512,
    );
    expect(vector, "a 512-bit vector with an over-long key").toBeTruthy();

    const value = await tag(
      "skeinmac",
      keyed(vector!.key, {
        [OPTION_SKEIN_STATE]: vector!.stateBits / 8,
        [OPTION_OUTPUT_LENGTH]: vector!.outputBits / 8,
      }),
      fromHex(vector!.message),
    );
    expect(value).toBe(vector!.hex);
  });

  it("Skein-MAC's state size and tag length are both real choices", async () => {
    const message = ascii("state and length");
    const key = "11".repeat(32);

    const byState = await Promise.all(
      [32, 64, 128].map((state) =>
        tag("skeinmac", keyed(key, { [OPTION_SKEIN_STATE]: state, [OPTION_OUTPUT_LENGTH]: 32 }), message),
      ),
    );
    expect(new Set(byState).size, "three state sizes, three answers").toBe(3);

    // And the length is bound into the configuration block, so a shorter tag is not a prefix.
    const short = await tag(
      "skeinmac",
      keyed(key, { [OPTION_SKEIN_STATE]: 64, [OPTION_OUTPUT_LENGTH]: 32 }),
      message,
    );
    const long = await tag(
      "skeinmac",
      keyed(key, { [OPTION_SKEIN_STATE]: 64, [OPTION_OUTPUT_LENGTH]: 64 }),
      message,
    );
    expect(short).not.toBe(long.slice(0, 64));
  });

  it("Ascon-MAC and Ascon-PRF reproduce their reference vectors through the tools", async () => {
    const macVector = ASCON_MAC_KAT.find((v) => v.length === 33);
    const prfVector = ASCON_PRF_KAT.find((v) => v.length === 33);
    expect(macVector && prfVector, "the 33-byte vectors").toBeTruthy();

    // 33 bytes crosses the 32-byte absorb rate, which is the length worth driving end to end.
    const message = asconKeyedKatMessage(33);
    expect(await tag("asconmac", keyed(ASCON_KEY), message)).toBe(macVector!.hex);
    expect(
      await tag("asconprf", keyed(ASCON_KEY, { [OPTION_OUTPUT_LENGTH]: ASCON_PRF_KAT_LEN }), message),
    ).toBe(prfVector!.hex);
  });

  it("Ascon-PRFShort reproduces its vectors and refuses more than 16 bytes as a result", async () => {
    const vector = ASCON_PRF_SHORT_KAT.find((v) => v.length === 16);
    expect(vector, "the 16-byte vector").toBeTruthy();
    expect(
      await tag(
        "asconprfs",
        keyed(ASCON_KEY, { [OPTION_OUTPUT_LENGTH]: ASCON_PRF_SHORT_KAT_LEN }),
        asconKeyedKatMessage(16),
      ),
    ).toBe(vector!.hex);

    /**
     * Seventeen bytes is a *result*, not an exception. The family's convention: anything a user reaches
     * by typing too much into the input panel comes back as a rendered error naming the alternative.
     */
    const tool = macToolDefinition("asconprfs");
    const spec = specFor("asconprfs", keyed(ASCON_KEY));
    const failed = await tool.compute(spec, asconKeyedKatMessage(17));
    expect(failed.bytes).toBeUndefined();
    expect(failed.error).toMatch(/at most 16 bytes/);
    expect(failed.error).toMatch(/Ascon-PRF/);
  });

  it("Ascon-PRF's output really is a prefix, unlike KMAC's and Skein's", async () => {
    /**
     * Three keyed constructions in this family produce variable-length output and they do not agree on
     * what that means: Ascon-PRF squeezes a stream, so 16 bytes is the first 16 of 64; KMAC and
     * Skein-MAC bind the length into the computation, so the same request gives an unrelated value.
     * Worth pinning, because someone truncating one of the latter two by hand gets a wrong answer.
     */
    const message = ascii("prefix or not");
    const long = await tag("asconprf", keyed(ASCON_KEY, { [OPTION_OUTPUT_LENGTH]: 64 }), message);
    const short = await tag("asconprf", keyed(ASCON_KEY, { [OPTION_OUTPUT_LENGTH]: 16 }), message);
    expect(short).toBe(long.slice(0, 32));

    const kmacLong = await tag(
      "kmac",
      keyed("22".repeat(32), { [OPTION_OUTPUT_LENGTH]: 64 }),
      message,
    );
    const kmacShort = await tag(
      "kmac",
      keyed("22".repeat(32), { [OPTION_OUTPUT_LENGTH]: 16 }),
      message,
    );
    expect(kmacShort).not.toBe(kmacLong.slice(0, 32));
  });

  it("keys of the wrong size are named, and Skein-MAC accepts any", async () => {
    // Ascon takes exactly 16 bytes; the message says what was given as well as what is needed.
    for (const variant of ["asconmac", "asconprf", "asconprfs"]) {
      const found = lint(specFor(variant, keyed("11".repeat(20)))).diagnostics.find(
        (d) => d.code === "M001",
      );
      expect(found?.message, variant).toMatch(/exactly 16 bytes; this one is 20/);
    }

    // Skein-MAC has no such limit -- UBI absorbs a key of any length, which is one of its advantages
    // over HMAC. A 200-byte key must simply work.
    const value = await tag(
      "skeinmac",
      keyed("ab".repeat(200), { [OPTION_OUTPUT_LENGTH]: 32 }),
      ascii("long key"),
    );
    expect(value).toHaveLength(64);
  });

  it("streams to the same tag as one shot, where the construction allows it", async () => {
    const message = new Uint8Array(300);
    for (let i = 0; i < message.length; i++) message[i] = (i * 19 + 7) & 0xff;

    const cases: [string, MacSpec["options"]][] = [
      ["skeinmac", keyed("33".repeat(32), { [OPTION_SKEIN_STATE]: 64, [OPTION_OUTPUT_LENGTH]: 64 })],
      ["asconmac", keyed(ASCON_KEY)],
      ["asconprf", keyed(ASCON_KEY, { [OPTION_OUTPUT_LENGTH]: 48 })],
    ];

    for (const [variant, options] of cases) {
      const oneShot = await tag(variant, options, message);
      const tool = macToolDefinition(variant);
      const spec = specFor(variant, options);
      for (const chunkSize of [1, 17, 32, 64]) {
        const streamed = await runStream(tool.createStream!(spec), rechunk(chunks(message), chunkSize));
        expect(encodeHex(streamed.bytes!), `${variant} @ ${chunkSize}`).toBe(oneShot);
      }
    }

    // PRFShort is the one that cannot stream, and its manifest says so rather than pretending.
    expect(requireMacTool("asconprfs").streaming).toBe(false);
    expect(requireMacTool("skeinmac").streaming).toBe(true);
  });

  it("is not HMAC over the same primitive", async () => {
    /**
     * The distinction the whole group exists for. Skein-MAC keys the UBI tweak and HMAC-Skein nests two
     * Skein calls with pads; Ascon-MAC keys the permutation and there is no HMAC-Ascon at all. Two
     * constructions, two answers -- and someone comparing a tag against the wrong one needs them to
     * differ visibly rather than subtly.
     */
    const message = ascii("native or nested");
    const key = "44".repeat(32);

    const native = await tag(
      "skeinmac",
      keyed(key, { [OPTION_SKEIN_STATE]: 64, [OPTION_OUTPUT_LENGTH]: 64 }),
      message,
    );
    const nested = await tag("hmac", keyed(key, { [OPTION_HASH]: "skein512" }), message);
    expect(native).not.toBe(nested);
    expect(native).toHaveLength(nested.length);
  });

  it("adds four tools without disturbing the eight lint rules", () => {
    // Every rule must still either fire or stay silent sensibly for each new tool; what would break is
    // a rule reaching for an option the tool does not have.
    for (const variant of ["skeinmac", "asconmac", "asconprf", "asconprfs"]) {
      const spec = specFor(
        variant,
        keyed(variant === "skeinmac" ? "55".repeat(32) : ASCON_KEY),
      );
      expect(() => lint(spec), variant).not.toThrow();
      const codes = lint(spec).diagnostics.map((d) => d.code);
      // None of these is an HMAC, so the hash-posture rule cannot apply.
      expect(codes, variant).not.toContain("M003");
    }
  });
});

describe("SipHash-2-4 through the MAC family", () => {
  it("reproduces the reference vectors, with the byte order the reference uses", async () => {
    /**
     * The confusion worth pinning at the family level as well as in `tests/algos-siphash.test.ts`:
     * the reference implementation's `vectors.h` prints the empty-message result as the byte string
     * `310e0edd47db6f72`, and the paper quotes the same value as the integer `0x726fdb47dd0e0e31`.
     * The tool shows the byte string, because that is what a tag is -- so a digest that looks
     * reversed against the paper is correct.
     */
    const key = "000102030405060708090a0b0c0d0e0f";
    expect(await tag("siphash", keyed(key), new Uint8Array(0))).toBe("310e0edd47db6f72");
    expect(await tag("siphash", keyed(key), fromHex("00"))).toBe("fd67dc93c539f874");
  });

  it("says it is not a MAC, because 64 bits is not enough to authenticate with", () => {
    const meta = requireMacTool("siphash");
    // The posture and the width. The reasoning used to be asserted through a `securityNote`, which
    // no longer exists -- and eight bytes of output *is* the reason, so this covers it directly.
    expect(meta.security).toBe("not-a-mac");
    expect(meta.outputLen).toBe(8);
  });

  it("refuses a key that is not 16 bytes, before computing anything", () => {
    for (const bytes of [8, 32]) {
      const result = resolveMac(specFor("siphash", keyed("11".repeat(bytes))));
      expect(result.ok, `${bytes} bytes`).toBe(false);
    }
  });
});

describe("every MAC tool can reach every one of its own options", () => {
  /**
   * The invariant `macToolDefinition`'s `variantTag` exists to hold, asserted rather than assumed.
   *
   * Each tool in this family gets a catalogue containing only its own options, so every one of them
   * should render. That was false for three tools: `variantTag` returned `undefined` for everything
   * but HMAC and KMAC, and `isAvailableOn` reads a missing tag as "not available" -- so Skein-MAC's
   * State size and Tag length selects and Ascon-PRF's and Ascon-PRFShort's output-length field were
   * unreachable from the app. Skein-MAC computed at a 512-bit state and a 64-byte tag with no way to
   * change either.
   *
   * Nothing else could see it. The controls existed, the catalogue was internally consistent, the
   * bindings took the parameters, and every unit test reached them by writing option values directly
   * into a spec -- which is exactly the shape the form never produces when the field does not render.
   */
  it("makes no option invisible under its own default spec", () => {
    for (const id of MAC_TOOL_IDS) {
      const tool = macToolDefinition(id);
      const tag = tool.variantTag?.(tool.createSpec());
      const hidden = tool.catalogue.options
        .filter((option) => !isAvailableOn(option, tag))
        .map((option) => option.id);
      expect(hidden, `${id} has unreachable options`).toEqual([]);
    }
  });
});

describe("HighwayHash as a MAC-family tool", () => {
  async function* single(bytes: Uint8Array) {
    yield bytes;
  }

  /**
   * The algorithm itself is checked against its 195 frozen golden values in
   * `tests/algos-nonchash.test.ts`. What is checked here is the layer between: that the tool's key
   * rule, its width select and its streaming path all reach the implementation.
   *
   * The key is the reference's own -- 00 01 02 ... 1f -- so the expected values below are three of
   * those golden values rather than anything this implementation produced.
   */
  const KEY = [...Array(32).keys()].map((i) => i.toString(16).padStart(2, "0")).join("");

  const specFor = (options: Record<string, string>) => ({
    ...createSpec({ variant: "highwayhash" }),
    options: { key: KEY, keyEncoding: "hex", ...options },
  });

  it("produces the reference's golden value at all three widths, over the empty message", async () => {
    const tool = macToolDefinition("highwayhash");
    /**
     * `kExpected64[0]`, `kExpected128[0..1]` and `kExpected256[0..3]` from google/highwayhash, written
     * little-endian -- and *derived* from the committed fixture by the loop below rather than typed.
     *
     * The first draft of this test wrote the 128- and 256-bit rows by hand and both were wrong, which
     * is the reason this repo's rule is to derive expected values: a hand-written one fails once, gets
     * "corrected" to whatever the code produced, and then asserts the bug forever.
     */
    const le = (words: readonly bigint[]): string =>
      words
        .map((w) =>
          [...Array(8).keys()]
            .map((i) => Number((w >> BigInt(8 * i)) & 0xffn).toString(16).padStart(2, "0"))
            .join(""),
        )
        .join("");
    const cases: [string, string][] = [
      ["8", le(HIGHWAY_64.slice(0, 1))],
      ["16", le(HIGHWAY_128.slice(0, 2))],
      ["32", le(HIGHWAY_256.slice(0, 4))],
    ];
    for (const [width, expected] of cases) {
      const result = await tool.compute(specFor({ outputLength: width }), new Uint8Array(0));
      expect(result.error, `width ${width}`).toBeUndefined();
      expect(encodeHex(result.bytes!), `HighwayHash at ${width} bytes`).toBe(expected);
    }
  });

  it("refuses a key that is not exactly 32 bytes", () => {
    // The resolver's job, not the binding's: the catalogue declares `exact: [32]` and the message
    // has to name the length rather than letting a 16-byte key reach the implementation and throw.
    const short = resolveMac({ ...specFor({}), options: { key: "00".repeat(16), keyEncoding: "hex" } });
    expect(short.ok).toBe(false);
  });

  it("streams identically to the one-shot path, across the 32-byte packet boundary", async () => {
    const tool = macToolDefinition("highwayhash");
    const message = Uint8Array.from({ length: 200 }, (_, i) => (i * 11 + 5) & 0xff);
    for (const width of ["8", "16", "32"]) {
      const spec = specFor({ outputLength: width });
      const oneShot = await tool.compute(spec, message);
      for (const chunk of [1, 7, 32, 33, 64]) {
        const streamed = await runStream(
          tool.createStream!(spec),
          rechunk(single(message), chunk),
        );
        expect(encodeHex(streamed.bytes!), `width ${width} in ${chunk}-byte chunks`).toBe(
          encodeHex(oneShot.bytes!),
        );
      }
    }
  });

  it("gives each width its own answer rather than truncating one", async () => {
    /**
     * The three run four, six and ten finalisation rounds and combine the state differently, so none
     * is a prefix of another. Worth pinning here as well as in the algorithm's own tests, because the
     * *tool* is where a width could get dropped -- a resolver that ignored the select would produce a
     * plausible 8-byte tag for all three.
     */
    const tool = macToolDefinition("highwayhash");
    const message = new TextEncoder().encode("three widths, three functions");
    const [a, b, c] = await Promise.all(
      ["8", "16", "32"].map(async (width) =>
        encodeHex((await tool.compute(specFor({ outputLength: width }), message)).bytes!),
      ),
    );
    expect(a).toHaveLength(16);
    expect(b).toHaveLength(32);
    expect(c).toHaveLength(64);
    expect(b!.slice(0, 16)).not.toBe(a);
    expect(c!.slice(0, 32)).not.toBe(b);
  });
});
