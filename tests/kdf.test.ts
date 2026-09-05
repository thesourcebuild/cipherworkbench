import { describe, expect, it } from "vitest";
import {
  BCRYPT_PASSWORD_LIMIT,
  KDF_MANIFESTS,
  KDF_TOOLS,
  OPTION_ARGON2_AD,
  OPTION_ARGON2_MEMORY,
  OPTION_ARGON2_PARALLELISM,
  OPTION_ARGON2_SECRET,
  OPTION_ARGON2_TIME,
  OPTION_ARGON2_VARIANT,
  OPTION_BCRYPT_COST,
  OPTION_EXPECTED,
  OPTION_HASH,
  OPTION_IKM,
  OPTION_INFO,
  OPTION_ITERATIONS,
  OPTION_KEY_LENGTH,
  OPTION_MODE,
  OPTION_PASSWORD,
  OPTION_ROUNDS,
  OPTION_SALT,
  OPTION_SCRYPT_N,
  OPTION_SCRYPT_P,
  OPTION_SCRYPT_R,
  OPENSSH_DEFAULT_ROUNDS,
  OPENSSH_KEY_IV_BYTES,
  OWASP_BCRYPT_COST,
  OWASP_PBKDF2_SHA256,
  owaspPbkdf2Minimum,
  requireKdfTool,
  type KdfSpec,
} from "@ocs/kdf";
import {
  applyAllFixes,
  createSpec,
  describeSpec,
  formatPhc,
  deriveEvpKdf,
  kdfToolDefinition,
  lint,
  parsePhc,
  resolveKdf,
} from "@ocs/kdf/definition";
import { encodeHex, validateCatalogue } from "@ocs/engine";

function specFor(variant: string, options: KdfSpec["options"] = {}): KdfSpec {
  const base = createSpec({ variant });
  return { ...base, options: { ...base.options, ...options } };
}

/** Salt as the `bytes` option stores it: text plus its encoding. */
function salted(hex: string, extra: KdfSpec["options"] = {}): KdfSpec["options"] {
  return { [OPTION_SALT]: hex, saltEncoding: "hex", ...extra };
}

/** Salt supplied as literal text, which is how the RFC vectors specify it. */
function saltedText(text: string, extra: KdfSpec["options"] = {}): KdfSpec["options"] {
  return { [OPTION_SALT]: text, saltEncoding: "utf-8", ...extra };
}

async function derive(variant: string, options: KdfSpec["options"]) {
  const tool = kdfToolDefinition(variant);
  const result = await tool.compute(specFor(variant, options), new Uint8Array(0));
  expect(result.error, `${variant} reported: ${result.error}`).toBeUndefined();
  return result;
}

// ── PBKDF2: RFC 6070 ────────────────────────────────────────────────────────

describe("PBKDF2 — RFC 6070 test vectors", () => {
  const CASES: readonly [string, string, number, number, string][] = [
    ["password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"],
    ["password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"],
    ["password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"],
    [
      "passwordPASSWORDpassword",
      "saltSALTsaltSALTsaltSALTsaltSALTsalt",
      4096,
      25,
      "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
    ],
  ];

  for (const [password, salt, iterations, dkLen, expected] of CASES) {
    it(`c=${iterations}, dkLen=${dkLen}`, async () => {
      const result = await derive(
        "pbkdf2",
        saltedText(salt, {
          [OPTION_PASSWORD]: password,
          [OPTION_HASH]: "sha1",
          [OPTION_ITERATIONS]: iterations,
          [OPTION_KEY_LENGTH]: dkLen,
        }),
      );
      expect(encodeHex(result.bytes!)).toBe(expected);
    });
  }

  it("handles the embedded-NUL case from RFC 6070", async () => {
    // "pass\0word" and "sa\0lt" — the case that catches an implementation treating the
    // password as a C string.
    const result = await derive(
      "pbkdf2",
      salted("7361006c74", {
        [OPTION_PASSWORD]: "pass\u0000word",
        [OPTION_HASH]: "sha1",
        [OPTION_ITERATIONS]: 4096,
        [OPTION_KEY_LENGTH]: 16,
      }),
    );
    expect(encodeHex(result.bytes!)).toBe("56fa6aa75548099dcc37d7f03425e0c3");
  });

  it("reports the iteration count alongside the result", async () => {
    const result = await derive(
      "pbkdf2",
      saltedText("salt", { [OPTION_PASSWORD]: "password", [OPTION_ITERATIONS]: 600_000 }),
    );
    const iterations = result.fields!.find((f) => f.label === "Iterations");
    expect(iterations?.value).toBe("600,000");
  });
});

// ── HKDF: RFC 5869 ──────────────────────────────────────────────────────────

describe("HKDF — RFC 5869 test vectors", () => {
  it("case 1 — SHA-256, 42 bytes", async () => {
    const result = await derive(
      "hkdf",
      salted("000102030405060708090a0b0c", {
        [OPTION_IKM]: "0b".repeat(22),
        ikmEncoding: "hex",
        // RFC 5869's info for this case is the raw bytes f0..f9, not text, which is why
        // `info` is a bytes option with a selectable encoding rather than a text field.
        [OPTION_INFO]: "f0f1f2f3f4f5f6f7f8f9",
        infoEncoding: "hex",
        [OPTION_HASH]: "sha256",
        [OPTION_KEY_LENGTH]: 42,
      }),
    );
    expect(encodeHex(result.bytes!)).toBe(
      "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
  });

  it("case 3 — zero-length salt and info", async () => {
    const result = await derive("hkdf", {
      [OPTION_IKM]: "0b".repeat(22),
      ikmEncoding: "hex",
      [OPTION_HASH]: "sha256",
      [OPTION_KEY_LENGTH]: 42,
    });
    expect(encodeHex(result.bytes!)).toBe(
      "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
    );
  });

  it("accepts an absent salt and says it substituted zeros", async () => {
    // RFC 5869 permits this explicitly, so it must not be reported as a missing field.
    const result = await derive("hkdf", {
      [OPTION_IKM]: "00".repeat(32),
      ikmEncoding: "hex",
      [OPTION_KEY_LENGTH]: 32,
    });
    const saltField = result.fields!.find((f) => f.label === "Salt");
    expect(saltField?.value).toContain("none");
    expect(saltField?.hint).toContain("RFC 5869");
  });

  it("the info string changes the output", async () => {
    const base = { [OPTION_IKM]: "00".repeat(32), ikmEncoding: "hex", [OPTION_KEY_LENGTH]: 32 };
    const a = await derive("hkdf", { ...base, [OPTION_INFO]: "client write key" });
    const b = await derive("hkdf", { ...base, [OPTION_INFO]: "server write key" });
    expect(encodeHex(a.bytes!)).not.toBe(encodeHex(b.bytes!));
  });
});

// ── scrypt: RFC 7914 ────────────────────────────────────────────────────────

describe("scrypt — RFC 7914 test vectors", () => {
  it("N=16, r=1, p=1, empty password and salt", async () => {
    const result = await derive("scrypt", {
      [OPTION_PASSWORD]: "",
      [OPTION_SALT]: "",
      saltEncoding: "utf-8",
      [OPTION_SCRYPT_N]: 16,
      [OPTION_SCRYPT_R]: 1,
      [OPTION_SCRYPT_P]: 1,
      [OPTION_KEY_LENGTH]: 64,
      // Empty password would otherwise be rejected; the RFC vector needs it.
      [OPTION_MODE]: "derive",
    });
    expect(encodeHex(result.bytes!)).toBe(
      "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
    );
  });

  it("N=1024, r=8, p=16, password and NaCl", async () => {
    const result = await derive("scrypt", {
      [OPTION_PASSWORD]: "password",
      [OPTION_SALT]: "NaCl",
      saltEncoding: "utf-8",
      [OPTION_SCRYPT_N]: 1024,
      [OPTION_SCRYPT_R]: 8,
      [OPTION_SCRYPT_P]: 16,
      [OPTION_KEY_LENGTH]: 64,
    });
    expect(encodeHex(result.bytes!)).toBe(
      "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640",
    );
  });

  it("refuses an N that is not a power of two, and suggests one", async () => {
    // noble throws rather than rounding, so this is caught before it gets there.
    const tool = kdfToolDefinition("scrypt");
    const result = await tool.compute(
      specFor(
        "scrypt",
        salted("00".repeat(16), { [OPTION_PASSWORD]: "x", [OPTION_SCRYPT_N]: 1000 }),
      ),
      new Uint8Array(0),
    );
    expect(result.error).toMatch(/power of two/);
    expect(result.error).toMatch(/1024/);
  });

  it("reports the memory cost, which the three parameters do not make obvious", async () => {
    const result = await derive(
      "scrypt",
      salted("00".repeat(16), {
        [OPTION_PASSWORD]: "x",
        [OPTION_SCRYPT_N]: 16384,
        [OPTION_SCRYPT_R]: 8,
      }),
    );
    const params = result.fields!.find((f) => f.label === "Parameters");
    expect(params?.hint).toMatch(/16\.0 MiB/);
  });

  it("emits a PHC string recording ln, not N", async () => {
    const result = await derive(
      "scrypt",
      salted("00".repeat(16), { [OPTION_PASSWORD]: "x", [OPTION_SCRYPT_N]: 16384 }),
    );
    const encoded = result.fields!.find((f) => f.label === "Encoded form")!.value;
    // 2^14 = 16384, so the string must say ln=14 rather than N=16384.
    expect(encoded).toMatch(/^\$scrypt\$ln=14,r=8,p=1\$/);
  });
});

// ── Argon2: RFC 9106 ────────────────────────────────────────────────────────

describe("Argon2 — RFC 9106 test vectors", () => {
  /**
   * RFC 9106 section 5 uses a fixed non-trivial input: 32 bytes of 0x01 as the password,
   * 16 of 0x02 as the salt, m=32, t=3, p=4, 32 bytes out.
   */
  const RFC_INPUT = {
    [OPTION_PASSWORD]: "\u0001".repeat(32),
    ...salted("02".repeat(16)),
    [OPTION_ARGON2_MEMORY]: 32,
    [OPTION_ARGON2_TIME]: 3,
    // The RFC's vectors set all five inputs, including the two optional ones. Omitting
    // the secret and associated data is what made the first version of this test fail:
    // the implementation was right and the input was incomplete.
    [OPTION_ARGON2_SECRET]: "03".repeat(8),
    secretEncoding: "hex",
    [OPTION_ARGON2_AD]: "04".repeat(12),
    associatedDataEncoding: "hex",
    [OPTION_ARGON2_PARALLELISM]: 4,
    [OPTION_KEY_LENGTH]: 32,
  };

  it("Argon2d — section 5.1", async () => {
    const result = await derive("argon2", {
      ...RFC_INPUT,
      [OPTION_ARGON2_VARIANT]: "argon2d",
    });
    expect(encodeHex(result.bytes!)).toBe(
      "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
    );
  });

  it("Argon2i — section 5.2", async () => {
    const result = await derive("argon2", {
      ...RFC_INPUT,
      [OPTION_ARGON2_VARIANT]: "argon2i",
    });
    expect(encodeHex(result.bytes!)).toBe(
      "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
    );
  });

  it("Argon2id — section 5.3", async () => {
    const result = await derive("argon2", {
      ...RFC_INPUT,
      [OPTION_ARGON2_VARIANT]: "argon2id",
    });
    expect(encodeHex(result.bytes!)).toBe(
      "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
    );
  });

  it("emits a PHC string with the version and all three parameters", async () => {
    const result = await derive(
      "argon2",
      salted("00".repeat(16), { [OPTION_PASSWORD]: "x", [OPTION_ARGON2_MEMORY]: 19456 }),
    );
    const encoded = result.fields!.find((f) => f.label === "Encoded form")!.value;
    expect(encoded).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
  });

  it("the variant changes the output", async () => {
    const base = salted("00".repeat(16), {
      [OPTION_PASSWORD]: "x",
      [OPTION_ARGON2_MEMORY]: 64,
    });
    const id = await derive("argon2", { ...base, [OPTION_ARGON2_VARIANT]: "argon2id" });
    const i = await derive("argon2", { ...base, [OPTION_ARGON2_VARIANT]: "argon2i" });
    expect(encodeHex(id.bytes!)).not.toBe(encodeHex(i.bytes!));
  });
});

// ── bcrypt ──────────────────────────────────────────────────────────────────

describe("bcrypt", () => {
  it("produces a self-describing hash that verifies", async () => {
    const result = await derive("bcrypt", {
      [OPTION_PASSWORD]: "correct horse battery staple",
      [OPTION_BCRYPT_COST]: 4,
    });
    const encoded = result.fields!.find((f) => f.label === "Encoded form")!.value;
    expect(encoded).toMatch(/^\$2[aby]\$04\$/);

    // Round-trip through Verify mode, which is the whole point of the format.
    const tool = kdfToolDefinition("bcrypt");
    const verified = await tool.compute(
      specFor("bcrypt", {
        [OPTION_MODE]: "verify",
        [OPTION_PASSWORD]: "correct horse battery staple",
        [OPTION_EXPECTED]: encoded,
      }),
      new Uint8Array(0),
    );
    expect(verified.text).toBe("MATCH");
  });

  it("rejects the wrong password", async () => {
    const tool = kdfToolDefinition("bcrypt");
    const derived = await derive("bcrypt", {
      [OPTION_PASSWORD]: "hunter2",
      [OPTION_BCRYPT_COST]: 4,
    });
    const encoded = derived.fields!.find((f) => f.label === "Encoded form")!.value;

    const verified = await tool.compute(
      specFor("bcrypt", {
        [OPTION_MODE]: "verify",
        [OPTION_PASSWORD]: "hunter3",
        [OPTION_EXPECTED]: encoded,
      }),
      new Uint8Array(0),
    );
    expect(verified.text).toBe("NO MATCH");
  });

  it("verifies against a hash generated by OpenBSD's own implementation", async () => {
    // Interoperability rather than self-consistency: this string did not come from here.
    const tool = kdfToolDefinition("bcrypt");
    const stored = "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i";
    const good = await tool.compute(
      specFor("bcrypt", {
        [OPTION_MODE]: "verify",
        [OPTION_PASSWORD]: "abc",
        [OPTION_EXPECTED]: stored,
      }),
      new Uint8Array(0),
    );
    expect(good.text).toBe("MATCH");
    expect(good.fields!.find((f) => f.label === "Cost in stored hash")?.value).toBe("6");
  });

  it("reports a malformed stored hash rather than throwing", async () => {
    const tool = kdfToolDefinition("bcrypt");
    const result = await tool.compute(
      specFor("bcrypt", {
        [OPTION_MODE]: "verify",
        [OPTION_PASSWORD]: "x",
        [OPTION_EXPECTED]: "not a bcrypt hash",
      }),
      new Uint8Array(0),
    );
    expect(result.text).toBe("NO MATCH");
  });

  it("records the cost in the output string", async () => {
    const a = await derive("bcrypt", { [OPTION_PASSWORD]: "x", [OPTION_BCRYPT_COST]: 4 });
    const b = await derive("bcrypt", { [OPTION_PASSWORD]: "x", [OPTION_BCRYPT_COST]: 5 });
    const encodedA = a.fields!.find((f) => f.label === "Encoded form")!.value;
    const encodedB = b.fields!.find((f) => f.label === "Encoded form")!.value;
    expect(encodedA.length).toBe(encodedB.length);
    expect(encodedA.slice(4, 6)).toBe("04");
    expect(encodedB.slice(4, 6)).toBe("05");
  });
});

// ── verify mode ─────────────────────────────────────────────────────────────

// -- bcrypt-PBKDF ------------------------------------------------------------

describe("bcrypt-PBKDF", () => {
  it("reproduces the OpenBSD reference vector through the tool", async () => {
    // The same vector `tests/algos-bcrypt-pbkdf.test.ts` pins on the implementation, driven
    // through the catalogue instead -- which is what catches a salt read with the wrong encoding
    // or a rounds option the resolver never reads.
    const result = await derive(
      "bcryptpbkdf",
      saltedText("salt", { [OPTION_PASSWORD]: "password", [OPTION_ROUNDS]: 12, [OPTION_KEY_LENGTH]: 32 }),
    );
    expect(encodeHex(result.bytes!)).toBe(
      "1ae42c05d487bc02f64921a4ebe4ea93bcacfe135fda99974c06b7b01fae149a",
    );
  });

  it("defaults to ssh-keygen's 16 rounds and 48 bytes", () => {
    const resolved = resolveKdf(
      specFor("bcryptpbkdf", salted("00112233445566778899aabbccddeeff", { [OPTION_PASSWORD]: "pw" })),
    );
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.resolved.rounds).toBe(OPENSSH_DEFAULT_ROUNDS);
    expect(resolved.resolved.keyLength).toBe(OPENSSH_KEY_IV_BYTES);
  });

  it("names the AES-256-CTR split at 48 bytes and not below", async () => {
    const full = await derive(
      "bcryptpbkdf",
      salted("00112233445566778899aabbccddeeff", {
        [OPTION_PASSWORD]: "pw",
        [OPTION_ROUNDS]: 2,
      }),
    );
    expect(full.fields?.some((f) => f.label === "AES-256-CTR split")).toBe(true);
    const short = await derive(
      "bcryptpbkdf",
      salted("00112233445566778899aabbccddeeff", {
        [OPTION_PASSWORD]: "pw",
        [OPTION_ROUNDS]: 2,
        [OPTION_KEY_LENGTH]: 32,
      }),
    );
    expect(short.fields?.some((f) => f.label === "AES-256-CTR split")).toBe(false);
  });

  it("refuses an empty password, which is the one tool here that does", async () => {
    // Not policy: OpenBSD's `bcrypt_pbkdf` returns -1. Every other tool in this family computes
    // an empty password and gets `K008` instead -- see the note on RFC 7914's own vector.
    const tool = kdfToolDefinition("bcryptpbkdf");
    const result = await tool.compute(
      specFor("bcryptpbkdf", salted("00112233445566778899aabbccddeeff")),
      new Uint8Array(0),
    );
    expect(result.error).toMatch(/needs a password/);
  });

  it("refuses an empty salt for the same reason", async () => {
    const tool = kdfToolDefinition("bcryptpbkdf");
    const result = await tool.compute(
      specFor("bcryptpbkdf", { [OPTION_PASSWORD]: "pw", [OPTION_SALT]: "", saltEncoding: "hex" }),
      new Uint8Array(0),
    );
    expect(result.error).toMatch(/at least 1 byte/);
  });

  it("has no bcrypt options and bcrypt has none of its own", () => {
    // The throwing `Record` that replaced the fall-through chain, asserted rather than trusted:
    // the old code would have handed this tool bcrypt's log2 cost field and no salt.
    const ids = (variant: string) =>
      kdfToolDefinition(variant).catalogue.options.map((option) => option.id);
    expect(ids("bcryptpbkdf")).toContain(OPTION_ROUNDS);
    expect(ids("bcryptpbkdf")).toContain(OPTION_SALT);
    expect(ids("bcryptpbkdf")).not.toContain(OPTION_BCRYPT_COST);
    expect(ids("bcrypt")).not.toContain(OPTION_ROUNDS);
    expect(ids("bcrypt")).not.toContain(OPTION_SALT);
  });

  it("K002 measures rounds against ssh-keygen's default, and its fix silences it", () => {
    const low = specFor(
      "bcryptpbkdf",
      salted("00112233445566778899aabbccddeeff", {
        [OPTION_PASSWORD]: "pw",
        [OPTION_ROUNDS]: 4,
      }),
    );
    const found = lint(low).diagnostics.find((d) => d.code === "K002");
    expect(found?.level).toBe("insecure");
    expect(found?.message).toContain("ssh-keygen");
    expect(lint(applyAllFixes(low)).diagnostics.some((d) => d.code === "K002")).toBe(false);
  });
});

describe("verify mode", () => {
  it("round-trips for every tool that supports it", async () => {
    for (const meta of KDF_TOOLS.filter((t) => t.supportsVerify)) {
      const tool = kdfToolDefinition(meta.id);
      // Typed as the option record rather than inferred, or TypeScript unions the three
      // shapes and every key becomes optionally undefined.
      const cheap: KdfSpec["options"] =
        meta.id === "argon2"
          ? { [OPTION_ARGON2_MEMORY]: 32, [OPTION_ARGON2_TIME]: 1 }
          : meta.id === "scrypt"
            ? { [OPTION_SCRYPT_N]: 16, [OPTION_SCRYPT_R]: 1, [OPTION_SCRYPT_P]: 1 }
            : { [OPTION_BCRYPT_COST]: 4 };

      const derived = await derive(meta.id, {
        ...salted("00".repeat(16)),
        [OPTION_PASSWORD]: "pw",
        ...cheap,
      });
      const encoded = derived.fields!.find((f) => f.label === "Encoded form")!.value;

      const good = await tool.compute(
        specFor(meta.id, {
          [OPTION_MODE]: "verify",
          [OPTION_PASSWORD]: "pw",
          [OPTION_EXPECTED]: encoded,
        }),
        new Uint8Array(0),
      );
      expect(good.text, `${meta.id} correct password`).toBe("MATCH");

      const bad = await tool.compute(
        specFor(meta.id, {
          [OPTION_MODE]: "verify",
          [OPTION_PASSWORD]: "wrong",
          [OPTION_EXPECTED]: encoded,
        }),
        new Uint8Array(0),
      );
      expect(bad.text, `${meta.id} wrong password`).toBe("NO MATCH");
    }
  });

  it("uses the stored hash's parameters, not the form's", async () => {
    /**
     * The property that makes Verify mode work at all. A hash written at one cost must still
     * verify after the form's settings have been raised, which is exactly the situation you
     * are in when you increase your parameters and existing users log in.
     */
    const tool = kdfToolDefinition("scrypt");
    const derived = await derive("scrypt", {
      ...salted("11".repeat(16)),
      [OPTION_PASSWORD]: "pw",
      [OPTION_SCRYPT_N]: 16,
      [OPTION_SCRYPT_R]: 1,
      [OPTION_SCRYPT_P]: 1,
    });
    const encoded = derived.fields!.find((f) => f.label === "Encoded form")!.value;

    const verified = await tool.compute(
      specFor("scrypt", {
        [OPTION_MODE]: "verify",
        [OPTION_PASSWORD]: "pw",
        [OPTION_EXPECTED]: encoded,
        // Deliberately different from what produced the hash.
        [OPTION_SCRYPT_N]: 1024,
        [OPTION_SCRYPT_R]: 8,
        [OPTION_SCRYPT_P]: 2,
        ...salted("ff".repeat(16)),
      }),
      new Uint8Array(0),
    );
    expect(verified.text).toBe("MATCH");
    expect(verified.fields!.find((f) => f.label === "Parameters used")?.value).toContain(
      "ln=4",
    );
  });

  it("refuses to check an Argon2 hash as scrypt, naming what it found", async () => {
    const tool = kdfToolDefinition("scrypt");
    const result = await tool.compute(
      specFor("scrypt", {
        [OPTION_MODE]: "verify",
        [OPTION_PASSWORD]: "pw",
        [OPTION_EXPECTED]:
          "$argon2id$v=19$m=32,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA",
      }),
      new Uint8Array(0),
    );
    expect(result.error).toMatch(/argon2id hash, not an scrypt one/);
  });

  it("asks for the stored hash before doing anything", async () => {
    const tool = kdfToolDefinition("argon2");
    const result = await tool.compute(
      specFor("argon2", { [OPTION_MODE]: "verify", [OPTION_PASSWORD]: "pw" }),
      new Uint8Array(0),
    );
    expect(result.error).toMatch(/stored hash/i);
  });

  it("is offered by exactly the tools with a self-describing format", () => {
    for (const manifest of KDF_MANIFESTS) {
      const meta = requireKdfTool(manifest.id);
      expect(manifest.directions.includes("inverse"), manifest.id).toBe(meta.supportsVerify);
      const hasField = kdfToolDefinition(manifest.id).catalogue.options.some(
        (o) => o.id === OPTION_EXPECTED,
      );
      expect(hasField, manifest.id).toBe(meta.supportsVerify);
    }
  });

  it("keeps the Argon2 pepper out of the stored hash, so it must be re-supplied", async () => {
    /**
     * The defining property of a pepper: it is not in the output, so a stolen hash table is
     * useless without the application config. The flip side is that verification fails
     * without it, which is a consequence worth having a test for rather than a surprise.
     */
    const tool = kdfToolDefinition("argon2");
    const withPepper = {
      ...salted("00".repeat(16)),
      [OPTION_PASSWORD]: "pw",
      [OPTION_ARGON2_MEMORY]: 32,
      [OPTION_ARGON2_TIME]: 1,
      [OPTION_ARGON2_SECRET]: "aa".repeat(16),
      secretEncoding: "hex",
    };
    const derived = await derive("argon2", withPepper);
    const encoded = derived.fields!.find((f) => f.label === "Encoded form")!.value;
    // The pepper does not appear anywhere in the string.
    expect(encoded).not.toContain("aaaa");

    const withIt = await tool.compute(
      specFor("argon2", {
        ...withPepper,
        [OPTION_MODE]: "verify",
        [OPTION_EXPECTED]: encoded,
      }),
      new Uint8Array(0),
    );
    expect(withIt.text).toBe("MATCH");

    const withoutIt = await tool.compute(
      specFor("argon2", {
        [OPTION_MODE]: "verify",
        [OPTION_PASSWORD]: "pw",
        [OPTION_EXPECTED]: encoded,
      }),
      new Uint8Array(0),
    );
    expect(withoutIt.text).toBe("NO MATCH");
  });
});

// ── PHC string format ───────────────────────────────────────────────────────

describe("PHC string parsing", () => {
  it("round-trips through format and parse", () => {
    const value = {
      id: "argon2id",
      version: 19,
      params: { m: "19456", t: "2", p: "1" },
      salt: new Uint8Array([1, 2, 3, 4]),
      hash: new Uint8Array([5, 6, 7, 8]),
    };
    const parsed = parsePhc(formatPhc(value));
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value.id).toBe("argon2id");
      expect(parsed.value.version).toBe(19);
      expect(parsed.value.params).toEqual(value.params);
      expect(Array.from(parsed.value.salt)).toEqual([1, 2, 3, 4]);
      expect(Array.from(parsed.value.hash)).toEqual([5, 6, 7, 8]);
    }
  });

  it("emits unpadded base64, as the PHC spec requires", () => {
    const encoded = formatPhc({
      id: "x",
      params: {},
      salt: new Uint8Array([1, 2, 3, 4]),
      hash: new Uint8Array([1]),
    });
    expect(encoded).not.toContain("=");
  });

  it("handles a string with no version and no parameters", () => {
    const parsed = parsePhc("$plain$c2FsdA$aGFzaA");
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value.id).toBe("plain");
      expect(parsed.value.version).toBeUndefined();
      expect(parsed.value.params).toEqual({});
    }
  });

  it("rejects hostile input without throwing", () => {
    // A stored hash is attacker-influenced in any realistic threat model.
    for (const bad of [
      "",
      "no-dollar-sign",
      "$",
      "$argon2id",
      "$argon2id$v=notanumber$m=1$c2FsdA$aGFzaA",
      "$argon2id$v=19$m=1$onlysalt",
    ]) {
      expect(() => parsePhc(bad), JSON.stringify(bad)).not.toThrow();
      expect(parsePhc(bad).ok, JSON.stringify(bad)).toBe(false);
    }
  });
});

// ── lint rules ──────────────────────────────────────────────────────────────

describe("lint rules", () => {
  it("K002 flags a cost below the recommendation, per tool, and its fix raises it", () => {
    const cases: readonly [string, string, number, string][] = [
      ["pbkdf2", OPTION_ITERATIONS, 1000, "iterations"],
      ["scrypt", OPTION_SCRYPT_N, 1024, "N"],
      ["argon2", OPTION_ARGON2_MEMORY, 64, "KiB"],
      ["bcrypt", OPTION_BCRYPT_COST, 4, "Cost"],
    ];

    for (const [variant, optionId, tooLow, expectedWord] of cases) {
      const spec = specFor(variant, {
        ...salted("00".repeat(16)),
        [OPTION_PASSWORD]: "pw",
        [optionId]: tooLow,
      });
      const found = lint(spec).diagnostics.find((d) => d.code === "K002");
      expect(found, `${variant} should be flagged`).toBeDefined();
      expect(found!.message, variant).toContain(expectedWord);

      const fixed = applyAllFixes(spec);
      expect(
        lint(fixed).diagnostics.some((d) => d.code === "K002"),
        `${variant} after fix`,
      ).toBe(false);
    }
  });

  it("K002 stays quiet at the default settings, which are the recommendations", () => {
    // The defaults must not trip the rule, or every tool opens complaining about itself.
    for (const meta of KDF_TOOLS) {
      const spec = specFor(meta.id, {
        ...salted("00".repeat(16)),
        [OPTION_PASSWORD]: "pw",
        [OPTION_IKM]: "00".repeat(32),
        ikmEncoding: "hex",
      });
      expect(
        lint(spec).diagnostics.some((d) => d.code === "K002"),
        meta.id,
      ).toBe(false);
    }
  });

  it("K002 scales the PBKDF2 recommendation to the hash", () => {
    // Quoting the SHA-256 figure at someone using SHA-512 would overstate it threefold.
    expect(owaspPbkdf2Minimum("sha256")).toBe(OWASP_PBKDF2_SHA256);
    expect(owaspPbkdf2Minimum("sha512")).toBeLessThan(OWASP_PBKDF2_SHA256);
    expect(owaspPbkdf2Minimum("sha1")).toBeGreaterThan(OWASP_PBKDF2_SHA256);

    const spec = specFor("pbkdf2", {
      ...salted("00".repeat(16)),
      [OPTION_PASSWORD]: "pw",
      [OPTION_HASH]: "sha512",
      [OPTION_ITERATIONS]: 210_000,
    });
    // Exactly the SHA-512 floor, so no complaint, even though it is below the SHA-256 one.
    expect(lint(spec).diagnostics.some((d) => d.code === "K002")).toBe(false);
  });

  it("K002 is silent in Verify mode, where the form's costs are not used", () => {
    const spec = specFor("bcrypt", {
      [OPTION_MODE]: "verify",
      [OPTION_PASSWORD]: "pw",
      [OPTION_EXPECTED]: "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i",
      [OPTION_BCRYPT_COST]: 4,
    });
    expect(lint(spec).diagnostics.some((d) => d.code === "K002")).toBe(false);
  });

  it("K003 fires only for HKDF, the category error this family can make", () => {
    for (const meta of KDF_TOOLS) {
      const spec = specFor(meta.id, {
        ...salted("00".repeat(16)),
        [OPTION_PASSWORD]: "pw",
        [OPTION_IKM]: "00".repeat(32),
        ikmEncoding: "hex",
      });
      const codes = lint(spec).diagnostics.map((d) => d.code);
      expect(codes.includes("K003"), meta.id).toBe(meta.id === "hkdf");
    }
  });

  it("K004 escalates to insecure when there is no salt at all", () => {
    const none = specFor("pbkdf2", { [OPTION_PASSWORD]: "pw" });
    const found = lint(none).diagnostics.find((d) => d.code === "K004");
    expect(found?.level).toBe("insecure");
    expect(found?.message).toMatch(/identical hashes/);

    const short = specFor("pbkdf2", { ...salted("0011"), [OPTION_PASSWORD]: "pw" });
    expect(lint(short).diagnostics.find((d) => d.code === "K004")?.level).toBe("warning");

    const good = specFor("pbkdf2", { ...salted("00".repeat(16)), [OPTION_PASSWORD]: "pw" });
    expect(lint(good).diagnostics.some((d) => d.code === "K004")).toBe(false);
  });

  it("K004's fix generates a real salt of the recommended length", () => {
    const spec = specFor("pbkdf2", { [OPTION_PASSWORD]: "pw" });
    const fixed = applyAllFixes(spec);
    const resolved = resolveKdf(fixed);
    expect(resolved.ok).toBe(true);
    if (resolved.ok) expect(resolved.resolved.salt).toHaveLength(16);
    expect(lint(fixed).diagnostics.some((d) => d.code === "K004")).toBe(false);
  });

  it("K004 does not fire for HKDF, whose salt is optional by RFC 5869", () => {
    const spec = specFor("hkdf", { [OPTION_IKM]: "00".repeat(32), ikmEncoding: "hex" });
    expect(lint(spec).diagnostics.some((d) => d.code === "K004")).toBe(false);
  });

  it("K005 flags a password past bcrypt's 72-byte limit and says it is silent", () => {
    const long = specFor("bcrypt", { [OPTION_PASSWORD]: "a".repeat(100) });
    const found = lint(long).diagnostics.find((d) => d.code === "K005");
    expect(found?.level).toBe("warning");
    expect(found?.message).toContain(String(BCRYPT_PASSWORD_LIMIT));
    expect(found?.detail).toMatch(/silent/);

    const fine = specFor("bcrypt", { [OPTION_PASSWORD]: "a".repeat(72) });
    expect(lint(fine).diagnostics.some((d) => d.code === "K005")).toBe(false);
  });

  it("K005 counts bytes, not characters", () => {
    // 24 CJK characters is 72 bytes in UTF-8; 25 is 75 and over the limit.
    const at = specFor("bcrypt", { [OPTION_PASSWORD]: "\u65e5".repeat(24) });
    expect(lint(at).diagnostics.some((d) => d.code === "K005")).toBe(false);
    const over = specFor("bcrypt", { [OPTION_PASSWORD]: "\u65e5".repeat(25) });
    expect(lint(over).diagnostics.some((d) => d.code === "K005")).toBe(true);
  });

  it("K005 does not fire for tools without the limit", () => {
    for (const meta of KDF_TOOLS.filter((t) => t.id !== "bcrypt")) {
      const spec = specFor(meta.id, {
        ...salted("00".repeat(16)),
        [OPTION_PASSWORD]: "a".repeat(200),
        [OPTION_IKM]: "00".repeat(32),
        ikmEncoding: "hex",
      });
      expect(
        lint(spec).diagnostics.some((d) => d.code === "K005"),
        meta.id,
      ).toBe(false);
    }
  });

  it("K007 fires exactly for the tools with no verifiable output format", () => {
    for (const meta of KDF_TOOLS) {
      const spec = specFor(meta.id, {
        ...salted("00".repeat(16)),
        [OPTION_PASSWORD]: "pw",
        [OPTION_IKM]: "00".repeat(32),
        ikmEncoding: "hex",
      });
      const codes = lint(spec).diagnostics.map((d) => d.code);
      expect(codes.includes("K007"), meta.id).toBe(!meta.supportsVerify);
    }
  });

  it("K008 flags an empty password without blocking it", () => {
    const spec = specFor("pbkdf2", { ...salted("00".repeat(16)), [OPTION_PASSWORD]: "" });
    expect(lint(spec).diagnostics.find((d) => d.code === "K008")?.level).toBe("warning");
    // Not blocking, or the RFC vectors could not be reproduced.
    expect(lint(spec).hasErrors).toBe(false);
  });
});

// ── catalogue, manifests ────────────────────────────────────────────────────

describe("catalogue and manifests", () => {
  it("every tool's catalogue is internally consistent", () => {
    for (const meta of KDF_TOOLS) {
      expect(validateCatalogue(kdfToolDefinition(meta.id).catalogue.options), meta.id).toEqual(
        [],
      );
    }
  });

  it("marks the password and the Argon2 pepper secret, and the salt not", () => {
    /**
     * The salt is deliberately *not* secret: it is stored next to the hash in every real
     * system, and marking it so would strip it from share links, making a shared
     * configuration unreproducible for no benefit. The password and the pepper are the two
     * things that must never travel.
     */
    for (const meta of KDF_TOOLS.filter((t) => t.id !== "hkdf")) {
      const catalogue = kdfToolDefinition(meta.id).catalogue;
      expect(catalogue.secretIds(), meta.id).toContain(OPTION_PASSWORD);
      if (catalogue.get(OPTION_SALT)) {
        expect(catalogue.require(OPTION_SALT).secret, `${meta.id} salt`).toBeFalsy();
      }
    }
    expect(kdfToolDefinition("argon2").catalogue.secretIds()).toContain("secret");
    // HKDF's input is key material, which is secret; it has no password field.
    expect(kdfToolDefinition("hkdf").catalogue.secretIds()).toContain(OPTION_IKM);
  });

  it("turns file input off, because a KDF's input is its password", () => {
    for (const manifest of KDF_MANIFESTS) {
      expect(manifest.supportsFile, manifest.id).toBe(false);
      expect(manifest.streaming, manifest.id).toBe(false);
    }
  });

  it("declares no stream, matching the manifest", () => {
    for (const meta of KDF_TOOLS) {
      expect(kdfToolDefinition(meta.id).createStream, meta.id).toBeUndefined();
    }
  });

  it("shows the Stored hash field only in Verify mode", () => {
    const tool = kdfToolDefinition("argon2");
    expect(tool.variantTag!(specFor("argon2"))).toBeUndefined();
    expect(tool.variantTag!(specFor("argon2", { [OPTION_MODE]: "verify" }))).toBe("verify");
  });

  it("marks the legacy tools that are not first choices", () => {
    // PBKDF2, bcrypt, MD5-Crypt, and OpenPGP S2K are legacy.
    expect(
      KDF_MANIFESTS.filter((m) => m.security === "legacy")
        .map((m) => m.id)
        .sort(),
    ).toEqual(["bcrypt", "md5crypt", "openpgp-s2k", "pbkdf2"]);
  });
});

describe("describeSpec", () => {
  it("names the construction and the cost", () => {
    const text = describeSpec(
      specFor("argon2", { ...salted("00".repeat(16)), [OPTION_PASSWORD]: "pw" }),
    );
    expect(text).toContain("argon2id");
    expect(text).toContain("KiB");
  });

  it("does not describe cost settings in Verify mode, where they are unused", () => {
    const text = describeSpec(
      specFor("argon2", {
        [OPTION_MODE]: "verify",
        [OPTION_PASSWORD]: "pw",
        [OPTION_EXPECTED]: "$argon2id$v=19$m=32,t=1,p=1$AAAA$AAAA",
      }),
    );
    expect(text).toMatch(/recorded in it/);
    expect(text).not.toContain("KiB");
  });

  it("says what is missing", () => {
    expect(describeSpec(specFor("hkdf"))).toMatch(/key material/i);
  });

  it("reports the iteration count for PBKDF2", () => {
    const text = describeSpec(
      specFor("pbkdf2", { ...salted("00".repeat(16)), [OPTION_PASSWORD]: "pw" }),
    );
    expect(text).toContain("600,000");
  });
});

describe("createSpec", () => {
  it("defaults to the current recommendations rather than the algorithm minimums", () => {
    // Opening on PBKDF2 with 1000 iterations would teach the wrong thing by default.
    expect(createSpec({ variant: "pbkdf2" }).options[OPTION_ITERATIONS]).toBe(
      OWASP_PBKDF2_SHA256,
    );
    expect(createSpec({ variant: "bcrypt" }).options[OPTION_BCRYPT_COST]).toBe(
      OWASP_BCRYPT_COST,
    );
  });

  it("never pre-fills a password", () => {
    for (const meta of KDF_TOOLS) {
      expect(
        createSpec({ variant: meta.id }).options[OPTION_PASSWORD],
        meta.id,
      ).toBeUndefined();
    }
  });

  it("starts in Derive mode", () => {
    for (const meta of KDF_TOOLS) {
      expect(createSpec({ variant: meta.id }).options[OPTION_MODE], meta.id).toBe("derive");
    }
  });

  it("rejects an unknown variant", () => {
    expect(() => createSpec({ variant: "nonexistent_kdf_tool" })).toThrow(/Unknown KDF tool/);
    expect(() => requireKdfTool("nonexistent_kdf_tool")).toThrow(/nonexistent_kdf_tool/);
  });

  it("round-trips through the zod schema", () => {
    const tool = kdfToolDefinition("argon2");
    const spec = specFor("argon2", { ...salted("00".repeat(16)), [OPTION_PASSWORD]: "pw" });
    expect(tool.specSchema.parse(spec)).toEqual(spec);
  });
});

// ── EvpKDF ──────────────────────────────────────────────────────────────────

describe("EvpKDF matches OpenSSL", () => {
  /**
   * Checked against the OpenSSL that is installed, not against a remembered constant.
   *
   * `EVP_BytesToKey` has no specification document -- OpenSSL's C function *is* the definition --
   * so there is no published vector to quote. What there is instead is the reference
   * implementation on this machine: `openssl enc -k password -S <salt> -md <hash> -P` prints the
   * key and IV it derives, and these are those values. That makes them reproducible by anyone
   * with an `openssl` binary, which is the closest thing to a citation this construction has.
   *
   * Both entries use a password and salt with no ambiguity in them, and the 48-byte length that
   * covers AES-256-CBC's key and IV together -- which is the only reason anyone derives 48 bytes.
   */
  const OPENSSL_CASES = [
    {
      hash: "sha256",
      key: "00FE95DC06AC5418BB02DB45DF1CEC6C4027F9B17799260FA9D4EAC389C8069F",
      iv: "FF67086B5CAFB1DF5AB7FA8FD36C93C9",
      command: "openssl enc -aes-256-cbc -k password -S 0011223344556677 -md sha256 -P",
    },
    {
      hash: "md5",
      key: "E75F4D3D32B0165FEA20EFF507FCE9F4",
      iv: "BB572C0FA4B3CC5247515C8B69BFD055",
      command: "openssl enc -aes-128-cbc -k password -S 0011223344556677 -md md5 -P",
    },
  ] as const;

  for (const testCase of OPENSSL_CASES) {
    it(`${testCase.hash} reproduces ${testCase.command}`, () => {
      const keyBytes = testCase.key.length / 2;
      const derived = deriveEvpKdf(
        testCase.hash,
        new TextEncoder().encode("password"),
        Uint8Array.from("0011223344556677".match(/../g)!.map((b) => parseInt(b, 16))),
        1,
        keyBytes + 16,
      );
      const upper = (bytes: Uint8Array) => encodeHex(bytes).toUpperCase();
      expect(upper(derived.subarray(0, keyBytes))).toBe(testCase.key);
      expect(upper(derived.subarray(keyBytes))).toBe(testCase.iv);
    });
  }

  it("derives the same bytes through the tool as through the binding", async () => {
    // The option plumbing, not the arithmetic: the salt travels as a `bytes` option and the
    // password as a masked one, so this is what proves the tool wires them up correctly.
    const tool = kdfToolDefinition("evpkdf");
    const base = createSpec({ variant: "evpkdf" });
    const result = await tool.compute(
      {
        ...base,
        options: {
          ...base.options,
          [OPTION_PASSWORD]: "password",
          [OPTION_SALT]: "0011223344556677",
          saltEncoding: "hex",
          [OPTION_HASH]: "sha256",
          [OPTION_ITERATIONS]: 1,
          [OPTION_KEY_LENGTH]: 48,
        },
      },
      new Uint8Array(0),
    );
    expect(result.error).toBeUndefined();
    expect(encodeHex(result.bytes!).toUpperCase()).toBe(
      "00FE95DC06AC5418BB02DB45DF1CEC6C4027F9B17799260FA9D4EAC389C8069F" +
        "FF67086B5CAFB1DF5AB7FA8FD36C93C9",
    );
  });

  it("K009 fires whatever the iteration count, because no count fixes it", () => {
    // Distinct from K001, which a higher PBKDF2 count genuinely silences. There is no memory cost
    // here, so the attacker's parallel advantage is unbounded at any count -- hence no fix offered.
    for (const iterations of [1, 1000, 100_000]) {
      const spec = specFor("evpkdf", {
        [OPTION_PASSWORD]: "password",
        [OPTION_SALT]: "0011223344556677",
        saltEncoding: "hex",
        [OPTION_ITERATIONS]: iterations,
      });
      const diagnostic = lint(spec).diagnostics.find((d) => d.code === "K009");
      expect(diagnostic?.level, `at ${iterations} iterations`).toBe("insecure");
      expect(diagnostic?.fix).toBeUndefined();
    }
  });
});
