import { describe, expect, it } from "vitest";
import {
  ENCODING_MANIFESTS,
  ENCODING_TOOLS,
  OPTION_CASE,
  OPTION_DIRECTION,
  OPTION_KEY_ORDER,
  OPTION_PADDING,
  OPTION_VARIANT,
  type EncodingSpec,
} from "@ocs/encoding";
import {
  ALL_ENCODING_OPTIONS,
  applyAllFixes,
  createSpec,
  describeSpec,
  encodingToolDefinition,
  lint,
  RULE_CODES,
} from "@ocs/encoding/definition";
import { encodeOutput, validateCatalogue } from "@ocs/engine";

const ascii = (text: string) => new TextEncoder().encode(text);

function specFor(variant: string, options: EncodingSpec["options"] = {}): EncodingSpec {
  const base = createSpec({ variant });
  return { ...base, options: { ...base.options, ...options } };
}

const encode = async (variant: string, options: EncodingSpec["options"], input: Uint8Array) => {
  const result = await encodingToolDefinition(variant).compute(
    specFor(variant, options),
    input,
  );
  expect(result.error, `${variant} reported: ${result.error}`).toBeUndefined();
  return result.text!;
};

const decode = async (variant: string, options: EncodingSpec["options"], text: string) => {
  const result = await encodingToolDefinition(variant).compute(
    specFor(variant, { [OPTION_DIRECTION]: "decode", ...options }),
    ascii(text),
  );
  expect(result.error, `${variant} reported: ${result.error}`).toBeUndefined();
  return result;
};

/**
 * RFC 4648 section 10's test vectors, which cover every group-boundary case each alphabet has.
 *
 * The empty string through six characters is not a stylistic choice: Base64 pads at one and two bytes
 * short of three, Base32 at four different offsets, and those boundaries are the only places an
 * implementation goes wrong. The RFC tabulates all of them, so the table is the test.
 */
const RFC4648: readonly {
  input: string;
  base64: string;
  base32: string;
  base32hex: string;
  base16: string;
}[] = [
  { input: "", base64: "", base32: "", base32hex: "", base16: "" },
  { input: "f", base64: "Zg==", base32: "MY======", base32hex: "CO======", base16: "66" },
  { input: "fo", base64: "Zm8=", base32: "MZXQ====", base32hex: "CPNG====", base16: "666F" },
  { input: "foo", base64: "Zm9v", base32: "MZXW6===", base32hex: "CPNMU===", base16: "666F6F" },
  {
    input: "foob",
    base64: "Zm9vYg==",
    base32: "MZXW6YQ=",
    base32hex: "CPNMUOG=",
    base16: "666F6F62",
  },
  {
    input: "fooba",
    base64: "Zm9vYmE=",
    base32: "MZXW6YTB",
    base32hex: "CPNMUOJ1",
    base16: "666F6F6261",
  },
  {
    input: "foobar",
    base64: "Zm9vYmFy",
    base32: "MZXW6YTBOI======",
    base32hex: "CPNMUOJ1E8======",
    base16: "666F6F626172",
  },
];

describe("RFC 4648 section 10", () => {
  for (const vector of RFC4648) {
    it(`"${vector.input}" in every alphabet`, async () => {
      expect(await encode("base64", {}, ascii(vector.input))).toBe(vector.base64);
      expect(await encode("base32", {}, ascii(vector.input))).toBe(vector.base32);
      expect(
        await encode("base32", { [OPTION_VARIANT]: "rfc4648-hex" }, ascii(vector.input)),
      ).toBe(vector.base32hex);
      expect(await encode("hex", { [OPTION_CASE]: "upper" }, ascii(vector.input))).toBe(
        vector.base16,
      );
    });

    it(`"${vector.input}" decodes back from every alphabet`, async () => {
      for (const [tool, text, options] of [
        ["base64", vector.base64, {}],
        ["base32", vector.base32, {}],
        ["base32", vector.base32hex, { [OPTION_VARIANT]: "rfc4648-hex" }],
        ["hex", vector.base16, {}],
      ] as const) {
        const result = await decode(tool, options, text);
        const bytes = result.bytes ?? new Uint8Array(0);
        expect(new TextDecoder().decode(bytes), `${tool} ${text}`).toBe(vector.input);
      }
    });
  }
});

describe("published vectors for the alphabets RFC 4648 does not cover", () => {
  it("Base58 matches its published vectors", async () => {
    // The one everybody quotes, plain: "Hello World!" in Bitcoin's alphabet.
    expect(await encode("base58", { [OPTION_VARIANT]: "bitcoin" }, ascii("Hello World!"))).toBe(
      "2NEpo7TZRRrLZSi2U",
    );
  });

  it("Base58check reproduces the Bitcoin wiki's WIF example", async () => {
    // The canonical worked example for Base58Check: version byte 0x80 followed by a private key,
    // which encodes to this WIF string. It exercises the alphabet, the 4-byte SHA-256d checksum and
    // the leading-byte handling in one value that was not derived from this code.
    const payload = Uint8Array.from(
      "800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D"
        .match(/../g)!
        .map((b) => parseInt(b, 16)),
    );
    expect(await encode("base58", { [OPTION_VARIANT]: "check" }, payload)).toBe(
      "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
    );
  });

  it("Base58check rejects the same WIF with one character changed", async () => {
    // The whole point of the checksum, so it gets an assertion rather than a comment: the vector
    // above with its last character J turned into K. Plain Base58 would decode this happily into
    // different bytes, which is exactly the failure the checksum exists to catch.
    const result = await encodingToolDefinition("base58").compute(
      specFor("base58", { [OPTION_DIRECTION]: "decode", [OPTION_VARIANT]: "check" }),
      ascii("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTK"),
    );
    expect(result.error).toBeTruthy();
  });

  it("Crockford Base32 omits the letters people mistype", async () => {
    // Its alphabet has no I, L, O or U, so the encoding of these bytes cannot contain them.
    const encoded = await encode("base32", { [OPTION_VARIANT]: "crockford" }, ascii("Hello"));
    expect(encoded).toMatch(/^[0-9A-HJKMNP-TV-Z]+$/);
    const back = await decode("base32", { [OPTION_VARIANT]: "crockford" }, encoded);
    expect(new TextDecoder().decode(back.bytes!)).toBe("Hello");
  });

  it("base64url swaps the two characters that break URLs", async () => {
    // 0xFB 0xFF 0xFE encodes to +/// in the standard alphabet, which is the whole problem.
    const bytes = Uint8Array.from([0xfb, 0xff, 0xbe]);
    expect(await encode("base64", { [OPTION_VARIANT]: "standard" }, bytes)).toBe("+/++");
    expect(await encode("base64", { [OPTION_VARIANT]: "urlsafe" }, bytes)).toBe("-_--");
  });

  it("CBOR round-trips JSON through RFC 8949", async () => {
    // a26161016162820203 is Appendix A's {"a": 1, "b": [2, 3]}.
    expect(await encode("cbor", {}, ascii('{"a":1,"b":[2,3]}'))).toBe("a26161016162820203");
    const back = await decode("cbor", {}, "a26161016162820203");
    expect(JSON.parse(back.text!)).toEqual({ a: 1, b: [2, 3] });
  });
});

describe("the check value each tool advertises", () => {
  for (const tool of ENCODING_TOOLS) {
    it(`${tool.label}: ${tool.checkInput ?? "Hello"} → ${tool.check}`, async () => {
      // The Info panel offers this as something to compare against, so it has to be what the tool
      // actually produces from its own defaults.
      expect(await encode(tool.id, {}, ascii(tool.checkInput ?? "Hello"))).toBe(tool.check);
    });
  }
});

describe("round trips", () => {
  const payloads = [
    new Uint8Array(0),
    ascii("a"),
    ascii("hello world"),
    Uint8Array.from({ length: 256 }, (_, i) => i),
    Uint8Array.from({ length: 61 }, (_, i) => (i * 37) & 0xff),
  ];

  for (const tool of ENCODING_TOOLS.filter((t) => t.kind !== "cbor")) {
    for (const variant of tool.variants.length > 0 ? tool.variants : [undefined]) {
      for (const padding of ["padded", "unpadded"] as const) {
        it(`${tool.label}${variant ? ` (${variant})` : ""} ${padding}: decode(encode(x)) === x`, async () => {
          const options = {
            ...(variant ? { [OPTION_VARIANT]: variant } : {}),
            [OPTION_PADDING]: padding,
          };
          for (const payload of payloads) {
            const text = await encode(tool.id, options, payload);
            const back = await decode(tool.id, options, text);
            expect([...(back.bytes ?? new Uint8Array(0))], `${tool.id} ${text}`).toEqual([
              ...payload,
            ]);
          }
        });
      }
    }
  }
});

describe("decoding is forgiving in the ways pasted values need", () => {
  it("ignores the whitespace a wrapped PEM body or a hex dump comes with", async () => {
    const pem = "SGVsbG8s\nIHdvcmxk\nIQ==";
    expect(new TextDecoder().decode((await decode("base64", {}, pem)).bytes!)).toBe(
      "Hello, world!",
    );
    const dump = "48 65 6c 6c 6f\n2c 20 77 6f 72 6c 64";
    expect(new TextDecoder().decode((await decode("hex", {}, dump)).bytes!)).toBe(
      "Hello, world",
    );
  });

  it("accepts a hex fingerprint with its colons and a 0x literal", async () => {
    for (const text of ["de:ad:be:ef", "0xdeadbeef", "DE-AD-BE-EF", "de ad be ef"]) {
      const bytes = (await decode("hex", {}, text)).bytes!;
      expect(encodeOutput(bytes, "hex"), text).toBe("deadbeef");
    }
  });

  it("accepts Base64 with or without padding whichever way the option is set", async () => {
    // A JWT segment has none and a PEM body has some, and a user pasting one has not chosen a
    // setting. Both must work under both.
    for (const padding of ["padded", "unpadded"] as const) {
      for (const text of ["Zg==", "Zg"]) {
        const bytes = (await decode("base64", { [OPTION_PADDING]: padding }, text)).bytes!;
        expect(new TextDecoder().decode(bytes), `${padding} ${text}`).toBe("f");
      }
    }
  });

  it("says which digit is missing rather than guessing at an odd hex length", async () => {
    // `abc` could be 0abc or abc0 and they are different bytes, so this is the one thing the hex
    // reader will not do for you.
    const result = await encodingToolDefinition("hex").compute(
      specFor("hex", { [OPTION_DIRECTION]: "decode" }),
      ascii("abc"),
    );
    expect(result.error).toMatch(/even number of digits/i);
  });

  it("reports a bad character as a message rather than throwing", async () => {
    // Half-typed Base64 is the normal state of that field; `compute` throwing would unmount the
    // workbench over a missing character.
    const result = await encodingToolDefinition("base64").compute(
      specFor("base64", { [OPTION_DIRECTION]: "decode" }),
      ascii("not valid base64 !!"),
    );
    expect(result.error).toBeTruthy();
  });
});

describe("CBOR's JSON bridge states what it changed", () => {
  it("notes that byte strings are shown as base64url", async () => {
    // RFC 8949 section 6.1's own recommendation, and a note is what tells you the quotes were not in
    // the data.
    const result = await decode("cbor", {}, "43010203");
    expect(result.fields?.some((f) => /base64url/i.test(f.value))).toBe(true);
  });

  it("notes that integer map keys became strings", async () => {
    // COSE and CTAP use integer keys throughout, so anyone decoding one meets this immediately.
    const result = await decode("cbor", {}, "a1016161");
    expect(JSON.parse(result.text!)).toEqual({ "1": "a" });
    expect(result.fields?.some((f) => /integer map keys/i.test(f.value))).toBe(true);
  });

  it("notes a dropped tag rather than pretending the value was bare", async () => {
    const result = await decode("cbor", {}, "c074323031332d30332d32315432303a30343a30305a");
    expect(JSON.parse(result.text!)).toBe("2013-03-21T20:04:00Z");
    expect(result.fields?.some((f) => /tag 0 was dropped/i.test(f.value))).toBe(true);
  });

  it("decodes a bignum tag to its decimal value", async () => {
    // Tag 2 is a byte string standing in for an integer too large for a head, so reading it as a
    // number is the decoding rather than a workaround.
    const result = await decode("cbor", {}, "c249010000000000000000");
    expect(JSON.parse(result.text!)).toBe("18446744073709551616");
  });

  it("reports trailing bytes instead of refusing them", async () => {
    const result = await decode("cbor", {}, "0001");
    expect(JSON.parse(result.text!)).toBe(0);
    expect(result.fields?.some((f) => /not decoded/i.test(f.value))).toBe(true);
  });

  it("sorts keys only when asked, and the bytes differ", async () => {
    const json = '{"b":1,"a":2}';
    expect(await encode("cbor", { [OPTION_KEY_ORDER]: "as-written" }, ascii(json))).toBe(
      "a2616201616102",
    );
    expect(await encode("cbor", { [OPTION_KEY_ORDER]: "sorted" }, ascii(json))).toBe(
      "a2616102616201",
    );
  });

  it("refuses a map whose keys collide once stringified", async () => {
    // {1: "a", "1": "b"} -- two distinct CBOR keys, one JSON key. Losing one silently is the failure
    // this prevents.
    const result = await encodingToolDefinition("cbor").compute(
      specFor("cbor", { [OPTION_DIRECTION]: "decode" }),
      // map(2) { 1: "a", "1": "b" }: two distinct CBOR keys, one JSON key.
      ascii("a201616161316162"),
    );
    expect(result.error).toMatch(/both become/i);
  });
});

describe("catalogues and manifests", () => {
  it("every tool's option catalogue is internally consistent", () => {
    for (const tool of ENCODING_TOOLS) {
      expect(
        validateCatalogue(encodingToolDefinition(tool.id).catalogue.options),
        tool.id,
      ).toEqual([]);
    }
    expect(validateCatalogue([...ALL_ENCODING_OPTIONS])).toEqual([]);
  });

  it("a tool's defaults name only options it exposes", () => {
    for (const tool of ENCODING_TOOLS) {
      expect(Object.keys(tool.defaults).sort(), tool.id).toEqual([...tool.exposes].sort());
    }
  });

  it("every default is one of the option's own choices", () => {
    for (const tool of ENCODING_TOOLS) {
      const catalogue = encodingToolDefinition(tool.id).catalogue;
      for (const [id, value] of Object.entries(tool.defaults)) {
        expect(
          catalogue.require(id).choices!.map((c) => c.value),
          `${tool.id}.${id}`,
        ).toContain(value);
      }
    }
  });

  it("offers a variant menu exactly where the tool has variants", () => {
    for (const tool of ENCODING_TOOLS) {
      const catalogue = encodingToolDefinition(tool.id).catalogue;
      const hasMenu = catalogue.get(OPTION_VARIANT) !== undefined;
      expect(hasMenu, tool.id).toBe(tool.variants.length > 0);
      if (hasMenu) {
        expect(catalogue.require(OPTION_VARIANT).choices!.map((c) => c.value)).toEqual([
          ...tool.variants,
        ]);
      }
    }
  });

  it("a manifest exists for every tool and describes it consistently", () => {
    expect(ENCODING_MANIFESTS.map((m) => m.id)).toEqual(ENCODING_TOOLS.map((t) => t.id));
    for (const manifest of ENCODING_MANIFESTS) {
      expect(manifest.family).toBe("encoding");
      // The one thing every tool here has to say about itself.
      expect(manifest.security).toBe("not-encryption");
      // Both ways, which is what makes `direction` an option rather than two tools.
      expect(manifest.directions).toEqual(["forward", "inverse"]);
      // Decoding to readable text is what people come for, so it is the default.
      expect(manifest.outputEncodings[0]).toBe("utf-8");
      expect(manifest.streaming).toBe(false);
    }
  });

  it("describes both directions of every tool in one sentence", () => {
    for (const tool of ENCODING_TOOLS) {
      for (const direction of ["encode", "decode"] as const) {
        const sentence = describeSpec(specFor(tool.id, { [OPTION_DIRECTION]: direction }));
        expect(sentence, `${tool.id}/${direction}`).toMatch(/\.$/);
      }
    }
  });

  it("states the alphabet and the size ratio before anything is typed", () => {
    // `info`, not a result: both follow from the settings, and they are the two facts that decide
    // whether a format fits a job.
    const info = encodingToolDefinition("base64").info!(specFor("base64"));
    const labels = info.map((f) => f.label);
    expect(labels).toContain("Alphabet");
    expect(labels).toContain("Size");
    expect(info.find((f) => f.label === "Size")!.value).toMatch(/133%/);
  });
});

describe("lint rules", () => {
  it("each rule fires somewhere, and each fix silences the rule that offered it", () => {
    const fired = new Set<string>();
    const specs: EncodingSpec[] = [
      ...ENCODING_TOOLS.map((t) => specFor(t.id)),
      specFor("base64", { [OPTION_PADDING]: "unpadded" }),
      specFor("base58", { [OPTION_VARIANT]: "bitcoin" }),
      specFor("cbor", { [OPTION_KEY_ORDER]: "as-written" }),
    ];

    for (const spec of specs) {
      for (const diagnostic of lint(spec).diagnostics) {
        fired.add(diagnostic.code);
        if (!diagnostic.fix) continue;
        expect(
          lint(diagnostic.fix.apply(spec)).diagnostics.map((d) => d.code),
          `${spec.variant}/${diagnostic.code}`,
        ).not.toContain(diagnostic.code);
      }
    }

    expect([...fired].sort()).toEqual([...RULE_CODES].sort());
  });

  it("tells every tool that an encoding is not encryption", () => {
    // The reason this family carries diagnostics at all.
    for (const tool of ENCODING_TOOLS) {
      expect(
        lint(specFor(tool.id)).diagnostics.map((d) => d.code),
        tool.id,
      ).toContain("E001");
    }
  });

  it("never blocks a computation", async () => {
    // Every rule here is `info`: an encoding always works, and there is nothing to refuse.
    for (const tool of ENCODING_TOOLS) {
      const spec = specFor(tool.id);
      expect(lint(spec).hasErrors, tool.id).toBe(false);
      const fixed = applyAllFixes(spec);
      const input = tool.kind === "cbor" ? ascii('{"a":1}') : ascii("Hello");
      const result = await encodingToolDefinition(tool.id).compute(fixed, input);
      expect(result.error, tool.id).toBeUndefined();
    }
  });
});
