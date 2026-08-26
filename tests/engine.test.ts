import { describe, expect, it } from "vitest";
import {
  concatBytes,
  decodeBase32,
  decodeBase64,
  decodeBase64Url,
  decodeHex,
  decodeInput,
  decodeText,
  encodeBinary,
  encodeOctal,
  encodeDecimal,
  encodeHex,
  encodeOutput,
  encodeText,
  randomBytes,
  randomHex,
  rechunk,
  timingSafeEqual,
  validateCatalogue,
  verifyAgainst,
  verifyText,
  type OptionDef,
} from "@ocs/engine";
import { BASE_ENCODING_VECTORS } from "./vectors";

const ascii = (text: string) => new TextEncoder().encode(text);
const bytes = (...values: number[]) => new Uint8Array(values);

describe("hex decoding is lenient about separators", () => {
  // Every one of these is a shape people genuinely paste in: Wireshark, a hex
  // editor, source code, `xxd` output. None is ambiguous, so rejecting them
  // would cost usability for no correctness gain.
  const equivalent = [
    "deadbeef",
    "DEADBEEF",
    "de:ad:be:ef",
    "DE AD BE EF",
    "0xdeadbeef",
    "de ad\nbe ef",
    "de-ad-be-ef",
    "de_ad_be_ef",
    "  deadbeef  ",
  ];

  for (const input of equivalent) {
    it(`reads ${JSON.stringify(input)}`, () => {
      const result = decodeHex(input);
      expect(result.ok).toBe(true);
      expect(encodeHex(result.ok ? result.bytes : new Uint8Array())).toBe("deadbeef");
    });
  }

  it("reports an odd digit count rather than guessing", () => {
    const result = decodeHex("abc");
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.error).toMatch(/even number/);
  });

  it("names the offending character", () => {
    const result = decodeHex("dezz");
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.error).toContain("z");
  });

  it("treats empty as zero bytes, not an error", () => {
    const result = decodeHex("   ");
    expect(result.ok && result.bytes).toHaveLength(0);
  });
});

describe("RFC 4648 base encodings", () => {
  for (const vector of BASE_ENCODING_VECTORS) {
    it(`"${vector.input}" round-trips through Base64 and Base32`, () => {
      const input = ascii(vector.input);
      expect(encodeOutput(input, "base64")).toBe(vector.base64);
      expect(encodeOutput(input, "base32")).toBe(vector.base32);

      const fromB64 = decodeBase64(vector.base64);
      const fromB32 = decodeBase32(vector.base32);
      expect(fromB64.ok && encodeHex(fromB64.bytes)).toBe(encodeHex(input));
      expect(fromB32.ok && encodeHex(fromB32.bytes)).toBe(encodeHex(input));
    });
  }

  it("accepts unpadded Base64, as a JWT segment arrives", () => {
    // "foobar" padded is "Zm9vYmFy" (no padding needed); "foob" is "Zm9vYg==".
    const padded = decodeBase64("Zm9vYg==");
    const unpadded = decodeBase64("Zm9vYg");
    expect(padded.ok && unpadded.ok).toBe(true);
    expect(encodeHex(padded.ok ? padded.bytes : bytes())).toBe(
      encodeHex(unpadded.ok ? unpadded.bytes : bytes(1)),
    );
  });

  it("accepts the URL-safe alphabet in the plain Base64 box and vice versa", () => {
    // 0xfb 0xff encodes as "+/8=" in standard and "-_8=" URL-safe.
    const standard = decodeBase64("+/8=");
    const urlSafeInStandardBox = decodeBase64("-_8=");
    expect(standard.ok && encodeHex(standard.bytes)).toBe("fbff");
    expect(urlSafeInStandardBox.ok && encodeHex(urlSafeInStandardBox.bytes)).toBe("fbff");

    const urlSafe = decodeBase64Url("-_8=");
    expect(urlSafe.ok && encodeHex(urlSafe.bytes)).toBe("fbff");
  });

  it("reports unparseable Base64 rather than throwing", () => {
    const result = decodeBase64("!!!!");
    expect(result.ok).toBe(false);
  });
});

describe("text encodings", () => {
  it("encodes UTF-8 by code point", () => {
    const result = encodeText("é", "utf-8");
    expect(result.ok && encodeHex(result.bytes)).toBe("c3a9");
  });

  it("encodes UTF-16 in both byte orders", () => {
    const le = encodeText("ab", "utf-16le");
    const be = encodeText("ab", "utf-16be");
    expect(le.ok && encodeHex(le.bytes)).toBe("61006200");
    expect(be.ok && encodeHex(be.bytes)).toBe("00610062");
  });

  it("round-trips UTF-16 through decode", () => {
    for (const encoding of ["utf-16le", "utf-16be"] as const) {
      const encoded = encodeText("hello ☃", encoding);
      expect(encoded.ok && decodeText(encoded.bytes, encoding)).toBe("hello ☃");
    }
  });

  it("refuses a character Latin-1 cannot carry, naming it", () => {
    const result = encodeText("naïve ☃", "latin1");
    expect(result.ok).toBe(false);
    // Silently substituting would mean hashing something the user never typed.
    expect(result.ok === false && result.error).toMatch(/U\+2603/);
  });

  it("encodes the whole Latin-1 range", () => {
    const result = encodeText("ÿ", "latin1");
    expect(result.ok && encodeHex(result.bytes)).toBe("ff");
  });

  it("preserves a lone surrogate rather than replacing it", () => {
    // A lone surrogate is exactly the input that distinguishes one
    // implementation's digest from another's; U+FFFD substitution would lie.
    const result = encodeText("\ud800", "utf-16le");
    expect(result.ok && encodeHex(result.bytes)).toBe("00d8");
  });
});

describe("decodeInput dispatch", () => {
  it("routes each mode to the right decoder", () => {
    expect(readHex(decodeInput("abc", "text", "utf-8"))).toBe("616263");
    expect(readHex(decodeInput("616263", "hex", "utf-8"))).toBe("616263");
    expect(readHex(decodeInput("YWJj", "base64", "utf-8"))).toBe("616263");
    expect(readHex(decodeInput("YWJj", "base64url", "utf-8"))).toBe("616263");
  });

  it("honours the text encoding only in text mode", () => {
    expect(readHex(decodeInput("abc", "text", "utf-16le"))).toBe("610062006300");
    // Hex input is already bytes; the text encoding must not touch it.
    expect(readHex(decodeInput("616263", "hex", "utf-16le"))).toBe("616263");
  });
});

describe("output encodings", () => {
  const digest = bytes(0xde, 0xad, 0xbe, 0xef);

  it("spells hex in both cases", () => {
    expect(encodeOutput(digest, "hex")).toBe("deadbeef");
    expect(encodeOutput(digest, "hex-upper")).toBe("DEADBEEF");
  });

  it("renders decimal as a big-endian integer", () => {
    expect(encodeDecimal(digest)).toBe("3735928559");
  });

  it("does not lose precision above 2^53", () => {
    // CRC-64 exists, so `number` would silently round here.
    const wide = bytes(0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    expect(encodeDecimal(wide)).toBe("18446744073709551615");
  });

  it("groups binary a byte at a time", () => {
    expect(encodeBinary(bytes(0x0f, 0xf0))).toBe("00001111 11110000");
  });

  it("groups octal a byte at a time, three digits each", () => {
    /**
     * Per byte like binary, not one integer like decimal.
     *
     * The comparison people have to hand is `od -b`, which prints three octal digits per byte -- so
     * this matches that rather than rendering the whole result as a single octal number. Padding
     * matters for the same reason it does in binary: 0o7 and 0o007 are one number and only one of
     * them lines up in a column.
     */
    expect(encodeOctal(bytes(0x0f, 0xf0))).toBe("017 360");
    expect(encodeOctal(bytes(0x00, 0x01, 0x07, 0x08, 0xff))).toBe("000 001 007 010 377");
    // Every byte is exactly three digits, so the whole string is a fixed width per length.
    const all = encodeOctal(Uint8Array.from({ length: 256 }, (_, i) => i));
    expect(all.split(" ")).toHaveLength(256);
    expect(new Set(all.split(" ").map((g) => g.length))).toEqual(new Set([3]));
  });

  it("reaches octal through encodeOutput, under the id the dropdown uses", () => {
    // The enum value and the dispatch must agree, or the option renders and does nothing.
    expect(encodeOutput(bytes(0xcb, 0xf4, 0x39, 0x26), "octal")).toBe("313 364 071 046");
  });

  it("treats an empty result as an empty string, not a crash", () => {
    for (const encoding of ["hex", "base64", "base32", "binary", "octal", "latin1"] as const) {
      expect(typeof encodeOutput(bytes(), encoding)).toBe("string");
    }
    expect(encodeDecimal(bytes())).toBe("0");
  });
});

describe("verifyAgainst", () => {
  const digest = decodeHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  const sha256Abc = digest.ok ? digest.bytes : bytes();

  it("matches a hex digest", () => {
    const outcome = verifyAgainst(sha256Abc, encodeHex(sha256Abc));
    expect(outcome.status).toBe("match");
    expect(outcome.detectedAs).toBe("hex");
  });

  it("matches the same digest pasted as Base64", () => {
    const outcome = verifyAgainst(sha256Abc, encodeOutput(sha256Abc, "base64"));
    expect(outcome.status).toBe("match");
    expect(outcome.detectedAs).toBe("base64");
  });

  it("matches uppercase hex with separators, as copied from a hex editor", () => {
    const spaced = encodeHex(sha256Abc, true).replace(/(..)/g, "$1 ").trim();
    expect(verifyAgainst(sha256Abc, spaced).status).toBe("match");
  });

  it("prefers hex when a value is valid in more than one encoding", () => {
    // `deadbeef` is legal hex AND legal Base64. Reading it as Base64 would
    // decode to different bytes and report a spurious mismatch.
    const four = bytes(0xde, 0xad, 0xbe, 0xef);
    const outcome = verifyAgainst(four, "deadbeef");
    expect(outcome.status).toBe("match");
    expect(outcome.detectedAs).toBe("hex");
  });

  it("takes the first token, so a .sha256 file line pastes straight in", () => {
    const line = `${encodeHex(sha256Abc)}  archive.tar.gz`;
    expect(verifyAgainst(sha256Abc, line).status).toBe("match");
  });

  it("reports a mismatch with the bytes it actually read", () => {
    const wrong = encodeHex(sha256Abc).replace(/^ba/, "bb");
    const outcome = verifyAgainst(sha256Abc, wrong);
    expect(outcome.status).toBe("mismatch");
    expect(outcome.message).toContain("bb7816bf");
  });

  it("distinguishes a length mismatch from a value mismatch", () => {
    // Comparing a SHA-256 against a SHA-512 is a much more useful thing to be
    // told than "does not match".
    const outcome = verifyAgainst(sha256Abc, "00".repeat(64));
    expect(outcome.status).toBe("wrong-length");
    expect(outcome.expectedLength).toBe(64);
    expect(outcome.actualLength).toBe(32);
    expect(outcome.message).toMatch(/Different algorithm/);
  });

  it("says so when nothing parses", () => {
    expect(verifyAgainst(sha256Abc, "!!! not a digest !!!").status).toBe("unparseable");
  });

  it("treats a blank field as a prompt, not a failure", () => {
    const outcome = verifyAgainst(sha256Abc, "   ");
    expect(outcome.status).toBe("empty");
  });
});

describe("timingSafeEqual", () => {
  it("compares equal and unequal buffers correctly", () => {
    expect(timingSafeEqual(bytes(1, 2, 3), bytes(1, 2, 3))).toBe(true);
    expect(timingSafeEqual(bytes(1, 2, 3), bytes(1, 2, 4))).toBe(false);
    expect(timingSafeEqual(bytes(1, 2, 3), bytes(1, 2))).toBe(false);
    expect(timingSafeEqual(bytes(), bytes())).toBe(true);
  });

  it("does not short-circuit on the first differing byte", () => {
    // Both must be false; a naive loop returning early would still pass this,
    // but a bug that ORs into the wrong variable would not.
    expect(timingSafeEqual(bytes(9, 0, 0, 0), bytes(0, 0, 0, 0))).toBe(false);
    expect(timingSafeEqual(bytes(0, 0, 0, 9), bytes(0, 0, 0, 0))).toBe(false);
  });
});

describe("randomBytes", () => {
  it("returns the requested length", () => {
    for (const length of [0, 1, 16, 32]) {
      expect(randomBytes(length)).toHaveLength(length);
    }
  });

  it("fills past the 65536-byte getRandomValues limit", () => {
    const large = randomBytes(200_000);
    expect(large).toHaveLength(200_000);
    // A chunking bug would leave the tail as zeros.
    expect(large.subarray(150_000).some((b) => b !== 0)).toBe(true);
  });

  it("does not repeat itself", () => {
    expect(encodeHex(randomBytes(32))).not.toBe(encodeHex(randomBytes(32)));
  });

  it("randomHex returns two hex characters per byte", () => {
    expect(randomHex(12)).toMatch(/^[0-9a-f]{24}$/);
  });

  it("rejects a nonsense length instead of allocating", () => {
    expect(() => randomBytes(-1)).toThrow();
    expect(() => randomBytes(1.5)).toThrow();
  });
});

describe("rechunk", () => {
  async function collect(source: AsyncIterable<Uint8Array>): Promise<Uint8Array[]> {
    const out: Uint8Array[] = [];
    for await (const chunk of source) out.push(chunk);
    return out;
  }

  async function* from(...parts: Uint8Array[]) {
    for (const part of parts) yield part;
  }

  it("splits and merges to the requested size, preserving the byte stream", async () => {
    const chunks = await collect(rechunk(from(bytes(1, 2, 3), bytes(4, 5, 6, 7)), 3));
    expect(chunks.map((c) => Array.from(c))).toEqual([[1, 2, 3], [4, 5, 6], [7]]);
  });

  it("keeps the total byte count intact for awkward sizes", async () => {
    const input = new Uint8Array(1000);
    for (let i = 0; i < input.length; i++) input[i] = i & 0xff;
    for (const size of [1, 7, 999, 1000, 1001]) {
      const chunks = await collect(rechunk(from(input), size));
      expect(encodeHex(concatBytes(...chunks))).toBe(encodeHex(input));
    }
  });

  it("yields nothing for an empty source", async () => {
    expect(await collect(rechunk(from(), 4))).toEqual([]);
  });
});

describe("validateCatalogue", () => {
  const base: OptionDef = {
    id: "mode",
    label: "Mode",
    group: "core",
    kind: "enum",
    choices: [{ value: "gcm", label: "GCM" }],
    summary: "s",
    detail: "d",
    order: 10,
  };

  it("passes a well-formed catalogue", () => {
    expect(validateCatalogue([base])).toEqual([]);
  });

  it("catches a duplicate id", () => {
    expect(validateCatalogue([base, { ...base, order: 20 }])).toContainEqual(
      "duplicate option id: mode",
    );
  });

  it("catches a duplicate order inside one group but allows it across groups", () => {
    expect(validateCatalogue([base, { ...base, id: "other" }])).toContainEqual(
      "duplicate order 10 in group core: mode and other",
    );
    expect(validateCatalogue([base, { ...base, id: "other", group: "aead" }])).toEqual([]);
  });

  it("catches an enum with no choices, and choices on a non-enum", () => {
    const { choices: _choices, ...withoutChoices } = base;
    expect(validateCatalogue([{ ...withoutChoices, kind: "enum" }])).toContainEqual(
      "enum option mode has no choices",
    );
    expect(validateCatalogue([{ ...base, kind: "boolean" }])).toContainEqual(
      "non-enum option mode declares choices",
    );
  });

  it("catches a bytes option with no length spec", () => {
    const { choices: _choices, ...rest } = base;
    expect(validateCatalogue([{ ...rest, id: "key", kind: "bytes" }])).toContainEqual(
      "bytes option key has no bytesLength spec",
    );
  });

  it("catches an unmarked password option", () => {
    const { choices: _choices, ...rest } = base;
    expect(
      validateCatalogue([{ ...rest, id: "pass", kind: "password", arg: { placeholder: "" } }]),
    ).toContainEqual("password option pass is not marked secret");
  });

  it("catches a dangling implies/requires/conflictsWith reference", () => {
    expect(validateCatalogue([{ ...base, requires: ["ghost"] }])).toContainEqual(
      "mode references unknown option ghost",
    );
  });

  it("catches a collision with a synthesised encoding option", () => {
    const { choices: _choices, ...rest } = base;
    const problems = validateCatalogue([
      { ...rest, id: "key", kind: "bytes", bytesLength: { min: 1 } },
      { ...rest, id: "keyEncoding", kind: "boolean", order: 20 },
    ]);
    expect(problems.some((p) => p.includes("synthesised encoding option keyEncoding"))).toBe(
      true,
    );
  });
});

function readHex(
  result: { ok: true; bytes: Uint8Array } | { ok: false; error: string },
): string {
  if (!result.ok) throw new Error(result.error);
  return encodeHex(result.bytes);
}

/**
 * `verifyText`, the text half of the same question.
 *
 * The encoding family's forward direction returns a Base64 *string*, so `verifyAgainst` had nothing to
 * compare and the Verify panel sat inert on half that family. Comparing the string is the right answer
 * there and the wrong one for a document, which is what `supportsVerify` decides separately.
 */
describe("verifyText", () => {
  it("matches an exact string, ignoring surrounding whitespace", () => {
    expect(verifyText("Zm9vYmFy", "Zm9vYmFy").status).toBe("match");
    expect(verifyText("Zm9vYmFy", "  Zm9vYmFy\n").status).toBe("match");
    expect(verifyText("  Zm9vYmFy  ", "Zm9vYmFy").status).toBe("match");
  });

  /** The `.sha256`-style split applies here too: a value followed by a filename is still a value. */
  it("takes the first token when the rest cannot be part of the value", () => {
    expect(verifyText("Zm9vYmFy", "Zm9vYmFy  archive.tar.gz").status).toBe("match");
  });

  /**
   * No case folding, and that is the point rather than an omission.
   *
   * Base64 and Base32 are case-sensitive alphabets, so folding would report a match between two
   * different strings. Hex is the case where folding *would* be right, and the byte path already
   * handles it properly by decoding both sides.
   */
  it("does not fold case", () => {
    expect(verifyText("Zm9vYmFy", "zm9vymfy").status).toBe("mismatch");
  });

  it("says whether the length differs, because that is the first thing to check", () => {
    expect(verifyText("Zm9vYmFy", "Zm9vYmF").message).toMatch(/8 characters and this is 7/);
    expect(verifyText("Zm9vYmFy", "Zm9vYmFz").message).toMatch(/Same length/);
  });

  it("reports an empty expectation as empty rather than as a mismatch", () => {
    expect(verifyText("Zm9vYmFy", "").status).toBe("empty");
    expect(verifyText("Zm9vYmFy", "   ").status).toBe("empty");
  });
});
