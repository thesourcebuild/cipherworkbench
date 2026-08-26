import { describe, expect, it, vi } from "vitest";
import {
  ENCODING_GROUPS,
  TEXT_ENCODINGS,
  TEXT_ENCODING_IDS,
  getTextEncoding,
  needsTables,
  textEncodingLabel,
} from "@ocs/contracts";
import { decodeLegacy, encodeLegacy, ensureLegacyTables } from "@ocs/encodings";
import {
  decodeHexLenient,
  decodeInput,
  encodeHex,
  encodeOutput,
  encodeText,
} from "@ocs/engine";

/**
 * The character-encoding half of parity with emn178's online-tools.
 *
 * That site's input selector offers 39 text encodings, and the list is not arbitrary: it is the
 * WHATWG Encoding Standard's legacy set, which is the set every browser must be able to decode
 * and therefore the set data actually exists in. It gets them from a rebuilt copy of
 * `text-encoding`; this repo vendors the same library for the same reason, documented in
 * `packages/encodings/src/vendor/encoding.js`.
 *
 * The important test here is the first one. Rather than trusting the vendored tables, it derives
 * what the answer *should* be from the platform's own `TextDecoder` — an independent
 * implementation of the same standard, shipped by the host — and requires the two to agree for
 * every byte of every single-byte encoding. That is 28 encodings and about 7,000 assertions,
 * and it is the same experiment that ruled out doing this without tables at all.
 */

const hex = (bytes: Uint8Array) => encodeHex(bytes);

/** The hex of a successful encode, or the failure message — so an assertion reads either way. */
function hexOf(result: ReturnType<typeof encodeLegacy>): string {
  return result.ok ? hex(result.bytes) : `FAILED: ${result.error}`;
}

const unhex = (text: string) =>
  Uint8Array.from(text.match(/../g)!.map((pair) => Number.parseInt(pair, 16)));

/** Encodings whose whole mapping is derivable from a one-byte decode. */
const SINGLE_BYTE = TEXT_ENCODINGS.filter(
  (e) => e.tier === "tables" && (e.group === "iso" || e.group === "windows"),
);

/** Encodings the platform decodes but whose *encoder* applies extra pointer restrictions. */
const MULTI_BYTE = TEXT_ENCODINGS.filter((e) => e.group === "east-asian");

/**
 * Whether the platform's own `TextDecoder` is a usable oracle for the WHATWG single-byte indexes.
 *
 * It is not, on every Node. Node 22 answers these three from ICU's *legacy* converter tables rather
 * than from the WHATWG index, and gets all three wrong:
 *
 *  - `ibm866` byte 0x1A decodes to U+001C. Every WHATWG single-byte index is ASCII-transparent below
 *    0x80, so the answer is U+001A.
 *  - `windows-1253` byte 0xAA decodes to U+00AA. That pointer is a hole in the index, so the answer is
 *    U+FFFD.
 *  - `windows-874` byte 0xDB decodes to U+F8C1 -- a *private-use* character, which is the signature of
 *    a legacy converter table. Another hole; the answer is U+FFFD.
 *
 * Node 24 gets all three right. So this is not a bug in the vendored tables and must not be "fixed"
 * there: the tables are the WHATWG index and the older platform is the party that disagrees. What the
 * suite does instead is check the oracle's preconditions before trusting it -- the same discipline
 * CLAUDE.md records for OpenSSL refusing an XTS key whose halves are equal, and for `setAAD(empty)`
 * not being the same as no AAD.
 *
 * Chosen as *known answers* rather than as a Node version comparison, so nothing here goes stale: a
 * platform that answers these correctly is conformant enough for the comparison below to mean
 * something, whatever it calls itself.
 */
function platformFollowsWhatwg(): boolean {
  const probes: readonly [string, number, number][] = [
    // ASCII transparency, which every single-byte index has.
    ["ibm866", 0x1a, 0x1a],
    // Two pointers the indexes leave unmapped, so the decode must be the replacement character.
    ["windows-1253", 0xaa, 0xfffd],
    ["windows-874", 0xdb, 0xfffd],
  ];
  for (const [label, byte, expected] of probes) {
    try {
      const decoded = new TextDecoder(label).decode(new Uint8Array([byte]));
      if (decoded.codePointAt(0) !== expected) return false;
    } catch {
      return false;
    }
  }
  return true;
}

const PLATFORM_IS_ORACLE = platformFollowsWhatwg();

/**
 * The skip cannot become permanent, which is the other half of guarding on a capability.
 *
 * A conformant platform is what the repo develops against and what CI runs, so on Node 24 or newer the
 * probe above *must* pass -- a regression there is a finding rather than a reason to quietly stop
 * comparing. Below that it is a known limitation of the platform and the comparison is skipped with
 * this reason attached.
 */
describe("the platform decoder as an oracle", () => {
  it("follows the WHATWG indexes on the Node this repo verifies against", (ctx) => {
    /*
     * The note goes on the *skip*, not into an assertion message.
     *
     * A vacuous `expect(x).toBe(x)` would pass and print nothing, leaving somebody on an older Node
     * looking at twenty-nine silent skips with no explanation -- which is the failure mode this whole
     * arrangement exists to avoid.
     */
    if (!PLATFORM_IS_ORACLE) {
      ctx.skip(
        `Node ${process.versions.node} answers the WHATWG single-byte probes out of ICU's legacy tables, so the comparisons below are skipped: the vendored tables are right and the platform is not.`,
      );
      return;
    }
  });
});

describe("single-byte encodings agree with the platform's own decoder", () => {
  for (const meta of SINGLE_BYTE) {
    it.skipIf(!PLATFORM_IS_ORACLE)(`${meta.label} round-trips every byte it defines`, async () => {
      await ensureLegacyTables();
      // ISO-8859-8-I is an alias of ISO-8859-8 — same bytes, different glyph order — and the
      // platform has no separate decoder for it.
      const decoderLabel = meta.id === "iso-8859-8-i" ? "iso-8859-8" : meta.id;
      const decoder = new TextDecoder(decoderLabel);

      let checked = 0;
      const seen = new Set<string>();
      for (let byte = 0; byte < 256; byte++) {
        const char = decoder.decode(new Uint8Array([byte]));
        // Skip unmapped bytes, and characters a *lower* byte already claimed — the reverse
        // mapping is only well defined for the first byte that produces a given character.
        if (char.length !== 1 || char === "\uFFFD" || seen.has(char)) continue;
        seen.add(char);

        const result = encodeLegacy(meta.id, char);
        expect(result.ok, `${meta.label} U+${char.codePointAt(0)!.toString(16)}`).toBe(true);
        if (result.ok) {
          expect(hex(result.bytes), `${meta.label} byte 0x${byte.toString(16)}`).toBe(
            byte.toString(16).padStart(2, "0"),
          );
        }
        checked++;
      }
      // A guard against the test silently checking nothing, which a broken decoder label would
      // otherwise cause.
      expect(checked, `${meta.label} defined suspiciously few characters`).toBeGreaterThan(180);
    });
  }
});

describe("East Asian encodings", () => {
  /**
   * Published byte sequences, not round trips.
   *
   * These are the values every reference for these encodings prints, and they are the check that
   * matters: the platform's decoder cannot supply the expected answer here, because the WHATWG
   * *encoders* apply pointer restrictions the decoders do not. Deriving Shift_JIS from its
   * decoder disagreed with the standard on 2,256 characters, which is why the tables are shipped.
   */
  const VECTORS: readonly [string, string, string][] = [
    ["shift_jis", "日本語", "93fa967b8cea"],
    ["euc-jp", "日本語", "c6fccbdcb8ec"],
    ["gbk", "中文", "d6d0cec4"],
    ["big5", "中文", "a4a4a4e5"],
    ["euc-kr", "한국어", "c7d1b1b9beee"],
    // gb18030 encodes the euro as a2e3, where GBK has no mapping for it at all.
    ["gb18030", "中文€", "d6d0cec4a2e3"],
    // ISO-2022-JP is stateful: ESC $ B enters JIS X 0208, ESC ( B returns to ASCII.
    ["iso-2022-jp", "日本語", "1b2442467c4b5c386c1b2842"],
  ];

  for (const [id, text, expected] of VECTORS) {
    it(`${textEncodingLabel(id)} encodes ${text} to the published bytes`, async () => {
      await ensureLegacyTables();
      const result = encodeLegacy(id, text);
      expect(result.ok, result.ok ? "" : result.error).toBe(true);
      if (result.ok) expect(hex(result.bytes)).toBe(expected);
    });
  }

  for (const meta of MULTI_BYTE) {
    it(`${meta.label} round-trips through the platform's decoder`, async () => {
      await ensureLegacyTables();
      // Text chosen to exercise ASCII, the encoding's own script, and the ASCII/non-ASCII
      // boundary that trips a stateful encoder.
      const samples = ["abc", "ABC 123", "abc漢字abc"];
      for (const text of samples) {
        const encoded = encodeLegacy(meta.id, text);
        if (!encoded.ok) continue; // Big5 and EUC-KR cannot carry Japanese kanji.
        expect(new TextDecoder(meta.id).decode(encoded.bytes), `${meta.label} "${text}"`).toBe(
          text,
        );
      }
    });
  }

  /**
   * The two Chinese encodings are a superset relationship, not an alias, and the difference is
   * exactly the sort of thing this app exists to get right.
   */
  it("gb18030 and GBK disagree about the euro sign", async () => {
    await ensureLegacyTables();
    // Same character, different bytes, both correct for their encoding. A tool that treated
    // gb18030 as "GBK with extras" would get one of these wrong.
    expect(hexOf(encodeLegacy("gbk", "€"))).toBe("80");
    expect(hexOf(encodeLegacy("gb18030", "€"))).toBe("a2e3");
  });

  it("gb18030 reaches all of Unicode through its four-byte form, and GBK cannot", async () => {
    await ensureLegacyTables();
    // GBK is a two-byte encoding and stops at the BMP subset its tables cover. gb18030 adds an
    // algorithmic four-byte range that maps every remaining code point, astral planes included —
    // which is why it is the one Chinese encoding that can carry arbitrary text.
    for (const [char, wide] of [
      ["Ā", "81308b38"],
      ["︐", "84318236"],
      ["𠀋", "95328337"],
      ["𝄞", "9432be34"],
    ] as const) {
      expect(encodeLegacy("gbk", char).ok, `GBK should refuse ${char}`).toBe(false);
      expect(hexOf(encodeLegacy("gb18030", char)), `gb18030 ${char}`).toBe(wide);
      // And the platform decodes them back, which is what makes them real rather than invented.
      expect(new TextDecoder("gb18030").decode(unhex(wide))).toBe(char);
    }
  });
});

describe("the ISO-8859-8-I alias", () => {
  /**
   * A real bug in the reference, fixed here.
   *
   * The vendored engine keys its index lookup on the resolved encoding *name*, and the tables
   * have no `iso-8859-8-i` entry — so encoding to it throws `Cannot read properties of undefined
   * (reading 'indexOf')`. emn178's online-tools offers the option and hits the same crash.
   * WHATWG treats the two as one encoding differing only in glyph order, never in bytes, so
   * normalising the label is correct rather than a workaround.
   */
  it("encodes identically to ISO-8859-8 instead of throwing", async () => {
    await ensureLegacyTables();
    const logical = encodeLegacy("iso-8859-8-i", "שלום");
    const visual = encodeLegacy("iso-8859-8", "שלום");
    expect(logical.ok, logical.ok ? "" : logical.error).toBe(true);
    expect(visual.ok).toBe(true);
    if (logical.ok && visual.ok) {
      expect(hex(logical.bytes)).toBe(hex(visual.bytes));
      expect(hex(logical.bytes)).toBe("f9ece5ed");
    }
  });
});

describe("unencodable characters", () => {
  it("names the character and points at the escape hatch", async () => {
    await ensureLegacyTables();
    const result = encodeLegacy("iso-8859-2", "€");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      // The engine's own message is "The code point 8364 could not be encoded." — a decimal
      // number and nothing to act on.
      expect(result.error).toContain("€");
      expect(result.error).toContain("U+20AC");
      expect(result.error).toContain("Hex");
      expect(result.loading).toBeUndefined();
    }
  });

  it("does not substitute or clamp", async () => {
    await ensureLegacyTables();
    // The WHATWG encoder for form submission emits &#8364; here. Doing that would make the
    // tool hash something other than what was typed.
    const result = encodeLegacy("iso-8859-2", "a€b");
    expect(result.ok).toBe(false);
  });
});

describe("the lazy load", () => {
  /**
   * The pending state, checked in module isolation.
   *
   * The tables are 635 KB and load once per session, so every other test in this file has
   * already triggered them — hence `vi.resetModules()` and a fresh import. What is being
   * asserted is that a synchronous caller gets a distinguishable "not yet" rather than a hard
   * error, because that distinction is what lets the input panel show a pending message instead
   * of telling the user their input is wrong.
   */
  it("reports loading rather than failure before the tables arrive", async () => {
    vi.resetModules();
    const fresh = await import("@ocs/encodings");
    expect(fresh.legacyTablesReady()).toBe(false);

    const early = fresh.encodeLegacy("shift_jis", "日本語");
    expect(early.ok).toBe(false);
    if (!early.ok) {
      expect(early.loading).toBe(true);
      expect(early.error).toContain("Loading");
    }

    await fresh.ensureLegacyTables();
    expect(fresh.legacyTablesReady()).toBe(true);
    const late = fresh.encodeLegacy("shift_jis", "日本語");
    expect(late.ok).toBe(true);
  });

  it("is idempotent and shares one load between concurrent callers", async () => {
    vi.resetModules();
    const fresh = await import("@ocs/encodings");
    await Promise.all([
      fresh.ensureLegacyTables(),
      fresh.ensureLegacyTables(),
      fresh.ensureLegacyTables(),
    ]);
    expect(fresh.legacyTablesReady()).toBe(true);
    expect(fresh.encodeLegacy("big5", "中文").ok).toBe(true);
  });

  it("needs no tables for the four native encodings", () => {
    for (const meta of TEXT_ENCODINGS.filter((e) => e.tier === "native")) {
      expect(needsTables(meta.id), meta.label).toBe(false);
      // And they work through the engine with nothing loaded, which is the point of the tier.
      const result = encodeText("abc", meta.id);
      expect(result.ok, meta.label).toBe(true);
    }
  });
});

describe("the engine's input path", () => {
  it("routes every catalogued encoding through decodeInput", async () => {
    await ensureLegacyTables();
    for (const meta of TEXT_ENCODINGS) {
      // ASCII is representable in all forty, so a failure here is a wiring fault rather than an
      // unencodable character.
      const result = decodeInput("abc", "text", meta.id);
      expect(result.ok, `${meta.label}: ${result.ok ? "" : result.error}`).toBe(true);
    }
  });

  it("keeps true Latin-1 distinct from windows-1252", async () => {
    await ensureLegacyTables();
    /**
     * The reason `latin1` is in the catalogue at all, and the reason it is not an alias.
     *
     * WHATWG maps the *label* "iso-8859-1" onto windows-1252, because that is what the web does
     * — so the reference site offers only windows-1252 and there is no way to reach real
     * ISO-8859-1 there. The two differ across 0x80–0x9F, where 8859-1 has C1 control characters
     * and windows-1252 has typographic punctuation.
     */
    const curly = "\u201C"; // LEFT DOUBLE QUOTATION MARK
    expect(hexOf(encodeText(curly, "windows-1252"))).toBe("93");
    // True Latin-1 cannot carry it at all, and says so rather than substituting.
    const asLatin1 = encodeText(curly, "latin1");
    expect(asLatin1.ok).toBe(false);

    // And the other way: 0x93 is a control character in 8859-1 and a quote in windows-1252.
    expect(hexOf(encodeText("\u0093", "latin1"))).toBe("93");
  });

  it("hex-lenient discards litter that strict hex rejects", () => {
    const dump = "00000000: dead beef  ....\n00000010: cafe babe  ....";
    expect(decodeInput(dump, "hex", "utf-8").ok).toBe(false);
    const loose = decodeInput(dump, "hex-lenient", "utf-8");
    expect(loose.ok, loose.ok ? "" : loose.error).toBe(true);
    // The offsets are hex digits too, and are deliberately not special-cased — the mode's
    // contract is "keep every hex digit", which is what makes it predictable.
    if (loose.ok) expect(hex(loose.bytes)).toBe("00000000deadbeef00000010cafebabe");
  });

  it("hex-lenient strips byte-literal prefixes, so a C array or a shell escape works", () => {
    // The reference's own lenient mode drops non-hex characters only, turning "{ 0xde, 0xad }"
    // into "0de0ad" — three wrong bytes, no error. `x` cannot occur in hex data, so removing
    // `0x` and `\x` first is unambiguous. This is the only place this app deliberately differs.
    expect(hexOf(decodeHexLenient("{ 0xde, 0xad, 0xbe, 0xef }"))).toBe("deadbeef");
    expect(hexOf(decodeHexLenient(String.raw`\xde\xad\xbe\xef`))).toBe("deadbeef");
    expect(hexOf(decodeHexLenient("[0xDE, 0xAD]"))).toBe("dead");
  });

  it("hex-lenient cannot rescue a hex letter used as syntax, and says so", () => {
    // Python's bytes prefix is the letter `b`, which is also a hex digit. Nothing can tell the
    // two apart, so this lands on the odd-count error rather than on a wrong answer — and the
    // message names the count, which is the clue.
    const result = decodeHexLenient(String.raw`b"\xde\xad"`);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain("odd");
  });

  it("hex-lenient still refuses an odd digit count", () => {
    // Not padded: whether the stray nibble belongs to the front or the back of a byte is
    // genuinely unknowable, and guessing would produce a confidently wrong digest.
    const odd = decodeHexLenient("de ad b");
    expect(odd.ok).toBe(false);
    if (!odd.ok) expect(odd.error).toContain("odd");
  });
});

describe("parity with the reference site's encoding list", () => {
  /**
   * The 39 text encodings emn178's online-tools offers, read off its `#input-type` selector.
   *
   * Transcribed rather than fetched, obviously — a test must not depend on the network — but this
   * is the gate that makes the parity claim checkable rather than a memory. If the reference adds
   * one, or this app drops one, the list stops matching and this fails.
   */
  const REFERENCE_ENCODINGS: readonly string[] = [
    "utf-8",
    "utf-16le",
    "utf-16be",
    "ibm866",
    "iso-8859-2",
    "iso-8859-3",
    "iso-8859-4",
    "iso-8859-5",
    "iso-8859-6",
    "iso-8859-7",
    "iso-8859-8",
    "iso-8859-8-i",
    "iso-8859-10",
    "iso-8859-13",
    "iso-8859-14",
    "iso-8859-15",
    "iso-8859-16",
    "koi8-r",
    "koi8-u",
    "macintosh",
    "windows-874",
    "windows-1250",
    "windows-1251",
    "windows-1252",
    "windows-1253",
    "windows-1254",
    "windows-1255",
    "windows-1256",
    "windows-1257",
    "windows-1258",
    "x-mac-cyrillic",
    "gbk",
    "gb18030",
    "big5",
    "euc-jp",
    "iso-2022-jp",
    "shift_jis",
    "euc-kr",
    "x-user-defined",
  ];

  it("offers every encoding the reference does", () => {
    const ours = new Set(TEXT_ENCODING_IDS);
    expect(
      REFERENCE_ENCODINGS.filter((id) => !ours.has(id)),
      "encodings the reference offers and this app does not",
    ).toEqual([]);
  });

  it("adds true Latin-1 and nothing else", () => {
    // Any other addition should be a deliberate decision with a note, not a drift.
    const theirs = new Set(REFERENCE_ENCODINGS);
    expect(TEXT_ENCODING_IDS.filter((id) => !theirs.has(id))).toEqual(["latin1"]);
  });

  it("can actually encode every one of them", async () => {
    await ensureLegacyTables();
    for (const id of REFERENCE_ENCODINGS) {
      const meta = getTextEncoding(id);
      expect(meta, `${id} is listed but has no metadata`).toBeDefined();
      // "A" is representable in all 39, so a failure is a wiring fault.
      const result = encodeLegacy(id, "A");
      const viaEngine = encodeText("A", id);
      expect(viaEngine.ok, `${id} through encodeText`).toBe(true);
      if (meta!.tier === "tables") {
        expect(result.ok, `${id}: ${result.ok ? "" : result.error}`).toBe(true);
      }
    }
  });
});

describe("catalogue integrity", () => {
  it("has no duplicate ids and a label for every entry", () => {
    expect(new Set(TEXT_ENCODING_IDS).size).toBe(TEXT_ENCODING_IDS.length);
    for (const meta of TEXT_ENCODINGS) {
      expect(meta.label.length, meta.id).toBeGreaterThan(0);
      expect(textEncodingLabel(meta.id)).toBe(meta.label);
      expect(ENCODING_GROUPS as readonly string[]).toContain(meta.group);
    }
  });

  it("marks exactly the four Unicode encodings native", () => {
    // The tier is what decides whether selecting an encoding downloads 635 KB, so it is worth
    // pinning rather than trusting.
    expect(TEXT_ENCODINGS.filter((e) => e.tier === "native").map((e) => e.id)).toEqual([
      "utf-8",
      "utf-16le",
      "utf-16be",
      "latin1",
    ]);
    expect(TEXT_ENCODINGS.filter((e) => e.tier === "tables")).toHaveLength(36);
  });

  it("decodes back through the platform for every table-backed encoding", async () => {
    await ensureLegacyTables();
    for (const meta of TEXT_ENCODINGS.filter((e) => e.tier === "tables")) {
      const decoded = decodeLegacy(meta.id, new Uint8Array([0x41]));
      expect(decoded.ok, meta.label).toBe(true);
      if (decoded.ok) expect(decoded.text).toBe("A");
    }
  });
});

describe("Base64 matches hi-base64, the reference's Base64 library", () => {
  /**
   * The other half of the reference's encoding stack.
   *
   * emn178's online-tools does Base64 with `hi-base64` — their own library, MIT, still maintained
   * — and hex with a hand-rolled lookup table. This app uses `@scure/base` instead, and keeps it:
   * it is audited, it is already the source of Base32 here, and swapping an audited primitive for
   * an unaudited one would be a downgrade whatever the pedigree.
   *
   * What matters is that the *bytes* agree, so `hi-base64` is a devDependency used as an oracle,
   * the same role `xxhash-wasm` and `node:crypto` play elsewhere in this suite. This is the test
   * that turns "we use a different library" into "we produce identical output".
   */
  it("encodes identically across every length that exercises the padding", async () => {
    const base64 = (await import("hi-base64")).default;
    for (let length = 0; length <= 64; length++) {
      const bytes = new Uint8Array(length);
      for (let i = 0; i < length; i++) bytes[i] = (i * 61 + 7) & 0xff;
      // Every length mod 3 is covered, which is where padding differs.
      expect(base64.encode(bytes), `${length} bytes`).toBe(encodeOutput(bytes, "base64"));
    }
  });

  it("decodes identically, including unpadded input", async () => {
    const base64 = (await import("hi-base64")).default;
    for (const text of ["", "3q2+7w==", "3q2+7w", "YWJj", "YWJjZA==", "YWJjZGU="]) {
      const theirs = Uint8Array.from(base64.decode.bytes(text) as ArrayLike<number>);
      const ours = decodeInput(text, "base64", "utf-8");
      expect(ours.ok, `${text}: ${ours.ok ? "" : ours.error}`).toBe(true);
      if (ours.ok) expect(hex(ours.bytes), `"${text}"`).toBe(hex(theirs));
    }
  });

  it("agrees on the URL-safe alphabet, padding included", async () => {
    const base64 = (await import("hi-base64")).default;
    // 0xfb 0xff 0xbf produces both a + and a / in the standard alphabet, so this is the input
    // where the two alphabets visibly diverge — and a trailing zero byte forces padding.
    const bytes = Uint8Array.from([0xfb, 0xff, 0xbf, 0x00]);
    expect(encodeOutput(bytes, "base64")).toBe(base64.rfc_4648.encode(bytes));
    expect(encodeOutput(bytes, "base64url")).toBe(base64.rfc_4648_url_safe.encode(bytes));
    // Both keep the `=`, which RFC 4648 §5 permits. JOSE and JWT omit it; that is a property of
    // those formats rather than of base64url, and the reference site pads here too.
    expect(encodeOutput(bytes, "base64url")).toBe("-_-_AA==");
  });
});
