import { z } from "zod";

/**
 * Every character encoding this app can turn text into bytes with.
 *
 * The list matches the one on emn178's online-tools — the reference this app is modelled on —
 * because that list is not arbitrary: it is the WHATWG Encoding Standard's set of legacy
 * encodings, which is the set browsers are required to support and therefore the set anyone
 * has data in. Two additions of our own are marked below.
 *
 * Strings only. This module is bundled eagerly so a selector can be rendered without paying
 * for 635 KB of conversion tables; `../legacy.ts` loads those on demand.
 */

/**
 * How much machinery an encoding needs, which is what decides when the tables load.
 *
 *  native — the platform does it, or a short loop does. No tables, always available.
 *  tables — needs the vendored WHATWG index tables. Triggers a dynamic import.
 */
export type EncodingTier = "native" | "tables";

export interface EncodingMeta {
  /** The WHATWG label, which is also the id stored in a spec and a share link. */
  id: string;
  label: string;
  /** Grouping for the selector's `<optgroup>`s. */
  group: EncodingGroup;
  tier: EncodingTier;
  /** One line, shown as the option's title. Omitted where the label says everything. */
  summary?: string;
}

export const ENCODING_GROUPS = ["unicode", "iso", "windows", "east-asian", "other"] as const;
export type EncodingGroup = (typeof ENCODING_GROUPS)[number];

export const ENCODING_GROUP_LABEL: Record<EncodingGroup, string> = {
  unicode: "Unicode",
  iso: "ISO 8859",
  windows: "Windows and DOS code pages",
  "east-asian": "East Asian",
  other: "Other",
};

/**
 * The three group helpers exist so 35 entries read as data rather than as 35 object literals.
 * Every legacy encoding is `tier: "tables"` without exception — that is the definition of the
 * tier, not a coincidence — so none of them repeats it.
 */
function iso(entries: readonly [string, string][]): EncodingMeta[] {
  return entries.map(([id, summary]) => ({
    id,
    label: id.toUpperCase().replace("ISO-8859", "ISO-8859"),
    group: "iso" as const,
    tier: "tables" as const,
    summary,
  }));
}

function windows(entries: readonly [string, string][]): EncodingMeta[] {
  return entries.map(([id, summary]) => ({
    id,
    label: WINDOWS_LABELS[id] ?? id,
    group: "windows" as const,
    tier: "tables" as const,
    summary,
  }));
}

/** Casing that matches how each of these is normally written, which `toUpperCase` would not. */
const WINDOWS_LABELS: Readonly<Record<string, string>> = {
  ibm866: "IBM866",
  "windows-874": "Windows-874",
  "windows-1250": "Windows-1250",
  "windows-1251": "Windows-1251",
  "windows-1252": "Windows-1252",
  "windows-1253": "Windows-1253",
  "windows-1254": "Windows-1254",
  "windows-1255": "Windows-1255",
  "windows-1256": "Windows-1256",
  "windows-1257": "Windows-1257",
  "windows-1258": "Windows-1258",
  macintosh: "macintosh",
  "x-mac-cyrillic": "x-mac-cyrillic",
  "koi8-r": "KOI8-R",
  "koi8-u": "KOI8-U",
};

function eastAsian(entries: readonly [string, string][]): EncodingMeta[] {
  return entries.map(([id, summary]) => ({
    id,
    label: EAST_ASIAN_LABELS[id] ?? id,
    group: "east-asian" as const,
    tier: "tables" as const,
    summary,
  }));
}

const EAST_ASIAN_LABELS: Readonly<Record<string, string>> = {
  gbk: "GBK",
  gb18030: "gb18030",
  big5: "Big5",
  "euc-jp": "EUC-JP",
  shift_jis: "Shift_JIS",
  "iso-2022-jp": "ISO-2022-JP",
  "euc-kr": "EUC-KR",
};

export const TEXT_ENCODINGS: readonly EncodingMeta[] = [
  // ── Unicode: no tables needed anywhere ──────────────────────────────────
  {
    id: "utf-8",
    label: "UTF-8",
    group: "unicode",
    tier: "native",
    summary: "The default. What everything modern uses.",
  },
  {
    id: "utf-16le",
    label: "UTF-16LE",
    group: "unicode",
    tier: "native",
    summary: "Two bytes per code unit, low byte first. Windows' 'Unicode'.",
  },
  {
    id: "utf-16be",
    label: "UTF-16BE",
    group: "unicode",
    tier: "native",
    summary: "Two bytes per code unit, high byte first.",
  },
  /**
   * True ISO-8859-1, which is ours rather than the reference's.
   *
   * Deliberately not folded into windows-1252. WHATWG maps the *label* "iso-8859-1" to
   * windows-1252 because that is what the web does in practice, and the reference site offers
   * only windows-1252 as a result — but the two differ across 0x80–0x9F, where ISO-8859-1 has
   * control characters and windows-1252 has curly quotes and the euro sign. Anyone hashing
   * genuinely 8859-1 data needs the difference.
   */
  {
    id: "latin1",
    label: "Latin-1 (true ISO-8859-1)",
    group: "unicode",
    tier: "native",
    summary: "0x80–0x9F as control characters, not as windows-1252's punctuation.",
  },

  // ── ISO 8859 ─────────────────────────────────────────────────────────────
  ...iso([
    ["iso-8859-2", "Central European (Latin-2)"],
    ["iso-8859-3", "South European (Latin-3)"],
    ["iso-8859-4", "North European (Latin-4)"],
    ["iso-8859-5", "Cyrillic"],
    ["iso-8859-6", "Arabic"],
    ["iso-8859-7", "Greek"],
    ["iso-8859-8", "Hebrew, visual order"],
    ["iso-8859-8-i", "Hebrew, logical order — the same bytes as ISO-8859-8"],
    ["iso-8859-10", "Nordic (Latin-6)"],
    ["iso-8859-13", "Baltic Rim (Latin-7)"],
    ["iso-8859-14", "Celtic (Latin-8)"],
    ["iso-8859-15", "Latin-9 — Latin-1 with the euro sign"],
    ["iso-8859-16", "South-Eastern European (Latin-10)"],
  ]),

  // ── Windows and DOS code pages ──────────────────────────────────────────
  ...windows([
    ["ibm866", "DOS Cyrillic (CP866)"],
    ["windows-874", "Thai"],
    ["windows-1250", "Central European"],
    ["windows-1251", "Cyrillic"],
    ["windows-1252", "Western European — what a mislabelled ISO-8859-1 really is"],
    ["windows-1253", "Greek"],
    ["windows-1254", "Turkish"],
    ["windows-1255", "Hebrew"],
    ["windows-1256", "Arabic"],
    ["windows-1257", "Baltic"],
    ["windows-1258", "Vietnamese"],
    ["macintosh", "Mac OS Roman"],
    ["x-mac-cyrillic", "Mac OS Cyrillic"],
    ["koi8-r", "Russian"],
    ["koi8-u", "Ukrainian"],
  ]),

  // ── East Asian ───────────────────────────────────────────────────────────
  ...eastAsian([
    ["gbk", "Simplified Chinese"],
    ["gb18030", "Simplified Chinese, superset of GBK — covers all of Unicode"],
    ["big5", "Traditional Chinese"],
    ["euc-jp", "Japanese, Unix"],
    ["shift_jis", "Japanese, Windows and classic Mac"],
    ["iso-2022-jp", "Japanese, stateful — switches charset with escape sequences"],
    ["euc-kr", "Korean"],
  ]),

  // ── Other ────────────────────────────────────────────────────────────────
  {
    id: "x-user-defined",
    label: "x-user-defined",
    group: "other",
    tier: "tables",
    summary: "Bytes 0x80–0xFF map to U+F780–U+F7FF. For reading binary through a text API.",
  },
];

const BY_ID = new Map(TEXT_ENCODINGS.map((e) => [e.id, e]));

export function getTextEncoding(id: string): EncodingMeta | undefined {
  return BY_ID.get(id);
}

export const TEXT_ENCODING_IDS: readonly string[] = TEXT_ENCODINGS.map((e) => e.id);

/** True when this encoding needs the vendored tables — i.e. when selecting it triggers a load. */
export function needsTables(id: string): boolean {
  return BY_ID.get(id)?.tier === "tables";
}

/** Ids grouped for a selector, in declaration order within each group. */
export function encodingsByGroup(): { group: EncodingGroup; encodings: EncodingMeta[] }[] {
  return ENCODING_GROUPS.map((group) => ({
    group,
    encodings: TEXT_ENCODINGS.filter((e) => e.group === group),
  })).filter((entry) => entry.encodings.length > 0);
}

/**
 * How a run of *text* becomes bytes.
 *
 * All forty of them, which is the WHATWG Encoding Standard's legacy set plus true ISO-8859-1.
 * That is the same list emn178's online-tools offers, and it is not an arbitrary one: it is
 * exactly the set browsers are required to *decode*, and therefore the set anyone has data in.
 *
 * The asymmetry that makes this more than a list: `TextDecoder` handles all of them and
 * `TextEncoder` handles none of them but UTF-8, deliberately and permanently — the standard
 * forbids it. So turning typed text into Shift_JIS bytes needs shipped conversion tables, which
 * is what `@ocs/encodings` is and why `EncodingMeta.tier` exists to say which encodings pay for
 * them. Four are `native`; the other thirty-six load 635 KB on first use and never before.
 */
export const TextEncoding = z.enum(TEXT_ENCODING_IDS as [string, ...string[]]);
export type TextEncoding = string;

/**
 * Where a tool's input bytes come from.
 *
 * `hex-lenient` discards every character that is not a hex digit, rather than rejecting the
 * input. It exists as a mode of its own rather than as the behaviour of `hex` because the two
 * answer different questions: strict `hex` catches a typo, and lenient hex lets someone paste a
 * `xxd` dump, a C array or a Wireshark pane and get on with it. The reference this app follows
 * offers both for the same reason. Note that `hex` is already tolerant of *separators* — spaces,
 * colons, commas, dashes and a `0x` prefix — so reaching for this one means the input contains
 * something more than that.
 */
export const ByteSourceMode = z.enum([
  "text",
  "hex",
  "hex-lenient",
  "base64",
  "base64url",
  "file",
]);
export type ByteSourceMode = z.infer<typeof ByteSourceMode>;

/**
 * How a `bytes` option's typed value becomes bytes — a key, IV, nonce, salt or AAD.
 *
 * Separate from `ByteSourceMode` because the axes genuinely differ: an option
 * value can never be a file, and it *can* be text in a specific character
 * encoding without a "text mode" wrapping it. Keeping them apart means the key
 * field's selector never offers "File" and the input panel's never offers
 * "Latin-1" as a peer of "Hex".
 *
 * This is also why the encoding is stored alongside the value instead of the
 * value being pre-decoded: `"00112233"` as hex and as UTF-8 are four bytes and
 * eight bytes respectively, and a tool that lost that distinction would compute
 * confidently wrong answers.
 */
export const BytesEncoding = z.enum(["hex", "base64", "base64url", "utf-8", "latin1"]);
export type BytesEncoding = z.infer<typeof BytesEncoding>;

export const BYTES_ENCODING_LABEL: Record<BytesEncoding, string> = {
  hex: "Hex",
  base64: "Base64",
  base64url: "Base64url",
  "utf-8": "Text (UTF-8)",
  latin1: "Text (Latin-1)",
};

/**
 * How result bytes are spelled for display.
 *
 * `decimal` is meaningful only for tools whose output is a small fixed-width
 * integer — a CRC or Adler-32 checksum, which people genuinely do quote as
 * `3421780262`. It is not offered for digests: rendering 32 bytes as one
 * enormous decimal integer is technically possible and practically useless, so
 * `ToolManifest.outputEncodings` narrows the list per tool rather than every
 * tool advertising all of these.
 */
export const OutputEncoding = z.enum([
  "hex",
  "hex-upper",
  "base64",
  "base64url",
  "base32",
  "decimal",
  // Per byte, like `binary` and unlike `decimal` -- see the note on `encodeOctal`.
  "octal",
  "binary",
  "latin1",
  // Added for the encoding family: decoding Base64 to look at the text inside it is the single most
  // common thing anyone does with one, and `latin1` mangles every byte above 0x7F on the way.
  "utf-8",
]);
export type OutputEncoding = z.infer<typeof OutputEncoding>;

/**
 * Label for an encoding id. Derived from `TEXT_ENCODINGS` rather than duplicated, so adding an
 * encoding cannot leave a selector rendering a raw label like `x-mac-cyrillic` by accident.
 */
export function textEncodingLabel(id: string): string {
  return getTextEncoding(id)?.label ?? id;
}

export const BYTE_SOURCE_MODE_LABEL: Record<ByteSourceMode, string> = {
  text: "Text",
  hex: "Hex",
  "hex-lenient": "Hex (loose)",
  base64: "Base64",
  base64url: "Base64url",
  file: "File",
};

export const OUTPUT_ENCODING_LABEL: Record<OutputEncoding, string> = {
  hex: "Hex (lower case)",
  "hex-upper": "Hex (upper case)",
  base64: "Base64",
  base64url: "Base64url",
  base32: "Base32",
  decimal: "Decimal",
  octal: "Octal",
  binary: "Binary",
  latin1: "Latin-1",
  "utf-8": "Text (UTF-8)",
};
