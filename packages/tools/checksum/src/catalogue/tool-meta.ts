/**
 * The nine tools this family contributes, as eager metadata.
 *
 * One tool per named checksum rather than one tool with a variant dropdown — the opposite of
 * `@ocs/crc`'s arrangement, and for the reason that governs there too: the *name* is what someone
 * arrives searching for. Nobody looks for "CRC-32/BASE91-D", so the sixty-seven CRC models live
 * behind a dropdown; everybody looks for "LRC" or "Fletcher-16" by name, and there are nine of
 * them, so they are nine sidebar entries.
 *
 * Free of any `@ocs/algos` import, so listing these costs nothing but the strings.
 */
import {
  OPTION_BCC_MODE,
  OPTION_BYTE_ORDER,
  OPTION_RESULT,
  OPTION_WIDTH,
  OPTION_WORD_SIZE,
} from "../pure";

/** Which computation a tool performs. The compute path switches on exactly this. */
export type ChecksumKind =
  | "sum"
  | "ones"
  | "twos"
  | "xor"
  | "lrc"
  | "bcc"
  | "fletcher16"
  | "fletcher32"
  | "adler32"
  | "verhoeff"
  | "damm"
  | "luhn"
  | "isbn"
  | "iban"
  | "aba-routing"
  | "cusip-isin"
  | "sedol";

export interface ChecksumToolMeta {
  id: string;
  label: string;
  kind: ChecksumKind;
  /** Sidebar group. */
  category: string;
  /** Output width in bits. For the two tools with a `width` option this is the default. */
  width: 8 | 16 | 32;
  /** Catalogue option ids this tool exposes. Most expose none. */
  exposes: readonly string[];
  /** Option values a fresh spec starts with. */
  defaults: Readonly<Record<string, string>>;
  tags: readonly string[];
  summary: string;
  /**
   * Another tool in this family that computes the identical value under its default settings.
   *
   * Three of these overlap by construction, and saying so is worth more than pretending they are
   * distinct: the protocols named them separately, the arithmetic did not. Reported with the
   * result rather than buried, because someone comparing two devices needs to know a mismatch
   * cannot be explained by having picked the wrong one of a pair.
   */
  sameAs?: string;
  /**
   * This tool's value for the ASCII input `123456789`, in its default configuration.
   *
   * The same convention the RevEng CRC catalogue uses, and it earns its place for the same
   * reason: these algorithms have ambiguous names, so one agreed check value is how you confirm
   * two implementations mean the same thing. A test asserts each of these is what the tool
   * actually produces, so the number cannot drift away from the code.
   */
  check: string;
}

export const CHECKSUM_TOOLS: readonly ChecksumToolMeta[] = [
  {
    id: "sum",
    label: "Sum check",
    kind: "sum",
    category: "Sums",
    width: 8,
    exposes: [OPTION_WIDTH, OPTION_WORD_SIZE, OPTION_BYTE_ORDER],
    defaults: { [OPTION_WIDTH]: "8", [OPTION_WORD_SIZE]: "8", [OPTION_BYTE_ORDER]: "big" },
    tags: ["sum", "checksum", "additive", "byte sum", "modulo", "8-bit", "16-bit", "32-bit"],
    summary: "Add every byte or word and keep the low 8, 16 or 32 bits.",
    check: "0xDD",
  },
  {
    id: "ones-complement",
    label: "One's complement sum",
    kind: "ones",
    category: "Sums",
    width: 16,
    exposes: [OPTION_RESULT],
    defaults: { [OPTION_RESULT]: "complement" },
    tags: [
      "internet checksum",
      "rfc 1071",
      "ones complement",
      "ip",
      "tcp",
      "udp",
      "icmp",
      "header checksum",
    ],
    summary: "The Internet checksum of RFC 1071 — 16-bit words with an end-around carry.",
    check: "0xF62A",
  },
  {
    id: "twos-complement",
    label: "Two's complement checksum",
    kind: "twos",
    category: "Sums",
    width: 8,
    exposes: [OPTION_WIDTH, OPTION_WORD_SIZE, OPTION_BYTE_ORDER],
    defaults: { [OPTION_WIDTH]: "8", [OPTION_WORD_SIZE]: "8", [OPTION_BYTE_ORDER]: "big" },
    tags: [
      "twos complement",
      "negated sum",
      "checksum",
      "intel hex",
      "srec",
      "motorola s-record",
    ],
    summary: "The negated sum, so that the data plus its checksum comes to zero.",
    sameAs: "lrc",
    check: "0x23",
  },
  {
    id: "xor",
    label: "XOR checksum",
    kind: "xor",
    category: "Sums",
    width: 8,
    exposes: [],
    defaults: {},
    tags: ["xor", "checksum", "nmea", "nmea 0183", "gps", "parity", "longitudinal parity"],
    summary: "Every byte xored together — NMEA 0183's two hex digits after the asterisk.",
    sameAs: "bcc",
    check: "0x31",
  },
  {
    id: "lrc",
    label: "LRC",
    kind: "lrc",
    category: "Block checks",
    width: 8,
    exposes: [],
    defaults: {},
    tags: ["lrc", "longitudinal redundancy check", "modbus", "modbus ascii", "checksum"],
    summary:
      "Modbus ASCII's Longitudinal Redundancy Check — the two's complement of the byte sum.",
    sameAs: "twos-complement",
    check: "0x23",
  },
  {
    id: "bcc",
    label: "BCC",
    kind: "bcc",
    category: "Block checks",
    width: 8,
    exposes: [OPTION_BCC_MODE],
    defaults: { [OPTION_BCC_MODE]: "xor" },
    tags: ["bcc", "block check character", "iso 1155", "xor", "checksum", "industrial"],
    summary:
      "Block Check Character — ISO 1155's XOR, or the additive sum some vendors use instead.",
    sameAs: "xor",
    check: "0x31",
  },
  {
    id: "fletcher16",
    label: "Fletcher-16",
    kind: "fletcher16",
    category: "Fletcher and Adler",
    width: 16,
    exposes: [],
    defaults: {},
    tags: ["fletcher", "fletcher16", "fletcher-16", "checksum", "rfc 1146", "tcp alternate"],
    summary: "Two 8-bit sums mod 255 — close to a CRC's error detection at a sum's cost.",
    check: "0x1EDE",
  },
  {
    id: "fletcher32",
    label: "Fletcher-32",
    kind: "fletcher32",
    category: "Fletcher and Adler",
    width: 32,
    // The only tool here whose byte order is a real question. Fletcher-32 sums words, and nothing
    // in its definition says which end of a word the first octet lands on — the published vectors
    // answer it (little-endian), and a protocol that chose otherwise needs the switch.
    exposes: [OPTION_BYTE_ORDER],
    defaults: { [OPTION_BYTE_ORDER]: "little" },
    tags: ["fletcher", "fletcher32", "fletcher-32", "checksum", "zfs", "rfc 1146"],
    summary: "Two 16-bit sums mod 65535 over 16-bit words — ZFS's older block checksum.",
    check: "0xDF09D509",
  },
  {
    id: "adler32",
    label: "Adler-32",
    kind: "adler32",
    category: "Fletcher and Adler",
    width: 32,
    exposes: [],
    defaults: {},
    tags: [
      "adler",
      "adler32",
      "adler-32",
      "checksum",
      "zlib",
      "rfc1950",
      "rfc 1950",
      "deflate",
    ],
    summary: "zlib's checksum from RFC 1950 — Fletcher's idea with a prime modulus.",
    check: "0x091E01DE",
  },
  {
    id: "verhoeff",
    label: "Verhoeff",
    kind: "verhoeff",
    category: "Check Digits",
    width: 8,
    exposes: [],
    defaults: {},
    tags: ["verhoeff", "check digit", "dihedral", "d5", "transposition", "integrity", "aadhaar"],
    summary: "Verhoeff dihedral group D5 check digit algorithm — detects 100% of single transposition errors.",
    check: "0x00",
  },
  {
    id: "damm",
    label: "Damm",
    kind: "damm",
    category: "Check Digits",
    width: 8,
    exposes: [],
    defaults: {},
    tags: ["damm", "check digit", "quasigroup", "anti-symmetric", "transposition", "integrity"],
    summary: "Damm quasigroup check digit algorithm — detects all single and adjacent transposition errors.",
    check: "0x04",
  },
  {
    id: "luhn",
    label: "Luhn / Mod 10",
    kind: "luhn",
    category: "Check Digits",
    width: 8,
    exposes: [],
    defaults: {},
    tags: ["luhn", "mod10", "mod 10", "credit card", "imei", "check digit", "iso7812"],
    summary: "Luhn algorithm (Mod 10) with card issuer (Visa/Mastercard/Amex) and IMEI detection.",
    check: "0x07",
  },
  {
    id: "isbn",
    label: "ISBN / EAN-13",
    kind: "isbn",
    category: "Check Digits",
    width: 8,
    exposes: [],
    defaults: {},
    tags: ["isbn", "isbn10", "isbn13", "ean", "ean13", "book", "barcode", "check digit"],
    summary: "ISBN-10, ISBN-13, and EAN-13 check digit validator and bidirectional converter.",
    check: "0x0A",
  },
  {
    id: "iban",
    label: "IBAN Validator",
    kind: "iban",
    category: "Check Digits",
    width: 8,
    exposes: [],
    defaults: {},
    tags: ["iban", "iso13616", "mod97", "bank", "account", "check digit", "bban", "swift"],
    summary: "ISO 13616 International Bank Account Number MOD 97-10 generator and validator.",
    check: "0x22",
  },
  {
    id: "aba-routing",
    label: "ABA Routing Number",
    kind: "aba-routing",
    category: "Check Digits",
    width: 8,
    exposes: [],
    defaults: {},
    tags: ["aba", "routing", "fedwire", "bank", "transit", "check digit", "mod10"],
    summary: "Federal Reserve 9-digit ABA routing transit number weighted modulus 10 validator.",
    check: "0x00",
  },
  {
    id: "cusip-isin",
    label: "CUSIP & ISIN",
    kind: "cusip-isin",
    category: "Check Digits",
    width: 8,
    exposes: [],
    defaults: {},
    tags: ["cusip", "isin", "iso6166", "stocks", "bonds", "securities", "check digit"],
    summary: "CUSIP (9-digit) and ISIN (12-character) securities identification check digit calculator.",
    check: "0x02",
  },
  {
    id: "sedol",
    label: "SEDOL Check Digit",
    kind: "sedol",
    category: "Check Digits",
    width: 8,
    exposes: [],
    defaults: {},
    tags: ["sedol", "lse", "london", "stock exchange", "securities", "check digit"],
    summary: "London Stock Exchange 7-character SEDOL security identifier check digit validator.",
    check: "0x03",
  },
];

const BY_ID = new Map(CHECKSUM_TOOLS.map((t) => [t.id, t]));

export function getChecksumTool(id: string): ChecksumToolMeta | undefined {
  return BY_ID.get(id);
}

export function requireChecksumTool(id: string): ChecksumToolMeta {
  const meta = BY_ID.get(id);
  if (!meta) throw new Error(`Unknown checksum tool: ${id}`);
  return meta;
}

export const CHECKSUM_TOOL_IDS: readonly string[] = CHECKSUM_TOOLS.map((t) => t.id);
