/**
 * The eight check digit tools, as eager metadata.
 *
 * Check digits operate on human-entered alphanumeric strings (such as credit card numbers,
 * bank routing codes, ISBN barcodes, and securities identifiers) rather than arbitrary byte streams.
 * Their goal is to catch human keyboard mistakes — single-digit typos and adjacent swapped digits —
 * with minimal overhead.
 *
 * Free of any `@ocs/algos` import, so listing these costs nothing but the strings.
 */

export type CheckDigitKind =
  | "verhoeff"
  | "damm"
  | "luhn"
  | "isbn"
  | "iban"
  | "aba-routing"
  | "cusip-isin"
  | "sedol";

export interface CheckDigitToolMeta {
  id: string;
  label: string;
  kind: CheckDigitKind;
  /** Sidebar group. */
  category: string;
  /** Governing standard or underlying mathematical structure. */
  standard: string;
  /** Catalogue option ids this tool exposes. */
  exposes: readonly string[];
  /** Option values a fresh spec starts with. */
  defaults: Readonly<Record<string, string>>;
  tags: readonly string[];
  summary: string;
  /**
   * Published check value for the ASCII input `123456789`.
   */
  check: string;
  /**
   * Byte value produced for the ASCII input `123456789`.
   */
  checkByte: number;
}

export const CHECK_DIGIT_TOOLS: readonly CheckDigitToolMeta[] = [
  {
    id: "verhoeff",
    label: "Verhoeff",
    kind: "verhoeff",
    category: "Mathematical",
    standard: "Dihedral group D5 (ISO/IEC 7064)",
    exposes: [],
    defaults: {},
    tags: ["verhoeff", "check digit", "dihedral", "d5", "transposition", "integrity", "aadhaar"],
    summary: "Verhoeff dihedral group D5 check digit algorithm — detects 100% of single transposition errors.",
    check: "0",
    checkByte: 0,
  },
  {
    id: "damm",
    label: "Damm",
    kind: "damm",
    category: "Mathematical",
    standard: "Anti-symmetric quasigroup (order 10)",
    exposes: [],
    defaults: {},
    tags: ["damm", "check digit", "quasigroup", "anti-symmetric", "transposition", "integrity"],
    summary: "Damm quasigroup check digit algorithm — detects all single and adjacent transposition errors.",
    check: "4",
    checkByte: 4,
  },
  {
    id: "luhn",
    label: "Luhn / Mod 10",
    kind: "luhn",
    category: "Consumer & Barcode",
    standard: "ISO/IEC 7812-1 (Credit cards, IMEI)",
    exposes: [],
    defaults: {},
    tags: ["luhn", "mod10", "mod 10", "credit card", "imei", "check digit", "iso7812"],
    summary: "Luhn algorithm (Mod 10) with card issuer (Visa/Mastercard/Amex) and IMEI detection.",
    check: "7",
    checkByte: 7,
  },
  {
    id: "isbn",
    label: "ISBN / EAN-13",
    kind: "isbn",
    category: "Consumer & Barcode",
    standard: "ISO 2108 / GS1 EAN-13",
    exposes: [],
    defaults: {},
    tags: ["isbn", "isbn10", "isbn13", "ean", "ean13", "book", "barcode", "check digit"],
    summary: "ISBN-10, ISBN-13, and EAN-13 check digit validator and bidirectional converter.",
    check: "10",
    checkByte: 10,
  },
  {
    id: "iban",
    label: "IBAN Validator",
    kind: "iban",
    category: "Financial & Banking",
    standard: "ISO 13616 (MOD 97-10)",
    exposes: [],
    defaults: {},
    tags: ["iban", "iso13616", "mod97", "bank", "account", "check digit", "bban", "swift"],
    summary: "ISO 13616 International Bank Account Number MOD 97-10 generator and validator.",
    check: "34",
    checkByte: 34,
  },
  {
    id: "aba-routing",
    label: "ABA Routing Number",
    kind: "aba-routing",
    category: "Financial & Banking",
    standard: "Federal Reserve (Fedwire / ACH)",
    exposes: [],
    defaults: {},
    tags: ["aba", "routing", "fedwire", "bank", "transit", "check digit", "mod10"],
    summary: "Federal Reserve 9-digit ABA routing transit number weighted modulus 10 validator.",
    check: "0",
    checkByte: 0,
  },
  {
    id: "cusip-isin",
    label: "CUSIP & ISIN",
    kind: "cusip-isin",
    category: "Financial & Banking",
    standard: "ISO 6166 / ANSI X9.6",
    exposes: [],
    defaults: {},
    tags: ["cusip", "isin", "iso6166", "stocks", "bonds", "securities", "check digit"],
    summary: "CUSIP (9-digit) and ISIN (12-character) securities identification check digit calculator.",
    check: "2",
    checkByte: 2,
  },
  {
    id: "sedol",
    label: "SEDOL Check Digit",
    kind: "sedol",
    category: "Financial & Banking",
    standard: "London Stock Exchange SEDOL",
    exposes: [],
    defaults: {},
    tags: ["sedol", "lse", "london", "stock exchange", "securities", "check digit"],
    summary: "London Stock Exchange 7-character SEDOL security identifier check digit validator.",
    check: "3",
    checkByte: 3,
  },
];

const BY_ID = new Map(CHECK_DIGIT_TOOLS.map((t) => [t.id, t]));

export function getCheckDigitTool(id: string): CheckDigitToolMeta | undefined {
  return BY_ID.get(id);
}

export function requireCheckDigitTool(id: string): CheckDigitToolMeta {
  const meta = BY_ID.get(id);
  if (!meta) throw new Error(`Unknown check digit tool: ${id}`);
  return meta;
}

export const CHECK_DIGIT_TOOL_IDS: readonly string[] = CHECK_DIGIT_TOOLS.map((t) => t.id);
