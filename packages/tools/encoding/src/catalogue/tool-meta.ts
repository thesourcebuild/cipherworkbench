/**
 * The five tools this family contributes, as eager metadata.
 *
 * Each is bidirectional: `direction` is an option, not two entries in the sidebar, because Base64
 * and un-Base64 are one thing with an arrow on it and nobody looks for them separately. That is the
 * same reasoning the cipher family uses for encrypt/decrypt.
 *
 * Free of any `@ocs/algos` or `@scure/base` import, so listing these costs nothing but the strings.
 */
import {
  OPTION_CASE,
  OPTION_JSON_INDENT,
  OPTION_KEY_ORDER,
  OPTION_PADDING,
  OPTION_SEPARATOR,
  OPTION_VARIANT,
  type Variant,
} from "../pure";

export type EncodingKind = "hex" | "base32" | "base58" | "base64" | "cbor";

export interface EncodingToolMeta {
  id: string;
  label: string;
  kind: EncodingKind;
  category: string;
  /** Catalogue option ids this tool exposes, beyond the direction every tool has. */
  exposes: readonly string[];
  /** Option values a fresh spec starts with. */
  defaults: Readonly<Record<string, string>>;
  /** Alphabets this tool offers, in menu order. Empty for a format with no variants. */
  variants: readonly Variant[];
  tags: readonly string[];
  summary: string;
  /**
   * How much bigger the encoded form is, as a ratio and in the terms the format is defined in.
   *
   * Worth stating because it is the one number that decides whether an encoding is the right choice
   * for a job -- a Base64 payload does not fit in the space its bytes did -- and because it is not
   * something anyone remembers.
   */
  expansion: string;
  /**
   * A published-style check value: what `checkInput` encodes to under this tool's defaults.
   *
   * Borrowed from the RevEng CRC catalogue's convention, and useful here for the same reason -- these
   * formats have near-identical siblings, so one agreed value is how you confirm two implementations
   * mean the same alphabet.
   */
  check: string;
  /**
   * What to feed it. Defaults to the five ASCII characters `Hello`.
   *
   * CBOR needs its own, because its encoder takes a JSON *document* rather than arbitrary bytes:
   * `Hello` is not JSON and `"Hello"` is. The distinction is real rather than an artefact -- CBOR
   * encodes a structure, and the other four encode a byte string.
   */
  checkInput?: string;
}

export const ENCODING_TOOLS: readonly EncodingToolMeta[] = [
  {
    id: "hex",
    label: "Hex (Base16)",
    kind: "hex",
    category: "Base-N",
    exposes: [OPTION_CASE, OPTION_SEPARATOR],
    defaults: { [OPTION_CASE]: "lower", [OPTION_SEPARATOR]: "none" },
    variants: [],
    tags: ["hex", "hexadecimal", "base16", "rfc 4648", "hexdump", "fingerprint"],
    summary:
      "Two characters per byte — RFC 4648's Base16, the default way to write bytes down.",
    expansion: "2 characters per byte (200%)",
    check: "48656c6c6f",
  },
  {
    id: "base32",
    label: "Base32",
    kind: "base32",
    category: "Base-N",
    exposes: [OPTION_VARIANT, OPTION_PADDING],
    defaults: { [OPTION_VARIANT]: "rfc4648", [OPTION_PADDING]: "padded" },
    variants: ["rfc4648", "rfc4648-hex", "crockford"],
    tags: ["base32", "rfc 4648", "crockford", "totp", "onion", "case insensitive"],
    summary:
      "Five bytes to eight characters, case-insensitively — TOTP secrets, onion addresses, Crockford.",
    expansion: "8 characters per 5 bytes (160%)",
    check: "JBSWY3DP",
  },
  {
    id: "base58",
    label: "Base58",
    kind: "base58",
    category: "Base-N",
    exposes: [OPTION_VARIANT],
    defaults: { [OPTION_VARIANT]: "bitcoin" },
    variants: ["bitcoin", "ripple", "flickr", "check"],
    tags: ["base58", "base58check", "bitcoin", "address", "wif", "ipfs", "ripple", "flickr"],
    summary:
      "Base64's alphabet minus the characters people confuse — 0, O, I and l — as Bitcoin uses.",
    expansion: "about 1.37 characters per byte (137%)",
    check: "9Ajdvzr",
  },
  {
    id: "base64",
    label: "Base64",
    kind: "base64",
    category: "Base-N",
    exposes: [OPTION_VARIANT, OPTION_PADDING],
    defaults: { [OPTION_VARIANT]: "standard", [OPTION_PADDING]: "padded" },
    variants: ["standard", "urlsafe"],
    tags: ["base64", "base64url", "rfc 4648", "jwt", "data uri", "mime", "pem", "url safe"],
    summary: "Three bytes to four characters — MIME, PEM, data URIs, and JWTs (URL-safe form).",
    expansion: "4 characters per 3 bytes (133%)",
    check: "SGVsbG8=",
  },
  {
    id: "cbor",
    label: "CBOR",
    kind: "cbor",
    category: "Binary structures",
    exposes: [OPTION_KEY_ORDER, OPTION_JSON_INDENT],
    defaults: { [OPTION_KEY_ORDER]: "as-written", [OPTION_JSON_INDENT]: "indented" },
    variants: [],
    tags: ["cbor", "rfc 8949", "concise binary", "cose", "webauthn", "ctap", "json", "msgpack"],
    summary:
      "RFC 8949's binary JSON — encode from JSON, or decode CBOR bytes back to readable JSON.",
    expansion: "usually smaller than the JSON it replaces",
    check: "6548656c6c6f",
    checkInput: '"Hello"',
  },
];

const BY_ID = new Map(ENCODING_TOOLS.map((t) => [t.id, t]));

export function getEncodingTool(id: string): EncodingToolMeta | undefined {
  return BY_ID.get(id);
}

export function requireEncodingTool(id: string): EncodingToolMeta {
  const meta = BY_ID.get(id);
  if (!meta) throw new Error(`Unknown encoding tool: ${id}`);
  return meta;
}

export const ENCODING_TOOL_IDS: readonly string[] = ENCODING_TOOLS.map((t) => t.id);

/** The alphabet a variant uses, for the Info table. Empty where the format has no alphabet. */
export const VARIANT_ALPHABET: Partial<Record<Variant, string>> = {
  rfc4648: "A-Z 2-7",
  "rfc4648-hex": "0-9 A-V",
  crockford: "0-9 A-Z without I, L, O, U",
  bitcoin: "1-9 A-Z a-z without 0, O, I, l",
  ripple: "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",
  flickr: "1-9 a-z A-Z without 0, O, I, l",
  check: "Bitcoin's, plus a 4-byte SHA-256d checksum",
  standard: "A-Z a-z 0-9 + /",
  urlsafe: "A-Z a-z 0-9 - _",
};

export const VARIANT_LABEL: Record<Variant, string> = {
  rfc4648: "RFC 4648",
  "rfc4648-hex": "RFC 4648 base32hex",
  crockford: "Crockford",
  bitcoin: "Bitcoin",
  ripple: "Ripple",
  flickr: "Flickr",
  check: "Base58check",
  standard: "Standard",
  urlsafe: "URL-safe",
};
