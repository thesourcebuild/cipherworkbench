import {
  CborError,
  decodeCbor,
  encodeCbor,
  isCborMap,
  isCborTagged,
  type CborValue,
  base85Encode,
  base85Decode,
  base91Encode,
  base91Decode,
  base45Encode,
  base45Decode,
  proquintsEncode,
  proquintsDecode,
  punycodeEncode,
  punycodeDecode,
  bencodeEncode,
  bencodeDecode,
  type Base85Variant,
  encodeBubbleBabble,
  decodeBubbleBabble,
  encodeBaudotIta2,
  decodeBaudotIta2,
  encodePgpWords,
  decodePgpWords,
  encodeGrayBytes,
  decodeGrayBytes,
} from "@ocs/algos";
import {
  base32,
  base32crockford,
  base32hex,
  base32hexnopad,
  base32nopad,
  base58,
  base58check as base58checkWith,
  base58flickr,
  base58xrp,
  base64,
  base64nopad,
  base64url,
  base64urlnopad,
} from "@scure/base";
import { sha256 } from "@noble/hashes/sha2.js";
import type { EncodingKind } from "./catalogue/tool-meta";
import {
  SEPARATOR_TEXT,
  type JsonIndent,
  type KeyOrder,
  type Padding,
  type Separator,
  type Variant,
} from "./pure";

/**
 * The alphabets, from `@scure/base` in every case it has one.
 *
 * Not reimplemented, and worth saying why given this repo writes its own algorithms elsewhere: the
 * rule there is "no library met the constraints", and here one does. `@scure/base` is audited, is
 * already in the tree for the engine's own hex and Base64, and its bytes are checked against
 * `hi-base64` -- the library the reference site uses -- across every length and both alphabets in
 * `tests/encoding.test.ts`. Writing a second Base64 would add a way to be wrong, not a way to be
 * right.
 */
type Coder = { encode(bytes: Uint8Array): string; decode(text: string): Uint8Array };

function base32Coder(variant: Variant, padding: Padding): Coder {
  const padded = padding === "padded";
  switch (variant) {
    case "rfc4648-hex":
      return padded ? base32hex : base32hexnopad;
    case "crockford":
      // Crockford's specification has no padding at all, so the option does not apply to it -- the
      // form hides it, and this ignores it rather than pretending.
      return base32crockford;
    default:
      return padded ? base32 : base32nopad;
  }
}

function base58Coder(variant: Variant): Coder {
  switch (variant) {
    case "ripple":
      return base58xrp;
    case "flickr":
      return base58flickr;
    case "check":
      // Base58check is Bitcoin's alphabet plus four bytes of SHA-256d over the payload. The hash is
      // injected rather than assumed, which is why this takes a function.
      return base58checkWith(sha256);
    default:
      return base58;
  }
}

function base64Coder(variant: Variant, padding: Padding): Coder {
  const padded = padding === "padded";
  if (variant === "urlsafe") return padded ? base64url : base64urlnopad;
  return padded ? base64 : base64nopad;
}

/** Hex is written here rather than taken from a library, because the separator and case are ours. */
function encodeHexText(bytes: Uint8Array, upper: boolean, separator: Separator): string {
  const digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
  const parts: string[] = [];
  for (const byte of bytes) parts.push(digits[byte >> 4]! + digits[byte & 0x0f]!);
  return parts.join(SEPARATOR_TEXT[separator]);
}

/**
 * Hex in, bytes out, forgivingly.
 *
 * Every non-hex character is dropped before parsing, which makes a certificate fingerprint pasted
 * with its colons, a hex dump pasted with its spaces and newlines, and a `0x`-prefixed literal all
 * work without being cleaned up first. The one thing it will not do is guess at an odd number of
 * digits: `abc` could be `0abc` or `abc0` and the two are different bytes, so it says so.
 */
function decodeHexText(text: string): Uint8Array {
  const cleaned = text.replace(/0[xX]/g, "").replace(/[^0-9a-fA-F]/g, "");
  if (cleaned.length % 2 !== 0) {
    throw new Error(
      `Hex needs an even number of digits; this has ${cleaned.length}. A leading or trailing zero is missing, and which one changes the bytes.`,
    );
  }
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// ── the JSON bridge for CBOR ────────────────────────────────────────────────

/** Anything the conversion had to change on the way through, for the result panel to state. */
export interface CborNotes {
  notes: string[];
}

/** JSON's value space, which is what `JSON.parse` can hand back. */
type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function jsonToCbor(value: JsonValue, keyOrder: KeyOrder): CborValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") return value;
  if (Array.isArray(value)) return value.map((item) => jsonToCbor(item, keyOrder));

  const keys = Object.keys(value);
  // Sorted by RFC 8949 section 4.2.1's rule -- byte-wise on the encoded key -- which for the text
  // keys JSON can produce is the same as sorting the strings by UTF-8 bytes.
  if (keyOrder === "sorted") keys.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return {
    cborMap: keys.map(
      (key) => [key, jsonToCbor(value[key]!, keyOrder)] as [CborValue, CborValue],
    ),
  };
}

/**
 * A decoded CBOR item as something `JSON.stringify` can print, recording every lossy step.
 *
 * CBOR's value space is strictly larger than JSON's, so this cannot be a total function and pretending
 * otherwise is how a diagnostic tool starts lying. Rather than refuse, it converts and *says what it
 * did*: RFC 8949 section 6.1 recommends base64url for byte strings, so that is what happens to them,
 * and the note is what tells you the quotes around that string were not in the data.
 */
function cborToJson(value: CborValue, notes: CborNotes): JsonValue {
  if (value === null) return null;
  if (value === undefined) {
    notes.notes.push("CBOR `undefined` became JSON null, which is a different value.");
    return null;
  }
  if (typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") return value;

  if (typeof value === "bigint") {
    notes.notes.push(
      `The integer ${value} is outside what JSON numbers hold exactly, so it is a string here.`,
    );
    return value.toString();
  }

  if (value instanceof Uint8Array) {
    notes.notes.push(
      "Byte strings are shown as base64url, following RFC 8949 section 6.1. They were not text in the data.",
    );
    return base64urlnopad.encode(value);
  }

  if (Array.isArray(value)) return value.map((item) => cborToJson(item, notes));

  if (isCborTagged(value)) {
    if (value.tag === -1) {
      notes.notes.push("An unassigned CBOR simple value is shown as `simple(n)`.");
      return `simple(${String(value.value)})`;
    }
    // Bignums (tags 2 and 3) are a byte string standing in for an integer too large for a head,
    // so decoding them to a decimal string is the reading rather than a workaround.
    if ((value.tag === 2 || value.tag === 3) && value.value instanceof Uint8Array) {
      let magnitude = 0n;
      for (const byte of value.value) magnitude = (magnitude << 8n) | BigInt(byte);
      const result = value.tag === 2 ? magnitude : -1n - magnitude;
      notes.notes.push(
        `Tag ${value.tag} is a bignum; shown as the decimal string "${result}".`,
      );
      return result.toString();
    }
    notes.notes.push(
      `Tag ${String(value.tag)} was dropped; the value it wrapped is shown on its own.`,
    );
    return cborToJson(value.value, notes);
  }

  if (isCborMap(value)) {
    const out: { [key: string]: JsonValue } = {};
    let stringified = false;
    for (const [key, item] of value.cborMap) {
      let name: string;
      if (typeof key === "string") name = key;
      else if (typeof key === "number" || typeof key === "bigint") {
        name = key.toString();
        stringified = true;
      } else {
        throw new Error(
          "This CBOR map has a key that is neither text nor an integer, which JSON cannot represent. Decode to hex to inspect it.",
        );
      }
      if (name in out) {
        throw new Error(
          `Two map keys both become "${name}" in JSON, so the result would silently lose one.`,
        );
      }
      out[name] = cborToJson(item, notes);
    }
    if (stringified) {
      notes.notes.push(
        "Integer map keys became strings, since JSON object keys are always strings. COSE and CTAP use integer keys throughout.",
      );
    }
    return out;
  }

  throw new Error("Unsupported CBOR item");
}

// ── the two entry points the compute path uses ──────────────────────────────

export interface EncodeSettings {
  kind: EncodingKind;
  variant: Variant;
  padding: Padding;
  upper: boolean;
  separator: Separator;
  keyOrder: KeyOrder;
  jsonIndent: JsonIndent;
}

/** Bytes in, encoded text out. Throws with a message the panel can show. */
export function encodeToText(bytes: Uint8Array, settings: EncodeSettings): string {
  switch (settings.kind) {
    case "hex":
      return encodeHexText(bytes, settings.upper, settings.separator);
    case "base32":
      return base32Coder(settings.variant, settings.padding).encode(bytes);
    case "base58":
      return base58Coder(settings.variant).encode(bytes);
    case "base64":
      return base64Coder(settings.variant, settings.padding).encode(bytes);
    case "base85":
      return base85Encode(bytes, settings.variant as Base85Variant);
    case "base91":
      return base91Encode(bytes);
    case "base45":
      return base45Encode(bytes);
    case "proquints":
      return proquintsEncode(bytes);
    case "punycode":
      return punycodeEncode(new TextDecoder("utf-8").decode(bytes));
    case "bencode": {
      const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes).trim();
      try {
        const parsed = JSON.parse(text);
        return new TextDecoder("utf-8").decode(bencodeEncode(parsed));
      } catch {
        return new TextDecoder("utf-8").decode(bencodeEncode(bytes));
      }
    }
    case "bubble-babble":
      return encodeBubbleBabble(bytes);
    case "baudot":
      return decodeBaudotIta2(encodeBaudotIta2(new TextDecoder("utf-8").decode(bytes)));
    case "pgp-words":
      return encodePgpWords(bytes);
    case "gray-code":
      return Array.from(encodeGrayBytes(bytes))
        .map((b) => b.toString(2).padStart(8, "0"))
        .join(" ");
    case "cbor": {
      // The input is JSON text here rather than arbitrary bytes: CBOR encodes a *structure*, and
      // JSON is how someone types one. `decodeCbor`'s counterpart on the way back out.
      const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes).trim();
      if (text === "") throw new Error("Enter some JSON to encode as CBOR.");
      let parsed: JsonValue;
      try {
        parsed = JSON.parse(text) as JsonValue;
      } catch (error) {
        throw new Error(
          `The input is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      return encodeHexText(encodeCbor(jsonToCbor(parsed, settings.keyOrder)), false, "none");
    }
  }
}

export interface DecodeResult {
  bytes?: Uint8Array;
  text?: string;
  notes: string[];
}

/** Encoded text in, bytes out — or, for CBOR, JSON text out. Throws with a message. */
export function decodeFromText(input: string, settings: EncodeSettings): DecodeResult {
  // Whitespace is never part of any of these alphabets, and pasted values are full of it: PEM bodies
  // wrap at 64 columns, hex dumps wrap wherever the terminal did.
  const text = input.replace(/\s+/g, "");
  if (text === "") return { notes: [] };

  switch (settings.kind) {
    case "hex":
      return { bytes: decodeHexText(input), notes: [] };
    case "base32":
      // Case-insensitivity is the reason Base32 exists, so upper-casing here is part of the format
      // rather than a convenience.
      return {
        bytes: base32Coder(settings.variant, settings.padding).decode(text.toUpperCase()),
        notes: [],
      };
    case "base58":
      return { bytes: base58Coder(settings.variant).decode(text), notes: [] };
    case "base64": {
      /**
       * Padding is accepted either way round on the way in.
       *
       * `@scure/base`'s padded coders reject an unpadded value and its unpadded coders reject a padded
       * one, which is correct of them and useless here: a JWT segment has no padding, a PEM body does,
       * and a user pasting one has not chosen a setting. So the value is normalised to whatever this
       * coder wants before it sees it.
       */
      const stripped = text.replace(/=+$/, "");
      const padded = settings.padding === "padded";
      const remainder = stripped.length % 4;
      const normalised =
        padded && remainder !== 0 ? stripped + "=".repeat(4 - remainder) : stripped;
      return {
        bytes: base64Coder(settings.variant, settings.padding).decode(normalised),
        notes: [],
      };
    }
    case "base85":
      return { bytes: base85Decode(input, settings.variant as Base85Variant), notes: [] };
    case "base91":
      return { bytes: base91Decode(input), notes: [] };
    case "base45":
      return { bytes: base45Decode(input), notes: [] };
    case "proquints":
      return { bytes: proquintsDecode(input), notes: [] };
    case "punycode":
      return { bytes: new TextEncoder().encode(punycodeDecode(input)), notes: [] };
    case "bencode": {
      try {
        const decoded = bencodeDecode(new TextEncoder().encode(input));
        return {
          text: JSON.stringify(decoded, null, settings.jsonIndent === "indented" ? 2 : undefined),
          notes: [],
        };
      } catch (err) {
        throw new Error(`Bencode decode failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    case "bubble-babble":
      return { bytes: decodeBubbleBabble(input), notes: [] };
    case "baudot":
      return { bytes: new TextEncoder().encode(decodeBaudotIta2(encodeBaudotIta2(input))), notes: [] };
    case "pgp-words":
      return { bytes: decodePgpWords(input), notes: [] };
    case "gray-code": {
      const binaryTokens = input.trim().split(/\s+/).filter(Boolean);
      const rawBytes: number[] = [];
      if (binaryTokens.length > 0 && binaryTokens.every((t) => /^[01]{1,8}$/.test(t))) {
        for (const t of binaryTokens) rawBytes.push(parseInt(t, 2));
      } else {
        const cleanBits = input.replace(/[^01]/g, "");
        if (cleanBits.length > 0) {
          for (let i = 0; i < cleanBits.length; i += 8) {
            rawBytes.push(parseInt(cleanBits.slice(i, i + 8).padEnd(8, "0"), 2));
          }
        }
      }
      return { bytes: decodeGrayBytes(new Uint8Array(rawBytes)), notes: [] };
    }
    case "cbor": {
      let bytes: Uint8Array;
      try {
        bytes = decodeHexText(input);
      } catch (error) {
        throw new Error(
          `CBOR is decoded from hex bytes. ${error instanceof Error ? error.message : String(error)}`,
        );
      }
      const notes: CborNotes = { notes: [] };
      let decoded;
      try {
        decoded = decodeCbor(bytes);
      } catch (error) {
        if (error instanceof CborError) throw new Error(error.message);
        throw error;
      }
      if (decoded.trailing > 0) {
        notes.notes.push(
          `${decoded.trailing} byte${decoded.trailing === 1 ? "" : "s"} after the first item were not decoded. CBOR sequences are a real format, but this is more often a paste that picked up something extra.`,
        );
      }
      const json = cborToJson(decoded.value, notes);
      return {
        text: JSON.stringify(json, null, settings.jsonIndent === "indented" ? 2 : undefined),
        // Deduplicated: one note per kind of change, however many byte strings there were.
        notes: [...new Set(notes.notes)],
      };
    }
  }
}

