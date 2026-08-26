import type { TextEncoding } from "@ocs/contracts/encoding";
import { encodeLegacy } from "@ocs/encodings";

/**
 * Decoding user input is a normal, expected failure path — someone typing a hex
 * string is in an invalid state on every odd-numbered keystroke — so these
 * return a result rather than throwing. The UI shows `error` inline in the input
 * panel; nothing about a half-typed key is exceptional.
 */
export type BytesResult =
  | { ok: true; bytes: Uint8Array }
  | {
      ok: false;
      error: string;
      /**
       * Set when the only thing wrong is that something asynchronous has not arrived — today,
       * the WHATWG conversion tables behind a legacy character encoding. The distinction is not
       * cosmetic: a caller that treated this as an error would tell the user their input is
       * invalid a few hundred milliseconds before it becomes valid on its own.
       */
      loading?: boolean;
    };

export const ok = (bytes: Uint8Array): BytesResult => ({ ok: true, bytes });
export const fail = (error: string): BytesResult => ({ ok: false, error });

const utf8Encoder = /* @__PURE__ */ new TextEncoder();
const utf8Decoder = /* @__PURE__ */ new TextDecoder("utf-8");

/**
 * Text to bytes.
 *
 * The UTF-16 cases walk the string's code *units* rather than using
 * `TextEncoder` — which only ever emits UTF-8 — and deliberately do not
 * validate surrogate pairing. A lone surrogate is a legitimate thing to want to
 * hash: it is exactly the kind of input that distinguishes one implementation's
 * digest from another's, and silently substituting U+FFFD would make this tool
 * lie about what it hashed.
 */
export function encodeText(text: string, encoding: TextEncoding): BytesResult {
  switch (encoding) {
    case "utf-8":
      return ok(utf8Encoder.encode(text));

    case "utf-16le":
    case "utf-16be": {
      const little = encoding === "utf-16le";
      const bytes = new Uint8Array(text.length * 2);
      for (let i = 0; i < text.length; i++) {
        const unit = text.charCodeAt(i);
        bytes[i * 2 + (little ? 0 : 1)] = unit & 0xff;
        bytes[i * 2 + (little ? 1 : 0)] = unit >>> 8;
      }
      return ok(bytes);
    }

    case "latin1": {
      const bytes = new Uint8Array(text.length);
      for (let i = 0; i < text.length; i++) {
        const unit = text.charCodeAt(i);
        if (unit > 0xff) {
          // Not clamped or replaced: Latin-1 genuinely cannot carry this
          // character, and quietly mangling it would produce a digest of
          // something the user never entered.
          return fail(
            `"${text[i]}" (U+${unit.toString(16).toUpperCase().padStart(4, "0")}) has no Latin-1 encoding. Use UTF-8, or enter the bytes as hex.`,
          );
        }
        bytes[i] = unit;
      }
      return ok(bytes);
    }

    /**
     * The thirty-six legacy encodings, through `@ocs/encodings`.
     *
     * Kept out of this switch on purpose: those need 635 KB of WHATWG conversion tables and
     * this module is on the eagerly-bundled path, so the delegate holds them behind a dynamic
     * import. Until the tables have loaded, `encodeLegacy` returns a failure carrying
     * `loading: true`, which the input panel renders as a pending state rather than an error —
     * see `ensureLegacyTables`.
     */
    default:
      return encodeLegacy(encoding, text);
  }
}

/**
 * Bytes back to text. Used for decrypted output and for the `latin1` output
 * encoding — never for digests, which have no text reading.
 *
 * UTF-8 here is lossy by construction (`TextDecoder` substitutes U+FFFD for
 * invalid sequences), which is correct for *display* of something that was
 * meant to be text. Callers that must not lose bytes use the `hex` or `base64`
 * output encoding instead.
 */
export function decodeText(bytes: Uint8Array, encoding: TextEncoding): string {
  switch (encoding) {
    case "utf-8":
      return utf8Decoder.decode(bytes);

    case "utf-16le":
    case "utf-16be": {
      const little = encoding === "utf-16le";
      const units: number[] = [];
      // A trailing odd byte cannot form a code unit; dropping it is the only
      // option that does not invent data.
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        const lo = bytes[i + (little ? 0 : 1)]!;
        const hi = bytes[i + (little ? 1 : 0)]!;
        units.push((hi << 8) | lo);
      }
      return fromCharCodes(units);
    }

    case "latin1":
      return fromCharCodes(Array.from(bytes));

    /**
     * Every legacy encoding, decoded by the platform.
     *
     * This direction needs no tables at all: `TextDecoder` is required to support the whole
     * WHATWG set and does so in every browser, in an Electron renderer and in Node. It is only
     * the *encoding* direction the standard withholds. So the asymmetry that makes
     * `@ocs/encodings` necessary for `encodeText` leaves nothing to do here.
     */
    default:
      try {
        return new TextDecoder(encoding).decode(bytes);
      } catch {
        // An unknown label. Latin-1 is the reading that loses no bytes.
        return fromCharCodes(Array.from(bytes));
      }
  }
}

/**
 * `String.fromCharCode(...units)` blows the argument limit somewhere around
 * 100k units, which a decrypted file trivially exceeds. Chunked instead.
 */
function fromCharCodes(units: readonly number[]): string {
  const CHUNK = 8192;
  if (units.length <= CHUNK) return String.fromCharCode(...units);
  let out = "";
  for (let i = 0; i < units.length; i += CHUNK) {
    out += String.fromCharCode(...units.slice(i, i + CHUNK));
  }
  return out;
}
