import { base32, base64, base64url } from "@scure/base";
import { randomBelow, randomBytes } from "./random";
import type {
  ByteSourceMode,
  BytesEncoding,
  OutputEncoding,
  TextEncoding,
} from "@ocs/contracts/encoding";
import { decodeText, encodeText, fail, ok, type BytesResult } from "./text";

// ── hex ─────────────────────────────────────────────────────────────────────

const HEX_DIGITS = "0123456789abcdef";

/**
 * Deliberately lenient about separators. People paste digests in every shape
 * there is — `de:ad:be:ef` out of Wireshark, `DE AD BE EF` out of a hex editor,
 * `0xdeadbeef` out of source code, and multi-line output out of `xxd`. Rejecting
 * those and making the user reformat by hand would be a worse tool for no
 * correctness gain: none of these spellings is ambiguous.
 */
export function decodeHex(text: string): BytesResult {
  const cleaned = text
    .trim()
    .replace(/^0x/i, "")
    .replace(/[\s:,_-]+/g, "")
    .toLowerCase();

  if (cleaned === "") return ok(new Uint8Array(0));
  if (cleaned.length % 2 !== 0) {
    return fail(`Hex needs an even number of digits — got ${cleaned.length}.`);
  }

  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const hi = HEX_DIGITS.indexOf(cleaned[i * 2]!);
    const lo = HEX_DIGITS.indexOf(cleaned[i * 2 + 1]!);
    if (hi < 0 || lo < 0) {
      const bad = hi < 0 ? cleaned[i * 2] : cleaned[i * 2 + 1];
      return fail(`"${bad}" is not a hex digit.`);
    }
    bytes[i] = (hi << 4) | lo;
  }
  return ok(bytes);
}

export function encodeHex(bytes: Uint8Array, upper = false): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return upper ? out.toUpperCase() : out;
}

// ── base64 / base64url / base32 ─────────────────────────────────────────────

/**
 * `@scure/base`'s decoders are strict about padding and alphabet, which is the
 * right default — but base64 in the wild is routinely unpadded (JWT segments,
 * URL fragments) and routinely uses the URL-safe alphabet without saying so.
 * Normalising both here means a pasted JWT segment works in the plain Base64
 * box, rather than failing with a padding error the user cannot act on.
 */
function normalizeBase64(text: string, urlSafe: boolean): string {
  const cleaned = text.trim().replace(/\s+/g, "");
  const alphabet = urlSafe
    ? cleaned.replace(/\+/g, "-").replace(/\//g, "_")
    : cleaned.replace(/-/g, "+").replace(/_/g, "/");
  const stripped = alphabet.replace(/=+$/, "");
  const remainder = stripped.length % 4;
  if (remainder === 0) return stripped;
  if (remainder === 1) return stripped; // Invalid length — let the decoder say so.
  return stripped + "=".repeat(4 - remainder);
}

function wrapDecode(label: string, decode: () => Uint8Array): BytesResult {
  try {
    return ok(decode());
  } catch (error) {
    return fail(
      `Not valid ${label}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

export function decodeBase64(text: string): BytesResult {
  const normalized = normalizeBase64(text, false);
  if (normalized === "") return ok(new Uint8Array(0));
  return wrapDecode("Base64", () => base64.decode(normalized));
}

export function decodeBase64Url(text: string): BytesResult {
  const normalized = normalizeBase64(text, true);
  if (normalized === "") return ok(new Uint8Array(0));
  return wrapDecode("Base64url", () => base64url.decode(normalized));
}

export function decodeBase32(text: string): BytesResult {
  const stripped = text.trim().replace(/\s+/g, "").toUpperCase().replace(/=+$/, "");
  if (stripped === "") return ok(new Uint8Array(0));
  const padded = stripped.padEnd(Math.ceil(stripped.length / 8) * 8, "=");
  return wrapDecode("Base32", () => base32.decode(padded));
}

// ── input dispatch ──────────────────────────────────────────────────────────

export const MAX_TEXT_INPUT_BYTES = 50 * 1024 * 1024; // 50 MiB
export const MAX_TEXT_INPUT_CHARS = 50_000_000;

/**
 * The single entry point every tool's input goes through. `file` is absent on
 * purpose: file bytes never round-trip through a string, they come straight off
 * `File.stream()` into `ToolStream.update` (see `../stream.ts`). Passing "file"
 * here is a programming error, not a user error.
 */
export function decodeInput(
  text: string,
  mode: Exclude<ByteSourceMode, "file">,
  textEncoding: TextEncoding,
): BytesResult {
  if (text.length > MAX_TEXT_INPUT_CHARS) {
    return fail("Text input exceeds the 50 MB safety limit. Please use the File tab for large inputs.");
  }
  let res: BytesResult;
  switch (mode) {
    case "text":
      res = encodeText(text, textEncoding);
      break;
    case "hex":
      res = decodeHex(text);
      break;
    case "hex-lenient":
      res = decodeHexLenient(text);
      break;
    case "base64":
      res = decodeBase64(text);
      break;
    case "base64url":
      res = decodeBase64Url(text);
      break;
  }
  if (res.ok && res.bytes.length > MAX_TEXT_INPUT_BYTES) {
    return fail("Decoded input exceeds the 50 MB safety limit. Please use the File tab for large inputs.");
  }
  return res;
}

/**
 * Hex with everything that is not a hex digit thrown away.
 *
 * `decodeHex` already tolerates the separators people actually type — spaces, colons, commas,
 * dashes, a `0x` prefix, newlines. This goes further and drops *anything* else, which is what
 * makes a pasted `xxd` dump or a C byte array work: those carry offsets, an ASCII gutter and
 * `0x`/`,` litter that no separator list would cover. Kept as a separate function rather than a
 * flag on `decodeHex`, because silently accepting arbitrary junk is the wrong default for a tool
 * whose whole job is to be exact about bytes — the user opts into it by choosing the mode.
 */
export function decodeHexLenient(text: string): BytesResult {
  /**
   * Byte-literal prefixes go before the filter, which is the one place this deliberately
   * diverges from the reference implementation's `hex_ignore_non_hex`.
   *
   * That one drops every non-hex character and nothing else, so `{ 0xde, 0xad }` becomes
   * `0de0ad` — six digits that decode to three wrong bytes, with no error. Removing `0x` and
   * `\x` first cannot misread anything, because `x` is not a hex digit: those two sequences can
   * only ever be syntax. That makes a C array, a shell `\x` escape and a Rust literal all work.
   *
   * What it cannot fix, and no rule could: a hex *letter* appearing in the surrounding syntax is
   * indistinguishable from data. Python's `b"\xde\xad"` contributes its `b`, giving an odd digit
   * count and an error — which is the right outcome, since the alternative is a wrong answer.
   * The error message says the count is odd, which is the clue.
   */
  const cleaned = text.replace(/0[xX]|\[xX]/g, "").replace(/[^0-9a-fA-F]/g, "");
  if (cleaned === "") return ok(new Uint8Array(0));
  // An odd digit count is genuinely ambiguous, so it is still an error here. Padding it would
  // guess at whether the stray nibble belonged to the front or the back of a byte.
  if (cleaned.length % 2 !== 0) {
    return fail(
      `That leaves ${cleaned.length} hex digits, which is an odd number — a byte needs two. Check for a missing or extra digit.`,
    );
  }
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return ok(bytes);
}

/**
 * Decodes a `bytes` option's value — a key, IV, nonce, salt or AAD — using the
 * encoding stored in its companion option.
 *
 * The single decoder for that job. The form's byte counter, the length lint rules
 * and every cipher's compute path all call this, so a key can never be counted
 * one way and consumed another.
 */
export function decodeBytesValue(text: string, encoding: BytesEncoding): BytesResult {
  switch (encoding) {
    case "hex":
      return decodeHex(text);
    case "base64":
      return decodeBase64(text);
    case "base64url":
      return decodeBase64Url(text);
    case "utf-8":
      return encodeText(text, "utf-8");
    case "latin1":
      return encodeText(text, "latin1");
  }
}

// ── output dispatch ─────────────────────────────────────────────────────────

/**
 * Bytes as a big-endian unsigned integer. Only offered for tools whose output
 * genuinely is one — a CRC or Adler-32 checksum, which people do quote as
 * `3421780262`. `BigInt` rather than `number` because CRC-64 exists and would
 * silently lose precision above 2^53.
 */
export function encodeDecimal(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value.toString(10);
}

/** One space-separated group of 8 bits per byte — readable, unlike an unbroken bit run. */
export function encodeBinary(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(2).padStart(8, "0")).join(" ");
}

/**
 * Three octal digits per byte, space separated — what `od -b` prints.
 *
 * Per byte, following `encodeBinary`, and deliberately *not* following `encodeDecimal`, which renders
 * the whole thing as one big-endian integer. The split is not arbitrary: a decimal CRC-32 is a number
 * people genuinely quote (`3421780262`), whereas nobody quotes a digest as one enormous octal
 * integer. What they do have is `od -b` output to compare against, and that is grouped by byte.
 *
 * Padded to three digits because 0o7 and 0o007 are the same number and only one of them lines up in a
 * column -- the same reason `encodeBinary` pads to eight.
 */
export function encodeOctal(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(8).padStart(3, "0")).join(" ");
}

export function encodeOutput(bytes: Uint8Array, encoding: OutputEncoding): string {
  switch (encoding) {
    case "hex":
      return encodeHex(bytes, false);
    case "hex-upper":
      return encodeHex(bytes, true);
    case "base64":
      return base64.encode(bytes);
    case "base64url":
      return base64url.encode(bytes);
    case "base32":
      return base32.encode(bytes);
    case "decimal":
      return encodeDecimal(bytes);
    case "octal":
      return encodeOctal(bytes);
    case "binary":
      return encodeBinary(bytes);
    case "latin1":
      return decodeText(bytes, "latin1");
    case "utf-8":
      // Lossy by construction: `decodeText` replaces an invalid sequence with U+FFFD rather than
      // throwing, because a result panel showing a replacement character is more useful than one
      // showing an error for bytes that were never text in the first place.
      return decodeText(bytes, "utf-8");
  }
}

// ── misc byte helpers used across tool families ─────────────────────────────

export function concatBytes(...parts: readonly Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * Overwrites a buffer holding key material. Not a security guarantee — a JS
 * engine may well have copied it during a GC move, and there is no way to reach
 * those copies — but it does shorten the window in which a live reference to a
 * key sits in a long-lived object, which is worth the two lines.
 */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}

/**
 * Decodes a `bytes` option using the encoding the *catalogue* declares as its default.
 *
 * The fallback has to come from the option definition, not from a constant at the call site.
 * Getting that wrong is invisible and consequential: the options form reads
 * `defaultBytesEncoding` to decide which entry its selector starts on, so a compute path
 * that assumed hex while the option declared UTF-8 would show one encoding and use another —
 * silently deriving a different key from what the user believes they entered.
 *
 * Returns zero bytes for an absent option rather than an error. Whether absence is
 * acceptable is the caller's decision: HKDF's salt is optional by RFC 5869, PBKDF2's is not.
 */
/** Every encoding a `bytes` or `list` option may be written in. */
const BYTES_ENCODINGS = ["hex", "base64", "base64url", "utf-8", "latin1"] as const;

/**
 * The encoding a `bytes` or `list` option is currently written in.
 *
 * Shared by both decoders so the precedence rule -- the companion selector's value if it is a
 * valid encoding, otherwise the option's declared default, otherwise hex -- exists in one place.
 * It used to be inlined, and a second copy is how the two would drift.
 */
function resolveBytesEncoding(
  catalogue: { get(id: string): { defaultBytesEncoding?: BytesEncoding } | undefined },
  options: Readonly<Record<string, unknown>>,
  id: string,
): BytesEncoding {
  const declared = catalogue.get(id)?.defaultBytesEncoding ?? "hex";
  // Same companion-key convention the options form writes: `<id>Encoding`.
  const chosen = options[`${id}Encoding`];
  return typeof chosen === "string" && BYTES_ENCODINGS.includes(chosen as BytesEncoding)
    ? (chosen as BytesEncoding)
    : declared;
}

/**
 * The encodings a generated value can be written into, so `Generate` will not override them.
 *
 * Exported because the form's tooltip has to say in advance what pressing the button will do, and a
 * second list over there was a mirror waiting to drift -- the shape this repo has found in half a dozen
 * places. `encodeBytesValue` still branches in an exhaustive `switch` rather than looking this up, so a
 * sixth encoding is a compile error there; the test asserts the two agree.
 */
export const LOSSLESS_BYTES_ENCODINGS: readonly BytesEncoding[] = [
  "hex",
  "base64",
  "base64url",
];

/**
 * Every encoding `Generate` can write into, which is now all of them.
 *
 * Distinct from `LOSSLESS_BYTES_ENCODINGS` because the two answer different questions. That one asks
 * whether *arbitrary* bytes survive a round trip, which `utf-8` fails. This one asks whether the button
 * can produce a value in that encoding at all -- and it can, by generating printable characters rather
 * than encoding random bytes. Keeping them apart is what lets `encodeBytesValue` still fall back to hex
 * for real bytes: `C008`'s fix has an XTS key in hand and cannot make it readable.
 */
export const GENERATABLE_BYTES_ENCODINGS: readonly BytesEncoding[] = [
  "hex",
  "base64",
  "base64url",
  "utf-8",
  "latin1",
];

/**
 * Fresh random bytes, spelled in the encoding the field is **already set to**.
 *
 * The bug this exists for was reported and is worth stating plainly: `Generate` used to write hex and
 * set the companion encoding selector to `hex` unconditionally, so choosing Base64 and pressing
 * Generate silently moved the selector back. It was one call site shared by every `bytes` option in
 * every family -- key, IV, nonce, tweak, salt -- and by six lint fixes that generate a value, so it
 * was the same surprise in eight places.
 *
 * Returns the encoding it actually used, because two of the five genuinely cannot hold arbitrary
 * bytes and the caller has to know when it has been overridden:
 *
 * - `hex`, `base64` and `base64url` carry any byte string and give it back unchanged, so a request in
 *   one of those is honoured.
 * - `utf-8` cannot: most byte strings are not valid UTF-8 at all, so there is no text to write.
 * - `latin1` maps all 256 values one to one and is still refused, which is the one judgement here.
 *   Random bytes under it are a field full of control characters and NULs -- unreadable, and not
 *   reliably preserved by a text input. Falling back to hex and *saying so* beats writing something
 *   that looks corrupt.
 *
 * So the selector still moves for those two, and only for those two -- where it is information rather
 * than a value being taken away.
 */
export function randomBytesValue(
  length: number,
  encoding: BytesEncoding,
): { value: string; encoding: BytesEncoding } {
  /*
   * Text encodings generate *text*, rather than falling back to hex.
   *
   * The first version encoded random bytes and gave up for `utf-8` and `latin1`, on the grounds that
   * most byte strings are not valid UTF-8 -- which is true and was the wrong conclusion, and it was
   * reported as the bug it is: selecting Text (UTF-8) and pressing Generate moved the selector to hex.
   * What somebody asking for a text key wants is a random *readable* one, and that is perfectly
   * possible: pick printable ASCII, which is one byte per character in both encodings, so N characters
   * decode to exactly the N bytes the field was asked for.
   *
   * It costs entropy and the button says so. 94 printable characters is log2(94) = 6.55 bits each
   * rather than 8, so a 32-character key carries about 209 bits instead of 256 -- still far beyond
   * reach, and the honest trade for a key you can read out or paste into a config file.
   */
  if (encoding === "utf-8" || encoding === "latin1") {
    return { value: randomPrintable(length), encoding };
  }
  return encodeBytesValue(randomBytes(length), encoding);
}

/**
 * Printable ASCII, one byte per character, drawn without bias.
 *
 * `0x21` to `0x7e` -- every printable character except space, which is excluded because a leading or
 * trailing one is invisible in a text field and silently changes the key. `randomBelow` rejects rather
 * than taking a modulo, so no character is more likely than another; a modulo over 94 would favour the
 * first 68 of them, and an entropy figure this function's caller quotes would then be a claim it
 * cannot support.
 */
function randomPrintable(length: number): string {
  const FIRST = 0x21;
  const COUNT = 0x7e - 0x21 + 1;
  let out = "";
  for (let i = 0; i < length; i++) out += String.fromCharCode(FIRST + randomBelow(COUNT));
  return out;
}

/** Bits of entropy in a `randomBytesValue` result -- 8 per byte, or 6.55 for a printable one. */
export function randomValueEntropyBits(length: number, encoding: BytesEncoding): number {
  const perByte = encoding === "utf-8" || encoding === "latin1" ? Math.log2(94) : 8;
  return Math.round(length * perByte);
}

/**
 * Arbitrary bytes spelled in `encoding`, or in hex where that encoding cannot hold them.
 *
 * The general form of the above, and the inverse of `decodeBytesValue` for the three encodings that
 * round-trip. Separate because one caller has bytes rather than a length: `C008`'s fix replaces the
 * second half of an XTS key and has to re-spell the whole thing, which it cannot do by concatenating
 * strings without pinning the field to hex -- the very thing being fixed.
 */
export function encodeBytesValue(
  bytes: Uint8Array,
  encoding: BytesEncoding,
): { value: string; encoding: BytesEncoding } {
  switch (encoding) {
    case "hex":
      return { value: encodeHex(bytes), encoding };
    case "base64":
      return { value: base64.encode(bytes), encoding };
    case "base64url":
      return { value: base64url.encode(bytes), encoding };
    case "utf-8":
    case "latin1":
      // No `default`, so a sixth encoding is a compile error here rather than a silent hex fallback.
      return { value: encodeHex(bytes), encoding: "hex" };
  }
}

/**
 * The encoding a `bytes` option is written in, for a caller holding only the options bag.
 *
 * The lint fixes need this: a fix that regenerates a key has to write it in whatever encoding the
 * field is showing, and it has nothing but the spec to read. Same precedence as the decoders --
 * the companion selector, then the option's declared default, then hex -- because it is the same
 * function.
 */
export function bytesEncodingOf(
  catalogue: { get(id: string): { defaultBytesEncoding?: BytesEncoding } | undefined },
  options: Readonly<Record<string, unknown>>,
  id: string,
): BytesEncoding {
  return resolveBytesEncoding(catalogue, options, id);
}

export function decodeBytesOption(
  catalogue: { get(id: string): { defaultBytesEncoding?: BytesEncoding } | undefined },
  options: Readonly<Record<string, unknown>>,
  id: string,
): BytesResult {
  const text = options[id];
  if (typeof text !== "string" || text === "") return ok(new Uint8Array(0));
  return decodeBytesValue(text, resolveBytesEncoding(catalogue, options, id));
}

/** One decoded element of a `list` option, or the reason it could not be decoded. */
export type ListResult =
  { ok: true; items: Uint8Array[] } | { ok: false; error: string; index: number };

/**
 * Decodes a `list` option — an ordered set of byte strings, each read through the same
 * companion encoding as a `bytes` option would use.
 *
 * Exists for TupleHash, and the reason it is a list rather than a delimited string is the whole
 * point of that construction: `TupleHash(["ab", "c"])` and `TupleHash(["abc"])` are deliberately
 * different values, so the boundaries between elements are data. A newline-delimited text field
 * cannot represent an element that contains a newline, and would quietly compute the wrong digest
 * for one — which is precisely the class of silent-wrong-answer this repo spends its effort on.
 *
 * The error names the offending index, because "element 3 is not valid hex" is actionable where
 * "invalid input" is not.
 */
export function decodeListOption(
  catalogue: { get(id: string): { defaultBytesEncoding?: BytesEncoding } | undefined },
  options: Readonly<Record<string, unknown>>,
  id: string,
): ListResult {
  const raw = options[id];
  if (raw === undefined) return { ok: true, items: [] };
  if (!Array.isArray(raw)) {
    return { ok: false, error: `${id} is not a list.`, index: -1 };
  }

  const encoding = resolveBytesEncoding(catalogue, options, id);
  const items: Uint8Array[] = [];
  for (const [index, value] of raw.entries()) {
    if (typeof value !== "string") {
      return { ok: false, error: `Element ${index + 1} is not text.`, index };
    }
    // An empty element is kept, not skipped: a zero-length string is a legitimate tuple member
    // and dropping it would change the digest.
    const decoded = decodeBytesValue(value, encoding);
    if (!decoded.ok)
      return { ok: false, error: `Element ${index + 1}: ${decoded.error}`, index };
    items.push(decoded.bytes);
  }
  return { ok: true, items };
}
