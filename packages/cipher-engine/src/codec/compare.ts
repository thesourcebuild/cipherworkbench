import type { OutputEncoding } from "@ocs/contracts/encoding";
import { decodeBase32, decodeBase64, decodeBase64Url, decodeHex, encodeHex } from "./bytes";

/**
 * Constant-time byte comparison.
 *
 * Nobody is timing this browser tab to steal a digest, so the *practical* value
 * here is small. It is written this way regardless, for one reason worth stating:
 * this file is the reference anyone will copy from when they need to compare a
 * MAC in their own code, and a short-circuiting `===` loop is exactly the bug
 * that keeps shipping. Length is compared first and leaks — that is unavoidable
 * and harmless, since a digest's length is public.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export type VerifyStatus = "empty" | "match" | "mismatch" | "unparseable" | "wrong-length";

export interface VerifyOutcome {
  status: VerifyStatus;
  /** Which encoding the expected value was read as, once one parsed. */
  detectedAs?: OutputEncoding;
  /** Byte length the expected value decoded to — shown when it disagrees with the result's. */
  expectedLength?: number;
  actualLength: number;
  message: string;
}

/**
 * Order matters and is not arbitrary. Hex first: it is by far the most common
 * way a digest is quoted, and a hex string of even length is also valid Base32
 * and often valid Base64, so trying those first would decode `deadbeef` to the
 * wrong bytes and report a spurious mismatch. Within the remaining three,
 * length is what actually disambiguates, so each candidate is only accepted if
 * it decodes to the length we are comparing against.
 */
const CANDIDATES: readonly {
  encoding: OutputEncoding;
  decode: (text: string) => { ok: true; bytes: Uint8Array } | { ok: false; error: string };
}[] = [
  { encoding: "hex", decode: decodeHex },
  { encoding: "base64", decode: decodeBase64 },
  { encoding: "base64url", decode: decodeBase64Url },
  { encoding: "base32", decode: decodeBase32 },
];

/**
 * Compare a computed result against whatever the user pasted, without making
 * them tell us what encoding it is in.
 *
 * This is the "validating" half of the app, and the reason it auto-detects: in
 * practice you copy a digest out of a release page or a `.sha256` file and you
 * do not care whether it is hex or Base64 — you care whether it matches. Making
 * the user pick an encoding first turns a one-paste check into a three-step one,
 * and picking wrong reads as a failed verification.
 */
/**
 * The two shapes a pasted expected value arrives in pull in opposite directions,
 * and both have to work:
 *
 *  - `"BA 78 16 BF …"` out of a hex editor — the whitespace is *inside* the value.
 *  - `"ba7816bf…  archive.tar.gz"` out of a `.sha256` file — the whitespace
 *    separates the value from something that is not part of it.
 *
 * So neither "keep the whole string" nor "take the first token" is right on its
 * own. Both are tried, whole-string first: a spaced hex digest parses as a whole
 * and a checksum line does not (a filename contains characters no base alphabet
 * accepts), which resolves the two cases without having to guess which one this is.
 */
function candidateTexts(expected: string): string[] {
  const whole = expected.trim();
  const firstToken = whole.split(/\s+/)[0] ?? "";
  return firstToken === whole || firstToken === "" ? [whole] : [whole, firstToken];
}

/**
 * The same question for a result that is natively *text* rather than bytes.
 *
 * The encoding family's forward direction returns `ToolResult.text` -- a Base64 string is text, and
 * spelling it as bytes and then re-encoding them would be a round trip through the thing being
 * checked. So `verifyAgainst` had nothing to compare and the Verify panel sat inert on half that
 * family, which is the same defect the `format` family was carrying until `supportsVerify` removed the
 * panel there.
 *
 * A plain comparison after trimming, and deliberately nothing cleverer. No auto-detection, because
 * there is no encoding to detect -- the value *is* the string. No case folding either: Base64 and
 * Base32 are case-sensitive alphabets, and `deadbeef` against `DEADBEEF` is a question about hex
 * digits that the byte path already answers properly by decoding both.
 */
export function verifyText(actual: string, expected: string): VerifyOutcome {
  const wanted = expected.trim();
  if (wanted === "") {
    return { status: "empty", actualLength: actual.length, message: "Nothing to compare against." };
  }
  // The `.sha256`-style split applies here too: a value followed by a filename is still a value.
  const matched = candidateTexts(expected).some((text) => text === actual.trim());
  return matched
    ? { status: "match", actualLength: actual.length, message: "Match — compared as text." }
    : {
        status: "mismatch",
        expectedLength: wanted.length,
        actualLength: actual.length,
        message:
          wanted.length === actual.trim().length
            ? "No match. Same length, so at least one character differs."
            : `No match. The result is ${actual.trim().length} characters and this is ${wanted.length}.`,
      };
}

export function verifyAgainst(actual: Uint8Array, expected: string): VerifyOutcome {
  const texts = candidateTexts(expected);

  if (texts[0] === "") {
    return {
      status: "empty",
      actualLength: actual.length,
      message: "Paste an expected value to check against.",
    };
  }

  // Pass one: prefer a reading that decodes to exactly the right length, so an
  // encoding whose alphabet happens to accept the text but yields the wrong size
  // never wins over one that fits.
  for (const text of texts) {
    for (const candidate of CANDIDATES) {
      const result = candidate.decode(text);
      if (!result.ok || result.bytes.length !== actual.length) continue;
      return timingSafeEqual(actual, result.bytes)
        ? {
            status: "match",
            detectedAs: candidate.encoding,
            expectedLength: result.bytes.length,
            actualLength: actual.length,
            message: `Match — read as ${label(candidate.encoding)}.`,
          }
        : {
            status: "mismatch",
            detectedAs: candidate.encoding,
            expectedLength: result.bytes.length,
            actualLength: actual.length,
            message: `No match. Read as ${label(candidate.encoding)}; expected ${encodeHex(result.bytes)}.`,
          };
    }
  }

  // Pass two: fall back to anything that decodes at all, so a length mismatch is
  // reported as such rather than as "unparseable". "You compared a SHA-256 to a
  // SHA-512" is a far more useful thing to be told than "no match".
  for (const text of texts) {
    for (const candidate of CANDIDATES) {
      const result = candidate.decode(text);
      if (!result.ok || result.bytes.length === 0) continue;
      return {
        status: "wrong-length",
        detectedAs: candidate.encoding,
        expectedLength: result.bytes.length,
        actualLength: actual.length,
        message: `Length mismatch: the expected value is ${result.bytes.length} bytes (read as ${label(candidate.encoding)}), this result is ${actual.length}. Different algorithm?`,
      };
    }
  }

  return {
    status: "unparseable",
    actualLength: actual.length,
    message: "Could not read that as hex, Base64, Base64url or Base32.",
  };
}

export interface IdentifyOutcome {
  /** Candidates the expected value matched. Plural because collisions are real — see below. */
  ids: readonly string[];
  /** The encoding the expected value was read as, from the first match. */
  readAs?: OutputEncoding;
  /** It decoded to bytes at all, whether or not anything matched. Separates "no match" from "not a value". */
  anyParsed: boolean;
}

/**
 * Which of these values is the one you are holding?
 *
 * The inverse of `verifyAgainst`, and the question the Variants panel exists to answer: you have an
 * eight-bit checksum off a device and twenty CRC-8 models in front of you. Scanning the column by eye
 * is the task humans are worst at, and it is the same failure mode `verifyAgainst` was written for —
 * you skim the first two characters, they match, you stop.
 *
 * **`ids` is plural because collisions are real, not because of defensive typing.** Over the check
 * string CRC-8/I-432-1 and CRC-8/MAXIM-DOW both produce `0xA1`; three of the nine checksums coincide
 * by construction. Returning one id would be arithmetically wrong, and returning the *first* would
 * make the answer depend on catalogue order. A caller that gets two ids has to say so — a width that
 * cannot separate two models is a fact about the width.
 *
 * `verifyAgainst` is called once per candidate rather than the expected value being decoded once up
 * front, and that is deliberate: which encoding parses depends on the length being compared against,
 * and a family's rows differ in length (SHA-2 spans 28 to 64 bytes). Decoding once would have to pick
 * a length, and picking wrong reads as "no match" over a value that matches perfectly.
 */
export function identifyAmong(
  candidates: readonly { id: string; bytes: Uint8Array }[],
  expected: string,
): IdentifyOutcome {
  const ids: string[] = [];
  let readAs: OutputEncoding | undefined;
  let anyParsed = false;

  for (const candidate of candidates) {
    const outcome = verifyAgainst(candidate.bytes, expected);
    // Anything but `empty` and `unparseable` means it decoded to bytes.
    if (outcome.status !== "empty" && outcome.status !== "unparseable") anyParsed = true;
    if (outcome.status !== "match") continue;
    ids.push(candidate.id);
    readAs ??= outcome.detectedAs;
  }

  return { ids, ...(readAs === undefined ? {} : { readAs }), anyParsed };
}

function label(encoding: OutputEncoding): string {
  switch (encoding) {
    case "hex":
      return "hex";
    case "base64":
      return "Base64";
    case "base64url":
      return "Base64url";
    case "base32":
      return "Base32";
    default:
      return encoding;
  }
}
