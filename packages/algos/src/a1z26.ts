const A1Z26_TOKEN = "(?:[1-9]|1[0-9]|2[0-6])";
const A1Z26_INPUT = new RegExp(
  `^${A1Z26_TOKEN}(?:-${A1Z26_TOKEN})*(?:\\s+${A1Z26_TOKEN}(?:-${A1Z26_TOKEN})*)*$`,
);

/**
 * Encodes each run of ASCII letters as A=1 through Z=26, joined with hyphens.
 * Non-letter runs become word boundaries, matching the conventional A1Z26 notation.
 */
export function a1z26Encode(text: string): string {
  const words = text.match(/[A-Za-z]+/g) ?? [];
  return words
    .map((word) =>
      [...word.toUpperCase()]
        .map((character) => String(character.charCodeAt(0) - 64))
        .join("-"),
    )
    .join(" ");
}

/** Decodes canonical A1Z26 notation and rejects partial, out-of-range, or empty tokens. */
export function a1z26Decode(text: string): string {
  const trimmed = text.trim();
  if (trimmed === "") return "";
  if (!A1Z26_INPUT.test(trimmed)) {
    throw new Error("Invalid A1Z26 input; use values 1 through 26 joined by hyphens.");
  }
  return trimmed
    .split(/\s+/)
    .map((word) =>
      word
        .split("-")
        .map((token) => String.fromCharCode(64 + Number(token)))
        .join(""),
    )
    .join(" ");
}

export const a1z26Encrypt = a1z26Encode;
export const a1z26Decrypt = a1z26Decode;
