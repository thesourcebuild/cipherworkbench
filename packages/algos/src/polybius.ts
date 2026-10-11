/** Standard 5x5 Polybius square, with I and J sharing coordinate 24. */
export const POLYBIUS_SQUARE = "ABCDEFGHIKLMNOPQRSTUVWXYZ";

/** Encodes ASCII letters as whitespace-separated row/column coordinates. */
export function polybiusEncode(text: string): string {
  const coordinates: string[] = [];
  for (const character of text) {
    const code = character.codePointAt(0)!;
    if (!((code >= 65 && code <= 90) || (code >= 97 && code <= 122))) continue;
    const upper = character.toUpperCase();
    const index = POLYBIUS_SQUARE.indexOf(upper === "J" ? "I" : upper);
    const row = Math.floor(index / 5) + 1;
    const column = (index % 5) + 1;
    coordinates.push(`${row}${column}`);
  }
  return coordinates.join(" ");
}

/** Decodes only canonical 11..55 coordinates; malformed input is never skipped. */
export function polybiusDecode(text: string): string {
  const trimmed = text.trim();
  if (trimmed === "") return "";

  const tokens = trimmed.split(/\s+/);
  let output = "";
  for (const token of tokens) {
    if (!/^[1-5][1-5]$/.test(token)) {
      throw new Error(`Invalid Polybius coordinate: ${token}`);
    }
    const row = Number(token[0]) - 1;
    const column = Number(token[1]) - 1;
    output += POLYBIUS_SQUARE[row * 5 + column]!;
  }
  return output;
}

export const polybiusEncrypt = polybiusEncode;
export const polybiusDecrypt = polybiusDecode;
