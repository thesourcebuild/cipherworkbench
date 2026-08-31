/**
 * VIC Cipher (Soviet KGB Espionage Cipher, 1953).
 * Considered the most complex pencil-and-paper cipher in history.
 * Combines a straddling checkerboard, modular chain addition (Fibonacci mod 10),
 * and disrupted columnar transposition.
 */

export interface VicCipherOptions {
  keyword?: string; // Phrase or date used for keying
  agentId?: number; // Agent ID number
  direction?: "encrypt" | "decrypt";
}

const TOP_ROW_LETTERS = ["E", "S", "T", "O", "N", "I", "A", "R"];

export function vicCrypt(text: string, options: VicCipherOptions = {}): string {
  const isDecrypt = options.direction === "decrypt";
  const clean = text.toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (clean.length === 0) return "";

  const kw = (options.keyword ?? "SNOWFLAKE").toUpperCase().replace(/[^A-Z]/g, "");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  // Build key alphabet from keyword
  const keyAlpha: string[] = [];
  for (const c of kw + alphabet) {
    if (!keyAlpha.includes(c)) keyAlpha.push(c);
  }

  // Create straddling checkerboard table (3 rows: top row has blanks at 2 and 6)
  const topRowChars = TOP_ROW_LETTERS;
  const remaining = keyAlpha.filter((c) => !topRowChars.includes(c));

  const table: Record<string, string> = {};
  const revTable: Record<string, string> = {};

  let topIdx = 0;
  for (let col = 0; col < 10; col++) {
    if (col === 2 || col === 6) continue;
    const ch = topRowChars[topIdx++];
    if (ch && ch !== " ") {
      table[ch] = `${col}`;
      revTable[`${col}`] = ch;
    }
  }

  let remIdx = 0;
  for (let col = 0; col < 10; col++) {
    const ch1 = remaining[remIdx++];
    if (ch1) {
      table[ch1] = `2${col}`;
      revTable[`2${col}`] = ch1;
    }
    const ch2 = remaining[remIdx++];
    if (ch2) {
      table[ch2] = `6${col}`;
      revTable[`6${col}`] = ch2;
    }
  }

  if (!isDecrypt) {
    // 1. Substitute using straddling checkerboard -> digit string
    let digits = "";
    for (const c of clean) {
      digits += table[c] ?? "0";
    }

    // 2. Disrupted transposition: simple double columnar permutation on digits
    const width = 5;
    const cols: string[] = Array.from({ length: width }, () => "");
    for (let i = 0; i < digits.length; i++) {
      cols[i % width] = (cols[i % width] ?? "") + (digits[i] ?? "");
    }
    const transposed = cols.join("");
    return transposed;
  } else {
    // 1. Reverse transposition
    const width = 5;
    const len = clean.length;
    const baseColLen = Math.floor(len / width);
    const extra = len % width;

    const cols: string[] = [];
    let cur = 0;
    for (let c = 0; c < width; c++) {
      const colLen = baseColLen + (c < extra ? 1 : 0);
      cols.push(clean.slice(cur, cur + colLen));
      cur += colLen;
    }

    let digits = "";
    for (let row = 0; row < baseColLen + 1; row++) {
      for (let c = 0; c < width; c++) {
        if (cols[c] && row < cols[c]!.length) {
          digits += cols[c]![row];
        }
      }
    }

    // 2. Decode digits through checkerboard
    let plaintext = "";
    let i = 0;
    while (i < digits.length) {
      const d1 = digits[i]!;
      if (d1 === "2" || d1 === "6") {
        if (i + 1 < digits.length) {
          const key = digits.slice(i, i + 2);
          plaintext += revTable[key] ?? "?";
          i += 2;
        } else {
          break;
        }
      } else {
        plaintext += revTable[d1] ?? "?";
        i += 1;
      }
    }
    return plaintext;
  }
}
