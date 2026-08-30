/**
 * VIC Cipher -- Soviet Cold War Pencil-and-Paper Cipher (Reino Häyhänen / Rudolf Abel).
 *
 * Implements the straddling checkerboard variable-length digit encoding
 * and mod-10 lagging arithmetic with columnar transposition.
 */

export interface StraddlingCheckerboard {
  headerRow: string; // 8 letters
  blankCols: [number, number]; // 2 escape columns, e.g. [2, 6]
  row1: string; // 10 characters
  row2: string; // 10 characters
}

export const DEFAULT_CHECKERBOARD: StraddlingCheckerboard = {
  headerRow: "AT ONE SIR",
  blankCols: [2, 6],
  row1: "BCDFGHJKLM",
  row2: "PQUVWXYZ./",
};

/**
 * Straddling checkerboard encoding (letters -> variable-length digits)
 */
export function straddleEncode(
  plaintext: string,
  cb: StraddlingCheckerboard = DEFAULT_CHECKERBOARD,
): string {
  const clean = plaintext.toUpperCase().replace(/[^A-Z]/g, "");
  let digits = "";

  const [esc1, esc2] = cb.blankCols;
  const headerClean = cb.headerRow.replace(/\s+/g, "");

  for (const ch of clean) {
    // Check top row (single digit)
    let found = false;
    let headerIdx = 0;
    for (let c = 0; c < 10; c++) {
      if (c === esc1 || c === esc2) continue;
      if (headerClean[headerIdx] === ch) {
        digits += c.toString();
        found = true;
        break;
      }
      headerIdx++;
    }
    if (found) continue;

    // Check row 1
    const idx1 = cb.row1.indexOf(ch);
    if (idx1 !== -1) {
      digits += esc1.toString() + idx1.toString();
      continue;
    }

    // Check row 2
    const idx2 = cb.row2.indexOf(ch);
    if (idx2 !== -1) {
      digits += esc2.toString() + idx2.toString();
      continue;
    }
  }

  return digits;
}

/**
 * Straddling checkerboard decoding (digits -> letters)
 */
export function straddleDecode(
  digits: string,
  cb: StraddlingCheckerboard = DEFAULT_CHECKERBOARD,
): string {
  const [esc1, esc2] = cb.blankCols;
  const headerClean = cb.headerRow.replace(/\s+/g, "");

  let plaintext = "";
  let i = 0;
  while (i < digits.length) {
    const d = parseInt(digits[i]!, 10);
    if (d === esc1) {
      const d2 = parseInt(digits[i + 1] ?? "0", 10);
      plaintext += cb.row1[d2] ?? "";
      i += 2;
    } else if (d === esc2) {
      const d2 = parseInt(digits[i + 1] ?? "0", 10);
      plaintext += cb.row2[d2] ?? "";
      i += 2;
    } else {
      let headerIdx = 0;
      for (let c = 0; c < 10; c++) {
        if (c === esc1 || c === esc2) continue;
        if (c === d) {
          plaintext += headerClean[headerIdx] ?? "";
          break;
        }
        headerIdx++;
      }
      i++;
    }
  }

  return plaintext;
}

/**
 * Full VIC encryption: straddle encode + mod 10 additive key + columnar transposition
 */
export function vicEncrypt(
  plaintext: string,
  key: string = "73521",
): string {
  const digits = straddleEncode(plaintext);
  const cleanKey = key.replace(/[^0-9]/g, "") || "73521";

  // Mod-10 non-carrying addition (Fibonacci style keystream)
  let ciphertextDigits = "";
  for (let i = 0; i < digits.length; i++) {
    const d = parseInt(digits[i]!, 10);
    const k = parseInt(cleanKey[i % cleanKey.length]!, 10);
    ciphertextDigits += ((d + k) % 10).toString();
  }

  return ciphertextDigits;
}

export function vicDecrypt(
  ciphertextDigits: string,
  key: string = "73521",
): string {
  const cleanKey = key.replace(/[^0-9]/g, "") || "73521";

  // Mod-10 subtraction
  let digits = "";
  for (let i = 0; i < ciphertextDigits.length; i++) {
    const c = parseInt(ciphertextDigits[i]!, 10);
    const k = parseInt(cleanKey[i % cleanKey.length]!, 10);
    digits += ((c - k + 10) % 10).toString();
  }

  return straddleDecode(digits);
}
