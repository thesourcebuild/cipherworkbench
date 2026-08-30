/**
 * Straddling Checkerboard Substitution Cipher.
 *
 * Used extensively in historical espionage (e.g. Soviet spy rings and the VIC cipher)
 * to convert alphabetic messages into variable-length digit sequences without spaces.
 * High frequency letters (e.g. E, T, A, O, N, R, I, S) take 1 digit; others take 2 digits.
 */

export interface StraddlingCheckerboardOptions {
  /** Keyword to populate the remaining positions in the board. */
  keyword?: string;
  /** 8 high-frequency letters on top row. Default: "ESTONIA R" (with 2 gaps). */
  topRowLetters?: string;
  /** The 2 digit indices for the top row gaps (0-9). Default: [2, 6]. */
  gaps?: [number, number];
  direction?: "encrypt" | "decrypt";
}

export interface BoardMapping {
  charToCode: Map<string, string>;
  codeToChar: Map<string, string>;
}

export function buildStraddlingBoard(
  keyword = "CIPHER",
  topRowLetters = "ESTONIA R",
  gaps: [number, number] = [2, 6],
): BoardMapping {
  const charToCode = new Map<string, string>();
  const codeToChar = new Map<string, string>();

  const g1 = gaps[0];
  const g2 = gaps[1];

  const topChars = topRowLetters.toUpperCase().replace(/[^A-Z]/g, "");
  const used = new Set<string>();

  let topIdx = 0;
  for (let col = 0; col < 10; col++) {
    if (col === g1 || col === g2) {
      continue;
    }
    if (topIdx < topChars.length) {
      const ch = topChars[topIdx++]!;
      used.add(ch);
      const code = col.toString();
      charToCode.set(ch, code);
      codeToChar.set(code, ch);
    }
  }

  // Populate remaining letters & digits for rows prefixed with g1 and g2
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
  const cleanKey = keyword.toUpperCase().replace(/[^A-Z0-9]/g, "");
  const keyStream = cleanKey + alphabet;

  const remaining: string[] = [];
  for (let i = 0; i < keyStream.length; i++) {
    const ch = keyStream[i]!;
    if (!used.has(ch)) {
      used.add(ch);
      remaining.push(ch);
    }
  }

  // Row 1 (prefix g1, 10 columns 0-9)
  for (let col = 0; col < 10; col++) {
    if (remaining.length > 0) {
      const ch = remaining.shift()!;
      const code = `${g1}${col}`;
      charToCode.set(ch, code);
      codeToChar.set(code, ch);
    }
  }

  // Row 2 (prefix g2, 10 columns 0-9)
  for (let col = 0; col < 10; col++) {
    if (remaining.length > 0) {
      const ch = remaining.shift()!;
      const code = `${g2}${col}`;
      charToCode.set(ch, code);
      codeToChar.set(code, ch);
    }
  }

  return { charToCode, codeToChar };
}

export function straddlingCheckerboardEncrypt(
  text: string,
  options: StraddlingCheckerboardOptions = {},
): string {
  const { charToCode } = buildStraddlingBoard(
    options.keyword,
    options.topRowLetters,
    options.gaps,
  );

  const clean = text.toUpperCase();
  let result = "";

  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i]!;
    const code = charToCode.get(ch);
    if (code !== undefined) {
      result += code;
    }
  }

  return result;
}

export function straddlingCheckerboardDecrypt(
  ciphertext: string,
  options: StraddlingCheckerboardOptions = {},
): string {
  const { codeToChar } = buildStraddlingBoard(
    options.keyword,
    options.topRowLetters,
    options.gaps,
  );

  const gaps = options.gaps ?? [2, 6];
  const g1 = gaps[0].toString();
  const g2 = gaps[1].toString();

  let plaintext = "";
  let i = 0;

  while (i < ciphertext.length) {
    const d1 = ciphertext[i]!;
    if (d1 === g1 || d1 === g2) {
      if (i + 1 < ciphertext.length) {
        const twoDigit = d1 + ciphertext[i + 1]!;
        const ch = codeToChar.get(twoDigit);
        if (ch) plaintext += ch;
        i += 2;
      } else {
        break;
      }
    } else {
      const ch = codeToChar.get(d1);
      if (ch) plaintext += ch;
      i++;
    }
  }

  return plaintext;
}
