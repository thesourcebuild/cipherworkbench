/**
 * Securities Identifiers Checksums:
 * - CUSIP (Committee on Uniform Security Identification Procedures - 9 characters)
 * - ISIN (International Securities Identification Number - ISO 6166 12 characters)
 * - SEDOL (Stock Exchange Daily Official List - London Stock Exchange 7 characters)
 */

function charToCusipValue(ch: string): number {
  if (ch >= "0" && ch <= "9") return Number.parseInt(ch, 10);
  const code = ch.toUpperCase().charCodeAt(0);
  if (code >= 65 && code <= 90) return code - 64; // A=1, B=2, ..., Z=26
  if (ch === "*") return 36;
  if (ch === "@") return 37;
  if (ch === "#") return 38;
  return 0;
}

export function cusipComputeCheckDigit(eightChars: string): number {
  const clean = eightChars.toUpperCase().slice(0, 8);
  let sum = 0;

  for (let i = 0; i < clean.length; i++) {
    let val = charToCusipValue(clean[i]!);
    if (i % 2 === 1) {
      val *= 2;
    }
    sum += Math.floor(val / 10) + (val % 10);
  }
  return (10 - (sum % 10)) % 10;
}

export function cusipValidate(raw: string): { valid: boolean; reason?: string } {
  const clean = raw.toUpperCase().replace(/\s/g, "");
  if (clean.length !== 9) return { valid: false, reason: "CUSIP must be exactly 9 characters" };

  const expected = cusipComputeCheckDigit(clean.slice(0, 8));
  const check = Number.parseInt(clean[8]!, 10);
  return { valid: check === expected, reason: check === expected ? undefined : "Check digit mismatch" };
}

export function isinComputeCheckDigit(elevenChars: string): number {
  const clean = elevenChars.toUpperCase().slice(0, 11);
  let expanded = "";

  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i]!;
    if (ch >= "0" && ch <= "9") {
      expanded += ch;
    } else {
      const code = ch.charCodeAt(0);
      if (code >= 65 && code <= 90) {
        expanded += String(code - 55); // A=10, B=11, ...
      }
    }
  }

  let sum = 0;
  let double = true;
  for (let i = expanded.length - 1; i >= 0; i--) {
    let d = Number.parseInt(expanded[i]!, 10);
    if (double) {
      d *= 2;
      sum += Math.floor(d / 10) + (d % 10);
    } else {
      sum += d;
    }
    double = !double;
  }
  return (10 - (sum % 10)) % 10;
}

export function isinValidate(raw: string): { valid: boolean; reason?: string } {
  const clean = raw.toUpperCase().replace(/\s/g, "");
  if (clean.length !== 12) return { valid: false, reason: "ISIN must be exactly 12 characters" };

  const expected = isinComputeCheckDigit(clean.slice(0, 11));
  const check = Number.parseInt(clean[11]!, 10);
  return { valid: check === expected, reason: check === expected ? undefined : "Check digit mismatch" };
}

const SEDOL_WEIGHTS = [1, 3, 1, 7, 3, 9];

function charToSedolValue(ch: string): number {
  if (ch >= "0" && ch <= "9") return Number.parseInt(ch, 10);
  const code = ch.toUpperCase().charCodeAt(0);
  if (code >= 65 && code <= 90) {
    // Vowels A, E, I, O, U are never used in authentic SEDOLs, but mapping is alphanumeric (A=10)
    return code - 55;
  }
  return 0;
}

export function sedolComputeCheckDigit(sixChars: string): number {
  const clean = sixChars.toUpperCase().slice(0, 6).padEnd(6, "0");
  let sum = 0;
  for (let i = 0; i < 6; i++) {
    sum += charToSedolValue(clean[i]!) * SEDOL_WEIGHTS[i]!;
  }
  return (10 - (sum % 10)) % 10;
}

export function sedolValidate(raw: string): { valid: boolean; reason?: string } {
  const clean = raw.toUpperCase().replace(/\s/g, "");
  if (clean.length !== 7) return { valid: false, reason: "SEDOL must be exactly 7 characters" };

  const expected = sedolComputeCheckDigit(clean.slice(0, 6));
  const check = Number.parseInt(clean[6]!, 10);
  return { valid: check === expected, reason: check === expected ? undefined : "Check digit mismatch" };
}

export const cusipCheckDigit = cusipComputeCheckDigit;
export const isinCheckDigit = isinComputeCheckDigit;
export const sedolCheckDigit = sedolComputeCheckDigit;
