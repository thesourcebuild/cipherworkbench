/**
 * Check digit algorithms: Verhoeff, Damm, Luhn, and ISBN-10 / ISBN-13.
 *
 * All functions accept string or numeric inputs, ignore non-digit formatting characters
 * (such as hyphens and spaces where appropriate), and return normalized results.
 */

// ─────────────────────────────────────────────────────────────────────────────
// 1. Verhoeff Algorithm (Dihedral Group D5)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Multiplication table d(j, k) for the dihedral group D5.
 */
const VERHOEFF_D: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

/**
 * Permutation table p(i, j) based on permutation (1 5 8 9 4 2 7 0)(3 6).
 */
const VERHOEFF_P: readonly (readonly number[])[] = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/**
 * Inverse table in D5.
 */
const VERHOEFF_INV: readonly number[] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];

function extractDigits(input: string): number[] {
  const digits: number[] = [];
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (code >= 48 && code <= 57) {
      digits.push(code - 48);
    }
  }
  return digits;
}

/**
 * Computes the Verhoeff check digit for a string of digits.
 */
export function verhoeffCompute(input: string): number {
  const digits = extractDigits(input);
  if (digits.length === 0) throw new Error("Verhoeff computation requires at least one digit");

  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    const digit = digits[digits.length - 1 - i]!;
    c = VERHOEFF_D[c]![VERHOEFF_P[(i + 1) % 8]![digit]!]!;
  }
  return VERHOEFF_INV[c]!;
}

/**
 * Validates a number containing a trailing Verhoeff check digit.
 */
export function verhoeffValidate(input: string): boolean {
  const digits = extractDigits(input);
  if (digits.length < 2) return false;

  let c = 0;
  for (let i = 0; i < digits.length; i++) {
    const digit = digits[digits.length - 1 - i]!;
    c = VERHOEFF_D[c]![VERHOEFF_P[i % 8]![digit]!]!;
  }
  return c === 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Damm Algorithm (Quasigroup Table)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Anti-symmetric quasigroup of order 10 (weakly associative Latin square).
 */
const DAMM_TABLE: readonly (readonly number[])[] = [
  [0, 3, 1, 7, 5, 9, 8, 6, 4, 2],
  [7, 0, 9, 2, 1, 5, 4, 8, 6, 3],
  [4, 2, 0, 6, 8, 7, 1, 3, 5, 9],
  [1, 7, 5, 0, 9, 8, 3, 4, 2, 6],
  [6, 1, 2, 3, 0, 4, 5, 9, 7, 8],
  [3, 6, 7, 4, 2, 0, 9, 5, 8, 1],
  [5, 8, 6, 9, 7, 2, 0, 1, 3, 4],
  [8, 9, 4, 5, 3, 6, 2, 0, 1, 7],
  [9, 4, 3, 8, 6, 1, 7, 2, 0, 5],
  [2, 5, 8, 1, 4, 3, 6, 7, 9, 0],
];

/**
 * Computes the Damm check digit for a string of digits.
 */
export function dammCompute(input: string): number {
  const digits = extractDigits(input);
  if (digits.length === 0) throw new Error("Damm computation requires at least one digit");

  let c = 0;
  for (const d of digits) {
    c = DAMM_TABLE[c]![d]!;
  }
  return c;
}

/**
 * Validates a number containing a trailing Damm check digit.
 */
export function dammValidate(input: string): boolean {
  const digits = extractDigits(input);
  if (digits.length < 2) return false;

  let c = 0;
  for (const d of digits) {
    c = DAMM_TABLE[c]![d]!;
  }
  return c === 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Luhn Algorithm (Mod 10)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Computes the Luhn check digit for a string of digits.
 */
export function luhnCompute(input: string): number {
  const digits = extractDigits(input);
  if (digits.length === 0) throw new Error("Luhn computation requires at least one digit");

  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits[digits.length - 1 - i]!;
    // Double every second digit starting from the rightmost payload digit
    if (i % 2 === 0) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return (10 - (sum % 10)) % 10;
}

/**
 * Validates a number containing a trailing Luhn check digit.
 */
export function luhnValidate(input: string): boolean {
  const digits = extractDigits(input);
  if (digits.length < 2) return false;

  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits[digits.length - 1 - i]!;
    // In validation with check digit included, double every second digit starting
    // from index 1 (the digit immediately preceding the check digit).
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

export interface CardIssuerMatch {
  brand: string;
  category: "credit_card" | "imei" | "other";
}

/**
 * Identifies standard card network issuers or IMEI formats from a number.
 */
export function luhnIdentify(input: string): CardIssuerMatch | undefined {
  const digits = extractDigits(input).join("");
  const len = digits.length;

  if (len === 15 && digits.startsWith("35") || len === 15 && digits.startsWith("86")) {
    return { brand: "IMEI / TAC (Mobile Equipment)", category: "imei" };
  }
  if (digits.startsWith("4") && (len === 13 || len === 16 || len === 19)) {
    return { brand: "Visa", category: "credit_card" };
  }
  const prefix2 = Number(digits.slice(0, 2));
  const prefix4 = Number(digits.slice(0, 4));
  if (len === 16 && ((prefix2 >= 51 && prefix2 <= 55) || (prefix4 >= 2221 && prefix4 <= 2720))) {
    return { brand: "Mastercard", category: "credit_card" };
  }
  if (len === 15 && (digits.startsWith("34") || digits.startsWith("37"))) {
    return { brand: "American Express", category: "credit_card" };
  }
  if ((digits.startsWith("6011") || digits.startsWith("65") || (prefix2 >= 64 && prefix2 <= 65) || (prefix4 >= 6221 && prefix4 <= 6229)) && (len === 16 || len === 19)) {
    return { brand: "Discover", category: "credit_card" };
  }
  if (len === 14 && (digits.startsWith("36") || digits.startsWith("38") || (prefix2 >= 30 && prefix2 <= 35))) {
    return { brand: "Diners Club", category: "credit_card" };
  }
  if ((prefix4 >= 3528 && prefix4 <= 3589) && (len >= 16 && len <= 19)) {
    return { brand: "JCB", category: "credit_card" };
  }
  if (len === 15) {
    return { brand: "IMEI (15-digit Terminal Identity)", category: "imei" };
  }
  return undefined;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. ISBN-10, ISBN-13, EAN-13
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Computes the ISBN-10 check digit for a 9-digit payload.
 * Returns a string digit "0"-"9" or "X" (for value 10).
 */
export function isbn10Compute(input: string): string {
  const digits = extractDigits(input);
  if (digits.length !== 9) {
    throw new Error(`ISBN-10 check digit calculation requires exactly 9 digits (got ${digits.length})`);
  }

  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += digits[i]! * (10 - i);
  }
  const rem = (11 - (sum % 11)) % 11;
  return rem === 10 ? "X" : String(rem);
}

/**
 * Validates a 10-character ISBN-10 string.
 */
export function isbn10Validate(input: string): boolean {
  const cleaned = input.toUpperCase().replace(/[^0-9X]/g, "");
  if (cleaned.length !== 10) return false;

  let sum = 0;
  for (let i = 0; i < 9; i++) {
    const code = cleaned.charCodeAt(i);
    if (code < 48 || code > 57) return false;
    sum += (code - 48) * (10 - i);
  }

  const last = cleaned[9]!;
  const checkVal = last === "X" ? 10 : last.charCodeAt(0) - 48;
  if (checkVal < 0 || checkVal > 10) return false;
  sum += checkVal;

  return sum % 11 === 0;
}

/**
 * Computes the ISBN-13 / EAN-13 check digit for a 12-digit payload.
 */
export function isbn13Compute(input: string): number {
  const digits = extractDigits(input);
  if (digits.length !== 12) {
    throw new Error(`ISBN-13 check digit calculation requires exactly 12 digits (got ${digits.length})`);
  }

  let sum = 0;
  for (let i = 0; i < 12; i++) {
    sum += digits[i]! * (i % 2 === 0 ? 1 : 3);
  }
  return (10 - (sum % 10)) % 10;
}

/**
 * Validates a 13-digit ISBN-13 / EAN-13 string.
 */
export function isbn13Validate(input: string): boolean {
  const digits = extractDigits(input);
  if (digits.length !== 13) return false;

  let sum = 0;
  for (let i = 0; i < 13; i++) {
    sum += digits[i]! * (i % 2 === 0 ? 1 : 3);
  }
  return sum % 10 === 0;
}

/**
 * Converts a valid ISBN-10 to an ISBN-13.
 */
export function isbn10To13(isbn10: string): string {
  const cleaned = isbn10.toUpperCase().replace(/[^0-9X]/g, "");
  if (cleaned.length !== 10) throw new Error("Invalid ISBN-10 length");
  const core = "978" + cleaned.slice(0, 9);
  const check = isbn13Compute(core);
  return core + check;
}

/**
 * Converts an ISBN-13 with prefix 978 to an ISBN-10.
 * Returns null if the ISBN-13 starts with 979 (cannot be represented in ISBN-10).
 */
export function isbn13To10(isbn13: string): string | null {
  const cleaned = isbn13.replace(/[^0-9]/g, "");
  if (cleaned.length !== 13) throw new Error("Invalid ISBN-13 length");
  if (!cleaned.startsWith("978")) return null;

  const core = cleaned.slice(3, 12);
  const check = isbn10Compute(core);
  return core + check;
}
