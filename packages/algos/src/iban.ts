/**
 * IBAN (International Bank Account Number):
 * ISO 13616 / MOD 97-10 checksum validation and check digit computation.
 */

export const IBAN_LENGTHS: Record<string, number> = {
  AL: 28, AD: 24, AT: 20, AZ: 28, BH: 22, BY: 28, BE: 16, BA: 20, BR: 29, BG: 22,
  CR: 22, HR: 21, CY: 28, CZ: 24, DK: 18, DO: 28, EE: 20, FO: 18, FI: 18, FR: 27,
  GE: 22, DE: 22, GI: 23, GR: 27, GL: 18, GT: 28, HU: 28, IS: 26, IE: 22, IL: 23,
  IT: 27, JO: 30, KZ: 20, XK: 20, KW: 30, LV: 21, LB: 28, LI: 21, LT: 20, LU: 20,
  MK: 19, MT: 31, MR: 27, MU: 30, MD: 24, MC: 27, ME: 22, NL: 18, NO: 15, PK: 24,
  PS: 29, PL: 28, PT: 25, QA: 29, RO: 24, LC: 32, SM: 27, ST: 25, SA: 24, RS: 22,
  SC: 31, SK: 24, SI: 19, ES: 24, SE: 24, CH: 21, TN: 24, TR: 26, UA: 29, AE: 23,
  GB: 22, VA: 22, VG: 24,
};

export function mod97(digits: string): number {
  let remainder = 0;
  for (let i = 0; i < digits.length; i += 7) {
    const chunk = String(remainder) + digits.slice(i, i + 7);
    remainder = Number.parseInt(chunk, 10) % 97;
  }
  return remainder;
}

export function ibanToDigits(ibanRearranged: string): string {
  let out = "";
  for (let i = 0; i < ibanRearranged.length; i++) {
    const ch = ibanRearranged[i]!;
    if (ch >= "0" && ch <= "9") {
      out += ch;
    } else if (ch >= "A" && ch <= "Z") {
      out += String(ch.charCodeAt(0) - 55); // A=10, B=11, ...
    } else if (ch >= "a" && ch <= "z") {
      out += String(ch.charCodeAt(0) - 87);
    }
  }
  return out;
}

export function ibanValidate(raw: string): {
  valid: boolean;
  country: string;
  checkDigits?: string;
  expectedCheckDigits?: string;
  reason?: string;
} {
  const clean = raw.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
  if (clean.length < 5) return { valid: false, country: "", reason: "Too short" };
  const country = clean.slice(0, 2);
  const checkDigits = clean.slice(2, 4);
  const expectedLen = IBAN_LENGTHS[country];
  if (expectedLen && clean.length !== expectedLen) {
    return { valid: false, country, checkDigits, reason: `Length must be ${expectedLen} for ${country}` };
  }
  // Move first 4 characters to the end
  const rearranged = clean.slice(4) + clean.slice(0, 4);
  const numeric = ibanToDigits(rearranged);
  const remainder = mod97(numeric);
  const expectedCheckDigits = ibanComputeCheckDigits(country, clean.slice(4));
  return {
    valid: remainder === 1,
    country,
    checkDigits,
    expectedCheckDigits,
    reason: remainder === 1 ? undefined : "MOD 97 check failed",
  };
}

export function ibanComputeCheckDigits(countryCode: string, bban: string): string {
  const cleanCountry = countryCode.toUpperCase().slice(0, 2);
  const cleanBban = bban.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
  const rearranged = cleanBban + cleanCountry + "00";
  const numeric = ibanToDigits(rearranged);
  const remainder = mod97(numeric);
  const checkDigit = 98 - remainder;
  return String(checkDigit).padStart(2, "0");
}

/** Generate a full IBAN string from a country code and BBAN (Basic Bank Account Number). */
export function ibanGenerate(countryCode: string, bban: string): string {
  const cleanCountry = countryCode.toUpperCase().slice(0, 2);
  const cleanBban = bban.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
  const checkDigits = ibanComputeCheckDigits(cleanCountry, cleanBban);
  return cleanCountry + checkDigits + cleanBban;
}
