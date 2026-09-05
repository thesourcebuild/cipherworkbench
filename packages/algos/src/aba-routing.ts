/**
 * ABA Routing Transit Number:
 * 9-digit Fedwire / ACH routing identifier checksum (3*d1 + 7*d2 + 1*d3 + 3*d4 + 7*d5 + 1*d6 + 3*d7 + 7*d8 + 1*d9 mod 10 = 0).
 */

const ABA_WEIGHTS = [3, 7, 1, 3, 7, 1, 3, 7];

export function abaRoutingValidate(raw: string): { valid: boolean; reason?: string } {
  const digits = raw.replace(/\D/g, "");
  if (digits.length !== 9) return { valid: false, reason: "Must be exactly 9 digits" };

  let sum = 0;
  for (let i = 0; i < 8; i++) {
    sum += Number.parseInt(digits[i]!, 10) * ABA_WEIGHTS[i]!;
  }
  const check = Number.parseInt(digits[8]!, 10);
  const expectedCheck = (10 - (sum % 10)) % 10;
  return { valid: check === expectedCheck, reason: check === expectedCheck ? undefined : "Checksum mismatch" };
}

export function abaRoutingComputeCheckDigit(eightDigits: string): number {
  const digits = eightDigits.replace(/\D/g, "").slice(0, 8);
  if (digits.length < 8) throw new Error("Requires at least 8 digits");

  let sum = 0;
  for (let i = 0; i < 8; i++) {
    sum += Number.parseInt(digits[i]!, 10) * ABA_WEIGHTS[i]!;
  }
  return (10 - (sum % 10)) % 10;
}

export const abaRoutingCheckDigit = abaRoutingComputeCheckDigit;
