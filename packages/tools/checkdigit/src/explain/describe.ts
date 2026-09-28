import { requireCheckDigitTool } from "../catalogue/tool-meta";
import type { CheckDigitSpec } from "../spec";

export function describeSpec(spec: CheckDigitSpec): string {
  const tool = requireCheckDigitTool(spec.variant);
  switch (tool.kind) {
    case "verhoeff":
      return "Computes the Verhoeff dihedral group D5 check digit — detects 100% of single typos and adjacent transpositions.";
    case "damm":
      return "Computes the Damm quasigroup check digit — detects all single-digit errors and adjacent transpositions without needing table inversion.";
    case "luhn":
      return "Computes the Luhn algorithm (Mod 10) check digit with card issuer and IMEI identification.";
    case "isbn":
      return "Validates and computes ISBN-10, ISBN-13, and EAN-13 check digits with bidirectional conversion.";
    case "iban":
      return "Validates and computes ISO 13616 International Bank Account Number MOD 97-10 check digits.";
    case "aba-routing":
      return "Validates and computes the 9th check digit for Federal Reserve ABA routing transit numbers.";
    case "cusip-isin":
      return "Computes the check digit for 9-digit CUSIP or 12-character ISIN securities identifiers.";
    case "sedol":
      return "Computes the 7th check digit for London Stock Exchange SEDOL security identifiers.";
  }
}
