import {
  abaRoutingCheckDigit,
  abaRoutingValidate,
  cusipCheckDigit,
  cusipValidate,
  dammCompute,
  dammValidate,
  ibanValidate,
  isbn10Compute,
  isbn10To13,
  isbn10Validate,
  isbn13Compute,
  isbn13To10,
  isbn13Validate,
  isinCheckDigit,
  isinValidate,
  luhnCompute,
  luhnIdentify,
  luhnValidate,
  sedolCheckDigit,
  sedolValidate,
  verhoeffCompute,
  verhoeffValidate,
} from "@ocs/algos";
import type { ToolResult, ToolResultField, ToolStream, ToolVariantTable } from "@ocs/engine";
import {
  CHECK_DIGIT_TOOLS,
  requireCheckDigitTool,
  type CheckDigitToolMeta,
} from "./catalogue/tool-meta";
import { createSpec } from "./create-spec";
import type { CheckDigitSpec } from "./spec";

interface CheckDigitEngine {
  update(chunk: Uint8Array): void;
  result(): ToolResult;
}

function createEngine(spec: CheckDigitSpec, meta: CheckDigitToolMeta): CheckDigitEngine {
  let text = "";
  const decoder = new TextDecoder();

  return {
    update(chunk: Uint8Array) {
      text += decoder.decode(chunk, { stream: true });
    },
    result(): ToolResult {
      // Flush any remaining characters
      text += decoder.decode();
      const fields: ToolResultField[] = [];
      let checkByte = 0;

      switch (meta.kind) {
        case "verhoeff": {
          const digits = text.replace(/\D/g, "");
          if (digits.length === 0) {
            fields.push({
              label: "Check digit",
              value: "—",
              hint: "Enter digits to compute the Verhoeff check digit.",
            });
          } else {
            const cd = verhoeffCompute(digits);
            checkByte = cd;
            fields.push({
              label: "Check digit",
              value: String(cd),
              hint: "Verhoeff dihedral D5 check digit (detects 100% of single typos and adjacent transpositions).",
            });
            if (digits.length >= 2) {
              const valid = verhoeffValidate(digits);
              fields.push({
                label: "Trailing digit validity",
                value: valid ? "Valid" : "Invalid",
                hint: valid
                  ? "The final digit matches the Verhoeff check digit of the preceding numbers."
                  : "The final digit does not match the expected Verhoeff check digit.",
              });
            }
          }
          break;
        }

        case "damm": {
          const digits = text.replace(/\D/g, "");
          if (digits.length === 0) {
            fields.push({
              label: "Check digit",
              value: "—",
              hint: "Enter digits to compute the Damm check digit.",
            });
          } else {
            const cd = dammCompute(digits);
            checkByte = cd;
            fields.push({
              label: "Check digit",
              value: String(cd),
              hint: "Damm quasigroup check digit (detects all single and adjacent transposition errors).",
            });
            if (digits.length >= 2) {
              const valid = dammValidate(digits);
              fields.push({
                label: "Trailing digit validity",
                value: valid ? "Valid" : "Invalid",
                hint: valid
                  ? "The final digit matches the Damm check digit of the preceding numbers."
                  : "The final digit does not match the expected Damm check digit.",
              });
            }
          }
          break;
        }

        case "luhn": {
          const digits = text.replace(/\D/g, "");
          if (digits.length === 0) {
            fields.push({
              label: "Check digit",
              value: "—",
              hint: "Enter account or device digits to compute the Luhn check digit.",
            });
          } else {
            const cd = luhnCompute(digits);
            checkByte = cd;
            fields.push({
              label: "Check digit",
              value: String(cd),
              hint: "Luhn algorithm (Mod 10) check digit.",
            });
            if (digits.length >= 2) {
              const valid = luhnValidate(digits);
              fields.push({
                label: "Trailing digit validity",
                value: valid ? "Valid" : "Invalid",
                hint: valid
                  ? "The trailing digit is a valid Luhn checksum for the full number."
                  : "The trailing digit does not match the expected Luhn checksum.",
              });
            }
            const issuer = luhnIdentify(digits);
            if (issuer) {
              fields.push({
                label: "Detected format",
                value: issuer.brand,
                hint: `Recognized ${issuer.category === "credit_card" ? "payment card network" : "equipment identifier"} prefix pattern.`,
              });
            }
          }
          break;
        }

        case "isbn": {
          const digits = text.replace(/[^0-9X]/gi, "");
          if (digits.length === 0) {
            fields.push({
              label: "Check digit",
              value: "—",
              hint: "Enter 9 digits for ISBN-10 or 12 digits for ISBN-13 / EAN-13.",
            });
          } else if (digits.length >= 12) {
            const cd = isbn13Compute(digits.slice(0, 12));
            checkByte = cd;
            fields.push({
              label: "Check digit",
              value: String(cd),
              hint: "ISBN-13 / EAN-13 modulus 10 weighted check digit.",
            });
            if (digits.length === 13) {
              const valid = isbn13Validate(digits);
              fields.push({
                label: "ISBN-13 validity",
                value: valid ? "Valid" : "Invalid",
                hint: "Verifies the full 13-digit book barcode.",
              });
              const converted = isbn13To10(digits);
              if (converted) {
                fields.push({
                  label: "Converted to ISBN-10",
                  value: converted,
                  hint: "Equivalent legacy 10-digit ISBN.",
                });
              }
            }
          } else if (digits.length >= 9) {
            const cdStr = isbn10Compute(digits.slice(0, 9));
            const cdVal = cdStr === "X" ? 10 : parseInt(cdStr, 10) || 0;
            checkByte = cdVal;
            fields.push({
              label: "Check digit",
              value: cdStr,
              hint: "ISBN-10 modulus 11 weighted check digit ('X' denotes 10).",
            });
            if (digits.length === 10) {
              const valid = isbn10Validate(digits);
              fields.push({
                label: "ISBN-10 validity",
                value: valid ? "Valid" : "Invalid",
                hint: "Verifies full 10-character ISBN identifier.",
              });
              fields.push({
                label: "Converted to ISBN-13",
                value: isbn10To13(digits),
                hint: "Standard GS1 Bookland EAN-13 barcode format (prefix 978).",
              });
            }
          } else {
            fields.push({
              label: "Check digit",
              value: "—",
              hint: `Input has ${digits.length} digits; ISBN requires 9 (ISBN-10) or 12 (ISBN-13) payload digits.`,
            });
          }
          break;
        }

        case "iban": {
          const clean = text.toUpperCase().replace(/[^A-Z0-9]/g, "");
          if (clean.length === 0) {
            fields.push({
              label: "Check digits",
              value: "—",
              hint: "Enter bank account string to compute or validate ISO 13616 IBAN check digits.",
            });
          } else {
            const res = ibanValidate(clean);
            const cdStr = res.checkDigits || res.expectedCheckDigits || "0";
            checkByte = parseInt(cdStr, 10) || 0;
            fields.push({
              label: "Check digits",
              value: cdStr.padStart(2, "0"),
              hint: "ISO 13616 MOD 97-10 two-digit check value.",
            });
            fields.push({
              label: "Status",
              value: res.valid ? "Valid IBAN" : "Invalid",
              hint: res.reason ?? (res.valid ? "Valid IBAN checksum and country structure." : "Checksum mismatch."),
            });
            if (res.country) {
              fields.push({
                label: "Country",
                value: res.country,
                hint: "ISO 3166-1 alpha-2 country code.",
              });
            }
          }
          break;
        }

        case "aba-routing": {
          const digits = text.replace(/\D/g, "");
          if (digits.length === 0) {
            fields.push({
              label: "Check digit",
              value: "—",
              hint: "Enter 8 digits to compute or 9 digits to validate an ABA routing number.",
            });
          } else if (digits.length >= 8) {
            const cd = abaRoutingCheckDigit(digits);
            checkByte = cd;
            fields.push({
              label: "Check digit",
              value: String(cd),
              hint: "9th check digit for Federal Reserve routing transit numbers (weights: 3, 7, 1).",
            });
            if (digits.length === 9) {
              const val = abaRoutingValidate(digits);
              fields.push({
                label: "Status",
                value: val.valid ? "Valid Routing Number" : "Invalid",
                hint: val.reason ?? "Valid Federal Reserve 9-digit routing identifier.",
              });
            }
          } else {
            fields.push({
              label: "Check digit",
              value: "—",
              hint: "Requires at least 8 digits to calculate routing transit check digit.",
            });
          }
          break;
        }

        case "cusip-isin": {
          const clean = text.toUpperCase().replace(/[^A-Z0-9*@#]/g, "");
          if (clean.length === 0) {
            fields.push({
              label: "Check digit",
              value: "—",
              hint: "Enter 8 characters for CUSIP or 11 characters for ISIN.",
            });
          } else if (clean.length >= 11) {
            const cd = isinCheckDigit(clean);
            checkByte = cd;
            fields.push({
              label: "Check digit",
              value: String(cd),
              hint: "12th check digit for ISO 6166 ISIN securities identifier.",
            });
            if (clean.length === 12) {
              const val = isinValidate(clean);
              fields.push({
                label: "Status",
                value: val.valid ? "Valid ISIN" : "Invalid",
                hint: val.reason ?? "ISO 6166 international securities identification number.",
              });
            }
          } else if (clean.length >= 8) {
            const cd = cusipCheckDigit(clean);
            checkByte = cd;
            fields.push({
              label: "Check digit",
              value: String(cd),
              hint: "9th check digit for North American CUSIP securities identifier.",
            });
            if (clean.length === 9) {
              const val = cusipValidate(clean);
              fields.push({
                label: "Status",
                value: val.valid ? "Valid CUSIP" : "Invalid",
                hint: val.reason ?? "ANSI X9.6 Committee on Uniform Security Identification Procedures.",
              });
            }
          } else {
            fields.push({
              label: "Check digit",
              value: "—",
              hint: "Requires 8 characters (CUSIP) or 11 characters (ISIN).",
            });
          }
          break;
        }

        case "sedol": {
          const clean = text.toUpperCase().replace(/[^A-Z0-9]/g, "");
          if (clean.length === 0) {
            fields.push({
              label: "Check digit",
              value: "—",
              hint: "Enter 6 alphanumeric characters to calculate SEDOL check digit.",
            });
          } else if (clean.length >= 6) {
            const cd = sedolCheckDigit(clean);
            checkByte = cd;
            fields.push({
              label: "Check digit",
              value: String(cd),
              hint: "7th check digit for London Stock Exchange SEDOL (weights: 1, 3, 1, 7, 3, 9).",
            });
            if (clean.length === 7) {
              const val = sedolValidate(clean);
              fields.push({
                label: "Status",
                value: val.valid ? "Valid SEDOL" : "Invalid",
                hint: val.reason ?? "London Stock Exchange security identifier.",
              });
            }
          } else {
            fields.push({
              label: "Check digit",
              value: "—",
              hint: "Requires at least 6 alphanumeric characters.",
            });
          }
          break;
        }
      }

      return {
        bytes: new Uint8Array([checkByte & 0xff]),
        fields,
      };
    },
  };
}

export function checkDigitInfo(spec: CheckDigitSpec): ToolResultField[] {
  const meta = requireCheckDigitTool(spec.variant);
  return [
    {
      label: "Category",
      value: meta.category,
    },
    {
      label: "Governing standard",
      value: meta.standard,
    },
    {
      label: "Check value",
      value: meta.check,
      hint: "Published check value for the ASCII test input \"123456789\".",
    },
  ];
}

export async function computeCheckDigit(
  spec: CheckDigitSpec,
  input: Uint8Array,
): Promise<ToolResult> {
  const meta = requireCheckDigitTool(spec.variant);
  const engine = createEngine(spec, meta);
  engine.update(input);
  return engine.result();
}

/**
 * All variants of the check digit family over the current input.
 *
 * Lists all 8 check digit algorithms, their categories, and governing standards.
 */
export function checkDigitVariants(spec: CheckDigitSpec): ToolVariantTable {
  return {
    noun: "check digit",
    columns: ["Category", "Standard / Application"],
    rows: CHECK_DIGIT_TOOLS.map((tool) => ({
      id: tool.id,
      label: tool.label,
      stream: () => createCheckDigitStream(createSpec({ variant: tool.id })),
      selected: tool.id === spec.variant,
      cells: [tool.category, tool.standard],
    })),
  };
}

export function createCheckDigitStream(spec: CheckDigitSpec): ToolStream {
  const meta = requireCheckDigitTool(spec.variant);
  const engine = createEngine(spec, meta);
  let finished = false;

  return {
    update(chunk) {
      if (finished) throw new Error(`Cannot update a ${meta.label} stream after finish().`);
      engine.update(chunk);
    },
    finish() {
      if (finished) throw new Error(`finish() called twice on the same ${meta.label} stream.`);
      finished = true;
      return engine.result();
    },
  };
}
