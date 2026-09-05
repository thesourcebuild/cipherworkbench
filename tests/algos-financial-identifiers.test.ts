import { describe, expect, it } from "vitest";
import {
  ibanValidate,
  ibanGenerate,
  abaRoutingCheckDigit,
  abaRoutingValidate,
  cusipCheckDigit,
  cusipValidate,
  isinCheckDigit,
  isinValidate,
  sedolCheckDigit,
  sedolValidate,
} from "@ocs/algos";

describe("Financial Checksums & Integrity", () => {
  describe("IBAN (ISO 13616 / MOD 97-10)", () => {
    it("validates known valid IBANs", () => {
      // German test IBAN
      const resDE = ibanValidate("DE89 3704 0044 0532 0130 00");
      expect(resDE.valid).toBe(true);
      expect(resDE.country).toBe("DE");
      expect(resDE.checkDigits).toBe("89");

      // French test IBAN
      const resFR = ibanValidate("FR14 2004 1010 0505 0001 3M02 606");
      expect(resFR.valid).toBe(true);
      expect(resFR.country).toBe("FR");
    });

    it("rejects invalid IBANs", () => {
      // Tampered check digit
      const res = ibanValidate("DE88 3704 0044 0532 0130 00");
      expect(res.valid).toBe(false);
      expect(res.expectedCheckDigits).toBe("89");
    });

    it("generates correct check digits for country and BBAN", () => {
      const generated = ibanGenerate("DE", "370400440532013000");
      expect(generated).toBe("DE89370400440532013000");
      expect(ibanValidate(generated).valid).toBe(true);
    });
  });

  describe("ABA Routing Transit Number", () => {
    it("validates Federal Reserve routing numbers", () => {
      // Chase Bank NYC routing number: 021000021
      expect(abaRoutingValidate("021000021").valid).toBe(true);
      // Bank of America NC: 053000196
      expect(abaRoutingValidate("053000196").valid).toBe(true);
    });

    it("calculates 9th check digit", () => {
      expect(abaRoutingCheckDigit("02100002")).toBe(1);
      expect(abaRoutingCheckDigit("05300019")).toBe(6);
    });

    it("rejects invalid routing numbers", () => {
      expect(abaRoutingValidate("021000022").valid).toBe(false);
      expect(abaRoutingValidate("12345").valid).toBe(false);
    });
  });

  describe("CUSIP & ISIN Check Digits", () => {
    it("calculates CUSIP check digits and validates", () => {
      // Apple Inc: 037833100
      expect(cusipCheckDigit("03783310")).toBe(0);
      expect(cusipValidate("037833100").valid).toBe(true);

      // Microsoft: 594918104
      expect(cusipCheckDigit("59491810")).toBe(4);
      expect(cusipValidate("594918104").valid).toBe(true);
    });

    it("calculates ISIN check digits and validates", () => {
      // Apple ISIN: US0378331005
      expect(isinCheckDigit("US037833100")).toBe(5);
      expect(isinValidate("US0378331005").valid).toBe(true);

      // Microsoft ISIN: US5949181045
      expect(isinCheckDigit("US594918104")).toBe(5);
      expect(isinValidate("US5949181045").valid).toBe(true);
    });
  });

  describe("SEDOL Check Digit", () => {
    it("calculates SEDOL check digit and validates", () => {
      // BAE Systems: 0263494
      expect(sedolCheckDigit("026349")).toBe(4);
      expect(sedolValidate("0263494").valid).toBe(true);

      // Vodafone: B16GWD5
      expect(sedolCheckDigit("B16GWD")).toBe(5);
      expect(sedolValidate("B16GWD5").valid).toBe(true);
    });

    it("rejects tampered SEDOL", () => {
      expect(sedolValidate("B16GWD6").valid).toBe(false);
    });
  });
});
