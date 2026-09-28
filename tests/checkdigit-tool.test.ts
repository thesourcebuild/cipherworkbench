import { describe, expect, it } from "vitest";
import {
  CHECKDIGIT_MANIFESTS,
  CHECK_DIGIT_TOOLS,
  requireCheckDigitTool,
  type CheckDigitSpec,
  type CheckDigitToolMeta,
} from "@ocs/checkdigit";
import {
  checkDigitToolDefinition,
  createSpec,
  describeSpec,
  lint,
  RULE_CODES,
} from "@ocs/checkdigit/definition";
import { CHECK_INPUT } from "@ocs/algos";
import {
  encodeDecimal,
  encodeHex,
  rechunk,
  runStream,
  runStreams,
  type ToolResultField,
  type ToolVariant,
} from "@ocs/engine";

const ascii = (text: string) => new TextEncoder().encode(text);

async function* single(bytes: Uint8Array) {
  yield bytes;
}

function specFor(variant: string, options: CheckDigitSpec["options"] = {}): CheckDigitSpec {
  const base = createSpec({ variant });
  return { ...base, options: { ...base.options, ...options } };
}

describe("check digit tool suite", () => {
  describe("every tool computes its published check value", () => {
    for (const tool of CHECK_DIGIT_TOOLS) {
      it(`${tool.label} → ${tool.check}`, async () => {
        const result = await checkDigitToolDefinition(tool.id).compute(
          specFor(tool.id),
          CHECK_INPUT,
        );
        expect(result.error).toBeUndefined();
        expect(result.bytes![0]).toBe(tool.checkByte);
        expect(encodeDecimal(result.bytes!)).toBe(tool.check);
      });
    }

    it("advertises metadata and check value in info", () => {
      const definition = checkDigitToolDefinition("luhn");
      const info = definition.info!(specFor("luhn"));
      expect(info.find((f: ToolResultField) => f.label === "Category")?.value).toBe("Consumer & Barcode");
      expect(info.find((f: ToolResultField) => f.label === "Governing standard")?.value).toContain("ISO/IEC 7812");
      expect(info.find((f: ToolResultField) => f.label === "Check value")?.value).toBe("7");
    });
  });

  describe("all variants table", () => {
    it("lists all 8 check digit algorithms with Category and Standard columns", async () => {
      const table = checkDigitToolDefinition("luhn").variants!(specFor("luhn"));
      expect(table.noun).toBe("check digit");
      expect(table.columns).toEqual(["Category", "Standard / Application"]);
      expect(table.rows.map((r: ToolVariant) => r.id)).toEqual(CHECK_DIGIT_TOOLS.map((t: CheckDigitToolMeta) => t.id));

      const results = await runStreams(
        table.rows.map((row: ToolVariant) => row.stream()),
        single(CHECK_INPUT),
      );
      for (const [index, row] of table.rows.entries()) {
        const tool = requireCheckDigitTool(row.id);
        expect(results[index]!.bytes![0]).toBe(tool.checkByte);
      }
    });

    it("marks the tool being viewed as selected", () => {
      for (const id of ["verhoeff", "luhn", "iban"]) {
        const { rows } = checkDigitToolDefinition(id).variants!(specFor(id));
        expect(rows.find((r: ToolVariant) => r.selected)?.id).toBe(id);
      }
    });
  });

  describe("streaming", () => {
    for (const tool of CHECK_DIGIT_TOOLS) {
      it(`${tool.label} streams identically to one shot`, async () => {
        const definition = checkDigitToolDefinition(tool.id);
        const spec = specFor(tool.id);
        const input = ascii("453201511283036");
        const expected = await definition.compute(spec, input);

        for (const chunkSize of [1, 3, 7]) {
          const streamed = await runStream(
            definition.createStream!(spec),
            rechunk(single(input), chunkSize),
          );
          expect(encodeHex(streamed.bytes!), `${tool.id} at ${chunkSize}`).toBe(
            encodeHex(expected.bytes!),
          );
          expect(streamed.fields, `${tool.id} at ${chunkSize}`).toEqual(expected.fields);
        }
      });
    }

    it("refuses reuse after finish", () => {
      for (const tool of CHECK_DIGIT_TOOLS) {
        const stream = checkDigitToolDefinition(tool.id).createStream!(specFor(tool.id));
        stream.update(ascii("123"));
        stream.finish();
        expect(() => stream.update(ascii("4")), tool.id).toThrow(/after finish/);
        expect(() => stream.finish(), tool.id).toThrow(/twice/);
      }
    });
  });

  describe("catalogues and manifests", () => {
    it("all manifests belong strictly to family checkdigit", () => {
      for (const manifest of CHECKDIGIT_MANIFESTS) {
        expect(manifest.family).toBe("checkdigit");
        expect(manifest.security).toBe("not-a-mac");
        expect(manifest.streaming).toBe(true);
        expect(manifest.supportsFile).toBe(true);
        expect(manifest.supportsVerify).toBe(true);
        expect(manifest.directions).toEqual(["forward"]);
        // The default encoding is decimal (index 0)
        expect(manifest.outputEncodings[0]).toBe("decimal");
      }
    });

    it("describes every tool with full stop", () => {
      for (const tool of CHECK_DIGIT_TOOLS) {
        const sentence = describeSpec(specFor(tool.id));
        expect(sentence, tool.id).toMatch(/\.$/);
      }
    });
  });

  describe("specific tool capabilities", () => {
    it("Verhoeff detects transpositions and displays validity", async () => {
      const def = checkDigitToolDefinition("verhoeff");
      // Payload 236 -> check digit 3
      const calc = await def.compute(specFor("verhoeff"), ascii("236"));
      expect(calc.fields?.find((f: ToolResultField) => f.label === "Check digit")?.value).toBe("3");

      // Full number with check digit: 2363 -> Valid
      const valid = await def.compute(specFor("verhoeff"), ascii("2363"));
      expect(valid.fields?.find((f: ToolResultField) => f.label === "Trailing digit validity")?.value).toBe("Valid");

      // Transposed: 3263 -> Invalid
      const invalid = await def.compute(specFor("verhoeff"), ascii("3263"));
      expect(invalid.fields?.find((f: ToolResultField) => f.label === "Trailing digit validity")?.value).toBe("Invalid");
    });

    it("Damm detects adjacent transpositions", async () => {
      const def = checkDigitToolDefinition("damm");
      const calc = await def.compute(specFor("damm"), ascii("572"));
      expect(calc.fields?.find((f: ToolResultField) => f.label === "Check digit")?.value).toBe("4");

      const valid = await def.compute(specFor("damm"), ascii("5724"));
      expect(valid.fields?.find((f: ToolResultField) => f.label === "Trailing digit validity")?.value).toBe("Valid");

      const transposed = await def.compute(specFor("damm"), ascii("7524"));
      expect(transposed.fields?.find((f: ToolResultField) => f.label === "Trailing digit validity")?.value).toBe("Invalid");
    });

    it("Luhn detects payment card brand and IMEI", async () => {
      const def = checkDigitToolDefinition("luhn");
      // Visa
      const visa = await def.compute(specFor("luhn"), ascii("4532015112830366"));
      expect(visa.fields?.find((f: ToolResultField) => f.label === "Detected format")?.value).toBe("Visa");
      expect(visa.fields?.find((f: ToolResultField) => f.label === "Trailing digit validity")?.value).toBe("Valid");

      // Amex
      const amex = await def.compute(specFor("luhn"), ascii("378282246310005"));
      expect(amex.fields?.find((f: ToolResultField) => f.label === "Detected format")?.value).toBe("American Express");
    });

    it("ISBN handles ISBN-10, ISBN-13, and bidirectional conversion", async () => {
      const def = checkDigitToolDefinition("isbn");
      // ISBN-10 with check digit X
      const res10X = await def.compute(specFor("isbn"), ascii("080442957"));
      expect(res10X.fields?.find((f: ToolResultField) => f.label === "Check digit")?.value).toBe("X");

      // ISBN-10 full with conversion to ISBN-13
      const res10 = await def.compute(specFor("isbn"), ascii("0-306-40615-2"));
      expect(res10.fields?.find((f: ToolResultField) => f.label === "ISBN-10 validity")?.value).toBe("Valid");
      expect(res10.fields?.find((f: ToolResultField) => f.label === "Converted to ISBN-13")?.value).toBe("9780306406157");

      // ISBN-13 full with conversion to ISBN-10
      const res13 = await def.compute(specFor("isbn"), ascii("978-0-306-40615-7"));
      expect(res13.fields?.find((f: ToolResultField) => f.label === "ISBN-13 validity")?.value).toBe("Valid");
      expect(res13.fields?.find((f: ToolResultField) => f.label === "Converted to ISBN-10")?.value).toBe("0306406152");
    });

    it("IBAN validates German and French accounts", async () => {
      const def = checkDigitToolDefinition("iban");
      const resDE = await def.compute(specFor("iban"), ascii("DE89 3704 0044 0532 0130 00"));
      expect(resDE.fields?.find((f: ToolResultField) => f.label === "Check digits")?.value).toBe("89");
      expect(resDE.fields?.find((f: ToolResultField) => f.label === "Status")?.value).toBe("Valid IBAN");
      expect(resDE.fields?.find((f: ToolResultField) => f.label === "Country")?.value).toBe("DE");
    });

    it("ABA Routing validates Federal Reserve numbers", async () => {
      const def = checkDigitToolDefinition("aba-routing");
      // Chase NYC: 021000021
      const res = await def.compute(specFor("aba-routing"), ascii("021000021"));
      expect(res.fields?.find((f: ToolResultField) => f.label === "Check digit")?.value).toBe("1");
      expect(res.fields?.find((f: ToolResultField) => f.label === "Status")?.value).toBe("Valid Routing Number");
    });

    it("CUSIP and ISIN compute and validate correctly", async () => {
      const def = checkDigitToolDefinition("cusip-isin");
      // Apple CUSIP 037833100
      const cusip = await def.compute(specFor("cusip-isin"), ascii("037833100"));
      expect(cusip.fields?.find((f: ToolResultField) => f.label === "Check digit")?.value).toBe("0");
      expect(cusip.fields?.find((f: ToolResultField) => f.label === "Status")?.value).toBe("Valid CUSIP");

      // Apple ISIN US0378331005
      const isin = await def.compute(specFor("cusip-isin"), ascii("US0378331005"));
      expect(isin.fields?.find((f: ToolResultField) => f.label === "Check digit")?.value).toBe("5");
      expect(isin.fields?.find((f: ToolResultField) => f.label === "Status")?.value).toBe("Valid ISIN");
    });

    it("SEDOL validates LSE security identifiers", async () => {
      const def = checkDigitToolDefinition("sedol");
      // Vodafone: B16GWD5
      const sedol = await def.compute(specFor("sedol"), ascii("B16GWD5"));
      expect(sedol.fields?.find((f: ToolResultField) => f.label === "Check digit")?.value).toBe("5");
      expect(sedol.fields?.find((f: ToolResultField) => f.label === "Status")?.value).toBe("Valid SEDOL");
    });
  });

  describe("lint rules", () => {
    it("CD001 fires on every check digit tool", () => {
      expect(RULE_CODES).toEqual(["CD001"]);
      for (const tool of CHECK_DIGIT_TOOLS) {
        const diagnostics = lint(specFor(tool.id)).diagnostics;
        expect(diagnostics.map((d: { code: string }) => d.code)).toContain("CD001");
      }
    });
  });
});
