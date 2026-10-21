/**
 * Tool-level tests for secret-sharing and commitment tools.
 *
 * Algorithm-level coverage remains in `algos-secret-sharing.test.ts`. These
 * tests cover the catalogue, metadata, resolver, lint, and workbench compute
 * contract without applying keypair assumptions to these tools.
 */

import { describe, expect, it } from "vitest";
import { ASYMMETRIC_TOOLS, OPTION_OPERATION, type AsymmetricSpec } from "@ocs/asymmetric";
import {
  asymmetricCatalogueFor,
  asymmetricInfo,
  asymmetricToolDefinition,
  createSpec,
  describeSpec,
  lint,
  resolveAsymmetric,
} from "@ocs/asymmetric/definition";
import { validateCatalogue } from "@ocs/engine";

const NON_KEYPAIR_IDS = ["shamir", "slip39", "pedersen"] as const;
const NON_KEYPAIR_TOOLS = ASYMMETRIC_TOOLS.filter((tool) =>
  NON_KEYPAIR_IDS.some((id) => id === tool.id),
);
const encoder = new TextEncoder();

function specFor(toolId: string, overrides: AsymmetricSpec["options"] = {}): AsymmetricSpec {
  const base = createSpec({ variant: toolId });
  return { ...base, options: { ...base.options, ...overrides } };
}

async function compute(toolId: string, operation: "generate" | "derive", input: Uint8Array) {
  const definition = asymmetricToolDefinition(toolId);
  const result = await definition.compute(
    specFor(toolId, { [OPTION_OPERATION]: operation }),
    input,
  );
  expect(result.error, `${toolId}/${operation}: ${result.error}`).toBeUndefined();
  return result;
}

describe("secret-sharing and commitment tool registration", () => {
  it("registers exactly Shamir, SLIP-39, and Pedersen as the non-keypair tools", () => {
    expect(NON_KEYPAIR_TOOLS.map((tool) => tool.id).sort()).toEqual(
      [...NON_KEYPAIR_IDS].sort(),
    );
  });
});

describe("secret-sharing and commitment catalogues", () => {
  for (const tool of NON_KEYPAIR_TOOLS) {
    it(`${tool.id} has a valid non-keypair catalogue`, () => {
      const catalogue = asymmetricCatalogueFor(tool.id);
      expect(validateCatalogue(catalogue.options)).toEqual([]);
      expect(catalogue.get("privateKey")).toBeUndefined();
      expect(catalogue.get("publicKey")).toBeUndefined();
      expect(catalogue.get(OPTION_OPERATION)).toBeDefined();
    });

    it(`${tool.id} gates options only on supported operations`, () => {
      for (const option of asymmetricCatalogueFor(tool.id).options) {
        for (const operation of option.availableOn ?? []) {
          expect(tool.operations, `${tool.id}/${option.id} is gated on ${operation}`).toContain(
            operation,
          );
        }
      }
    });

    it(`${tool.id} exposes every operation as its variant tag`, () => {
      const definition = asymmetricToolDefinition(tool.id);
      for (const operation of tool.operations) {
        const spec = specFor(tool.id, { [OPTION_OPERATION]: operation });
        expect(definition.variantTag?.(spec)).toBe(operation);
        expect(definition.readsInputForSpec?.(spec)).toBe(true);
      }
    });

    it(`${tool.id} does not use keypair or shared secret labels for operations`, () => {
      const catalogue = asymmetricCatalogueFor(tool.id);
      const op = catalogue.get(OPTION_OPERATION);
      expect(op?.choices).toBeDefined();
      for (const choice of op!.choices!) {
        expect(choice.label.toLowerCase()).not.toContain("keypair");
        expect(choice.summary?.toLowerCase()).not.toContain("keypair");
        expect(choice.label.toLowerCase()).not.toContain("shared secret");
      }
    });
  }

  it("pedersen operation choices are 'Create commitment' and 'Verify commitment'", () => {
    const catalogue = asymmetricCatalogueFor("pedersen");
    const op = catalogue.get(OPTION_OPERATION);
    expect(op?.choices?.map((c) => c.label)).toEqual(["Create commitment", "Verify commitment"]);
  });

  it("shamir and slip39 operation choices are 'Split secret' and 'Combine shares'", () => {
    for (const toolId of ["shamir", "slip39"] as const) {
      const catalogue = asymmetricCatalogueFor(toolId);
      const op = catalogue.get(OPTION_OPERATION);
      expect(op?.choices?.map((c) => c.label)).toEqual(["Split secret", "Combine shares"]);
    }
  });
});

describe("secret-sharing and commitment descriptions", () => {
  for (const [toolId, expectedTerm] of [
    ["shamir", "secret"],
    ["slip39", "SLIP-0039"],
    ["pedersen", "commitment"],
  ] as const) {
    it(`${toolId} describes its own operation rather than a keypair operation`, () => {
      const description = describeSpec(specFor(toolId));
      expect(description).toContain(expectedTerm);
      expect(description.toLowerCase()).not.toMatch(/x25519|key ?pair/);
    });
  }
});

describe("secret-sharing and commitment info", () => {
  it.each([
    ["shamir", "Algorithm"],
    ["slip39", "Standard"],
    ["pedersen", "Scheme"],
  ] as const)("%s reports scheme metadata", (toolId, expectedLabel) => {
    expect(asymmetricInfo(specFor(toolId)).map((field) => field.label)).toContain(
      expectedLabel,
    );
  });
});

describe("secret-sharing and commitment resolution and lint", () => {
  for (const tool of NON_KEYPAIR_TOOLS) {
    for (const operation of tool.operations) {
      it(`${tool.id}/${operation} resolves without curve or key fields`, () => {
        const spec = specFor(tool.id, { [OPTION_OPERATION]: operation });
        const result = resolveAsymmetric(spec);
        expect(result.ok, result.ok ? undefined : result.problem).toBe(true);
      });
    }

    it(`${tool.id} does not show the keypair-storage warning`, () => {
      const diagnostics = lint(specFor(tool.id)).diagnostics;
      expect(diagnostics.some((diagnostic) => diagnostic.code === "A007")).toBe(false);
    });
  }
});

describe("secret-sharing and commitment compute", () => {
  it("splits and reconstructs a Shamir secret through the tool definition", async () => {
    const secret = "tool-level Shamir secret";
    const generated = await compute("shamir", "generate", encoder.encode(secret));
    const reconstructed = await compute("shamir", "derive", encoder.encode(generated.text!));

    expect(generated.text?.split("\n")).toHaveLength(5);
    expect(reconstructed.text).toBe(secret);
  });

  it("splits and reconstructs a SLIP-39 secret through the tool definition", async () => {
    const secret = "0123456789abcdef";
    const generated = await compute("slip39", "generate", encoder.encode(secret));
    const reconstructed = await compute("slip39", "derive", encoder.encode(generated.text!));

    expect(generated.fields?.filter((field) => field.label.startsWith("Share #"))).toHaveLength(
      5,
    );
    expect(reconstructed.text).toBe(secret);
  });

  it("creates and verifies a Pedersen commitment through both operations", async () => {
    const generated = await compute("pedersen", "generate", encoder.encode("42"));
    const verifiedDemo = await compute("pedersen", "derive", new Uint8Array(0));

    expect(generated.text).toContain("Commitment (C)");
    const commHex = generated.fields?.find((f) => f.label === "Commitment (C)")?.value.replace(/^0x/, "");
    const rHex = generated.fields?.find((f) => f.label === "Blinding factor (r)")?.value.replace(/^0x/, "");
    expect(commHex).toBeDefined();
    expect(rHex).toBeDefined();
    if (!commHex || !rHex) throw new Error("Missing generated commitment or blinding factor in fields");

    expect(
      generated.fields?.find((field) => field.label === "Blinding factor (r)")?.secret,
    ).toBe(true);
    expect(verifiedDemo.text).toBe("COMMITMENT VERIFIED");

    // Rejects non-empty input if commitment and blinding factor are missing
    const definition = asymmetricToolDefinition("pedersen");
    const missingKeys = await definition.compute(
      specFor("pedersen", { [OPTION_OPERATION]: "derive" }),
      encoder.encode("123456789"),
    );
    expect(missingKeys.error).toContain("Verification requires both the commitment (C) and blinding factor (r)");

    // Real verification with options provided
    const verifiedReal = await definition.compute(
      specFor("pedersen", {
        [OPTION_OPERATION]: "derive",
        commitment: commHex,
        blindingFactor: rHex,
      }),
      encoder.encode("42"),
    );
    expect(verifiedReal.text).toBe("COMMITMENT VERIFIED");
    expect(verifiedReal.fields?.find((f) => f.label === "Status")?.value).toBe(
      "Valid commitment opening verified.",
    );

    // Tampered message returns COMMITMENT INVALID
    const verifiedTampered = await definition.compute(
      specFor("pedersen", {
        [OPTION_OPERATION]: "derive",
        commitment: commHex,
        blindingFactor: rHex,
      }),
      encoder.encode("43"),
    );
    expect(verifiedTampered.text).toBe("COMMITMENT INVALID");
    expect(verifiedTampered.fields?.find((f) => f.label === "Status")?.value).toContain(
      "Verification failed",
    );
  });
});
