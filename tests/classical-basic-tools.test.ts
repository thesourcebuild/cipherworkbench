import { describe, expect, it } from "vitest";
import {
  CLASSICAL_MANIFESTS,
  OPTION_DIRECTION,
  OPTION_MULTIPLIER,
  OPTION_OFFSET,
  OPTION_ROT_VARIANT,
  OPTION_SHIFT,
  type ClassicalSpec,
} from "../packages/tools/classical/src/index";
import {
  classicalToolDefinition,
  createSpec,
  lint,
  resolveClassical,
} from "../packages/tools/classical/src/definition";
import { validateCatalogue } from "../packages/cipher-engine/src/index";

const bytes = (text: string) => new TextEncoder().encode(text);

function specFor(variant: string, options: ClassicalSpec["options"] = {}): ClassicalSpec {
  const spec = createSpec({ variant });
  return { ...spec, options: { ...spec.options, ...options } };
}

async function output(variant: string, input: string, options: ClassicalSpec["options"] = {}) {
  const result = await classicalToolDefinition(variant).compute(
    specFor(variant, options),
    bytes(input),
  );
  expect(result.error, result.error).toBeUndefined();
  return result.text;
}

describe("basic classical tool metadata", () => {
  it("publishes each new tool as text-only and broken", () => {
    for (const id of ["affine", "atbash", "polybius", "a1z26", "rot"]) {
      const manifest = CLASSICAL_MANIFESTS.find((candidate) => candidate.id === id);
      expect(manifest, id).toMatchObject({
        family: "classical",
        security: "broken",
        outputEncodings: ["utf-8"],
        readsInput: true,
        supportsVerify: false,
      });
      expect(validateCatalogue(classicalToolDefinition(id).catalogue.options), id).toEqual([]);
      expect(
        lint(specFor(id)).diagnostics.some((diagnostic) => diagnostic.code === "X004"),
        id,
      ).toBe(true);
    }
  });

  it("resolves defaults from the same values shown by the controls", () => {
    const affine = resolveClassical(specFor("affine"));
    expect(affine).toMatchObject({
      ok: true,
      value: { affineMultiplier: 5, affineOffset: 8 },
    });
    const rot = resolveClassical(specFor("rot"));
    expect(rot).toMatchObject({ ok: true, value: { rotVariant: "rot47" } });
  });
});

describe("basic classical tool compute", () => {
  it("routes published vectors through the tool layer", async () => {
    expect(await output("affine", "AFFINECIPHER")).toBe("IHHWVCSWFRCP");
    expect(await output("atbash", "Hello, World!")).toBe("Svool, Dliow!");
    expect(await output("polybius", "HELLO")).toBe("23 15 31 31 34");
    expect(await output("a1z26", "ATTACK AT DAWN")).toBe("1-20-20-1-3-11 1-20 4-1-23-14");
    expect(await output("rot", "Hello, World!")).toBe("w6==@[ (@C=5P");
  });

  it("decrypts affine, Polybius and A1Z26 through Direction", async () => {
    const decrypt = { [OPTION_DIRECTION]: "decrypt" };
    expect(await output("affine", "IHHWVCSWFRCP", decrypt)).toBe("AFFINECIPHER");
    expect(await output("polybius", "23 15 31 31 34", decrypt)).toBe("HELLO");
    expect(await output("a1z26", "8-5-12-12-15", decrypt)).toBe("HELLO");
  });

  it("exposes ROT5, ROT18 and ROT47 without moving ROT13 out of Caesar", async () => {
    expect(await output("rot", "Hello 123", { [OPTION_ROT_VARIANT]: "rot5" })).toBe(
      "Hello 678",
    );
    expect(await output("rot", "Hello 123", { [OPTION_ROT_VARIANT]: "rot18" })).toBe(
      "Uryyb 678",
    );
    expect(await output("rot", "Hello, World!", { [OPTION_ROT_VARIANT]: "rot47" })).toBe(
      "w6==@[ (@C=5P",
    );
    expect(await output("caesar", "Spoiler", { [OPTION_SHIFT]: 13 })).toBe("Fcbvyre");
  });

  it("returns strict decoder failures as tool errors", async () => {
    for (const [variant, malformed] of [
      ["polybius", "23 60"],
      ["a1z26", "8--5"],
    ] as const) {
      const result = await classicalToolDefinition(variant).compute(
        specFor(variant, { [OPTION_DIRECTION]: "decrypt" }),
        bytes(malformed),
      );
      expect(result.error, variant).toBeTruthy();
      expect(result.text, variant).toBeUndefined();
    }
  });

  it("rejects a non-invertible affine multiplier in resolve, lint and compute", async () => {
    const spec = specFor("affine", { [OPTION_MULTIPLIER]: 2, [OPTION_OFFSET]: 8 });
    expect(resolveClassical(spec)).toMatchObject({ ok: false, optionId: OPTION_MULTIPLIER });
    expect(lint(spec).diagnostics).toEqual(
      expect.arrayContaining([expect.objectContaining({ code: "X005", level: "error" })]),
    );
    const result = await classicalToolDefinition("affine").compute(spec, bytes("TEST"));
    expect(result.error).toMatch(/coprime with 26/);
  });
});
