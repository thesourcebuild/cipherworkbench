import { describe, expect, it } from "vitest";
import {
  CIPHER_MANIFESTS,
  OPTION_DIRECTION,
  OPTION_JASYPT_ITERATIONS,
  OPTION_JASYPT_IV,
  OPTION_JASYPT_PASSWORD,
  OPTION_JASYPT_PROFILE,
  OPTION_JASYPT_SALT,
  type CipherSpec,
} from "@ocs/cipher";
import {
  cipherToolDefinition,
  createSpec,
  lint,
  parseJasyptFrame,
} from "@ocs/cipher/definition";
import { encodeHex, isAvailableOn } from "@ocs/engine";
import {
  JASYPT_JAVA_UNICODE_PASSWORD_RESULT,
  JASYPT_JAVA_VECTORS,
} from "./fixtures/jasypt/vectors";

const bytesFromBase64 = (value: string) => Uint8Array.from(Buffer.from(value, "base64"));
const bytesFromHex = (value: string) => Uint8Array.from(Buffer.from(value, "hex"));

function jasyptSpec(
  vector: (typeof JASYPT_JAVA_VECTORS)[number],
  direction: "encrypt" | "decrypt",
  password: string = vector.password,
): CipherSpec {
  const base = createSpec({ variant: "jasypt" });
  return {
    ...base,
    options: {
      ...base.options,
      [OPTION_DIRECTION]: direction,
      [OPTION_JASYPT_PROFILE]: vector.profile,
      [OPTION_JASYPT_PASSWORD]: password,
      [OPTION_JASYPT_ITERATIONS]: vector.iterations,
      [OPTION_JASYPT_SALT]: vector.saltHex,
      jasyptSaltEncoding: "hex",
      [OPTION_JASYPT_IV]: vector.ivHex,
      jasyptIvEncoding: "hex",
    },
  };
}

describe("Jasypt 1.9.3 SunJCE interoperability", () => {
  const tool = cipherToolDefinition("jasypt");

  it.each(JASYPT_JAVA_VECTORS)("encrypts the Java $id fixture", async (vector) => {
    const result = await tool.compute(
      jasyptSpec(vector, "encrypt"),
      bytesFromBase64(vector.plaintextBase64),
    );
    expect(result.error).toBeUndefined();
    expect(Buffer.from(result.bytes!).toString("base64")).toBe(vector.ciphertextBase64);
    expect(encodeHex(result.bytes!).toUpperCase()).toBe(vector.ciphertextHex);
  });

  it.each(JASYPT_JAVA_VECTORS)(
    "decrypts Java $id Base64 and hexadecimal fixtures",
    async (vector) => {
      for (const framed of [
        bytesFromBase64(vector.ciphertextBase64),
        bytesFromHex(vector.ciphertextHex),
      ]) {
        const result = await tool.compute(jasyptSpec(vector, "decrypt"), framed);
        expect(result.error).toBeUndefined();
        expect(Buffer.from(result.bytes!).toString("base64")).toBe(vector.plaintextBase64);
      }
    },
  );

  it("preserves Unicode plaintext as the UTF-8 bytes used by StandardPBEStringEncryptor", async () => {
    const vector = JASYPT_JAVA_VECTORS[2];
    const result = await tool.compute(
      jasyptSpec(vector, "decrypt"),
      bytesFromBase64(vector.ciphertextBase64),
    );
    expect(new TextDecoder().decode(result.bytes)).toBe("Zażółć gęślą jaźń 🔐");
  });

  it("rejects Unicode passwords exactly as SunJCE's PBEKeyFactory does", async () => {
    expect(JASYPT_JAVA_UNICODE_PASSWORD_RESULT.result).toBe(
      "EncryptionInitializationException",
    );
    const vector = JASYPT_JAVA_VECTORS[1];
    const result = await tool.compute(
      jasyptSpec(vector, "encrypt", JASYPT_JAVA_UNICODE_PASSWORD_RESULT.password),
      bytesFromBase64(vector.plaintextBase64),
    );
    expect(result.error).toMatch(/printable ASCII/);
  });

  it.each(JASYPT_JAVA_VECTORS)(
    "fails Java's wrong-password and corrupted $id cases",
    async (vector) => {
      expect(vector.wrongPasswordFails).toBe(true);
      expect(vector.corruptionFails).toBe(true);
      const wrong = await tool.compute(
        jasyptSpec(vector, "decrypt", "wrong-password"),
        bytesFromBase64(vector.ciphertextBase64),
      );
      const corrupted = await tool.compute(
        jasyptSpec(vector, "decrypt"),
        bytesFromBase64(vector.corruptedBase64),
      );
      expect(wrong.error).toMatch(/wrong|corrupted/);
      expect(corrupted.error).toMatch(/wrong|corrupted/);
      expect(wrong.bytes).toBeUndefined();
      expect(corrupted.bytes).toBeUndefined();
    },
  );

  it("uses fresh random framing unless deterministic fixture values are supplied", async () => {
    const vector = JASYPT_JAVA_VECTORS[1];
    const spec = jasyptSpec(vector, "encrypt");
    delete spec.options[OPTION_JASYPT_SALT];
    delete spec.options[OPTION_JASYPT_IV];
    const plaintext = bytesFromBase64(vector.plaintextBase64);
    const first = await tool.compute(spec, plaintext);
    const second = await tool.compute(spec, plaintext);
    expect(first.error).toBeUndefined();
    expect(second.error).toBeUndefined();
    expect(encodeHex(first.bytes!)).not.toBe(encodeHex(second.bytes!));
    expect(parseJasyptFrame(vector.profile, first.bytes!).salt).toHaveLength(16);
    expect(parseJasyptFrame(vector.profile, first.bytes!).iv).toHaveLength(16);
  });

  it("exposes only the profile's applicable advanced fixture inputs", () => {
    const definition = cipherToolDefinition("jasypt");
    const iv = definition.catalogue.require(OPTION_JASYPT_IV);
    const salt = definition.catalogue.require(OPTION_JASYPT_SALT);
    const aesEncrypt = jasyptSpec(JASYPT_JAVA_VECTORS[1], "encrypt");
    const desEncrypt = jasyptSpec(JASYPT_JAVA_VECTORS[0], "encrypt");
    const aesDecrypt = jasyptSpec(JASYPT_JAVA_VECTORS[1], "decrypt");
    expect(isAvailableOn(iv, definition.variantTag?.(aesEncrypt))).toBe(true);
    expect(isAvailableOn(iv, definition.variantTag?.(desEncrypt))).toBe(false);
    expect(isAvailableOn(iv, definition.variantTag?.(aesDecrypt))).toBe(false);
    expect(isAvailableOn(salt, definition.variantTag?.(aesEncrypt))).toBe(true);
    expect(isAvailableOn(salt, definition.variantTag?.(aesDecrypt))).toBe(false);
  });

  it("ignores stale deterministic fields when they are hidden", async () => {
    const aes = JASYPT_JAVA_VECTORS[1];
    const decrypt = jasyptSpec(aes, "decrypt");
    decrypt.options[OPTION_JASYPT_SALT] = "not hexadecimal";
    decrypt.options[OPTION_JASYPT_IV] = "also not hexadecimal";
    const opened = await tool.compute(decrypt, bytesFromBase64(aes.ciphertextBase64));
    expect(opened.error).toBeUndefined();
    expect(Buffer.from(opened.bytes!).toString("base64")).toBe(aes.plaintextBase64);

    const des = JASYPT_JAVA_VECTORS[0];
    const encrypt = jasyptSpec(des, "encrypt");
    encrypt.options[OPTION_JASYPT_IV] = aes.ivHex;
    const sealed = await tool.compute(encrypt, bytesFromBase64(des.plaintextBase64));
    expect(sealed.error).toBeUndefined();
    expect(Buffer.from(sealed.bytes!).toString("base64")).toBe(des.ciphertextBase64);
  });

  it("marks the format legacy and reports unauthenticated, broken, and cheap settings", () => {
    const legacy = lint(jasyptSpec(JASYPT_JAVA_VECTORS[0], "encrypt"));
    expect(legacy.diagnostics.map((diagnostic) => diagnostic.code)).toEqual(
      expect.arrayContaining(["C002", "C014", "C015"]),
    );
    expect(legacy.diagnostics.find((diagnostic) => diagnostic.code === "C014")?.level).toBe(
      "insecure",
    );
    expect(CIPHER_MANIFESTS.find((manifest) => manifest.id === "jasypt")?.security).toBe(
      "legacy",
    );
  });

  it("advertises Jasypt's Base64 default and hexadecimal string format", () => {
    expect(
      CIPHER_MANIFESTS.find((manifest) => manifest.id === "jasypt")?.outputEncodings,
    ).toEqual(["base64", "hex-upper", "hex", "utf-8", "latin1"]);
  });
});
