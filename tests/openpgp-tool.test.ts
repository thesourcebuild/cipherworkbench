import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  OPTION_OPENPGP_COMPRESSION,
  OPTION_OPENPGP_KEY_PASSPHRASE,
  OPTION_OPENPGP_OPERATION,
  OPTION_OPENPGP_OUTPUT,
  OPTION_OPENPGP_PASSWORD,
  OPTION_OPENPGP_PRIVATE_KEYS,
  OPTION_OPENPGP_PROTECTION,
  OPTION_OPENPGP_RECIPIENT_KEYS,
  OPTION_OPENPGP_VERIFICATION_KEYS,
  type FormatSpec,
} from "@ocs/format";
import { createSpec, formatToolDefinition, lint } from "@ocs/format/definition";
import type { ToolComputeContext, ToolResult } from "@ocs/engine";
import { parseShareLink, buildShareLink } from "../apps/web/app/share-link";
import { EMPTY_INPUT } from "../apps/web/app/input-state";

const FIXTURES = resolve("tests/fixtures/openpgp");
const KEY_PASSPHRASE = "fixture-key-passphrase";
const MESSAGE_PASSWORD = "fixture-message-password";
const tool = formatToolDefinition("openpgp");
const utf8 = (value: string) => new TextEncoder().encode(value);
const fixture = (name: string) => new Uint8Array(readFileSync(resolve(FIXTURES, name)));
const fixtureText = (name: string) => readFileSync(resolve(FIXTURES, name), "utf8");
const base64Fixture = (name: string) => `base64:${readFileSync(resolve(FIXTURES, name)).toString("base64")}`;
const plaintext = fixture("plaintext.bin");

function spec(operation: string, options: FormatSpec["options"] = {}): FormatSpec {
  const base = createSpec({ variant: "openpgp" });
  return {
    ...base,
    options: { ...base.options, [OPTION_OPENPGP_OPERATION]: operation, ...options },
  };
}

async function run(
  operation: string,
  input: Uint8Array,
  options: FormatSpec["options"] = {},
  context?: ToolComputeContext,
): Promise<ToolResult> {
  return tool.compute(spec(operation, options), input, context);
}

function resultBytes(result: ToolResult): Uint8Array {
  expect(result.error).toBeUndefined();
  if (result.bytes) return result.bytes;
  expect(result.text).toBeTypeOf("string");
  return utf8(result.text!);
}

function field(result: ToolResult, label: string): string | undefined {
  return result.fields?.find((item) => item.label === label)?.value;
}

const privateOne = {
  [OPTION_OPENPGP_PRIVATE_KEYS]: fixtureText("private-one-protected.asc"),
  [OPTION_OPENPGP_KEY_PASSPHRASE]: KEY_PASSPHRASE,
};
const privateTwoBinary = {
  [OPTION_OPENPGP_PRIVATE_KEYS]: base64Fixture("private-two-protected.gpg"),
  [OPTION_OPENPGP_KEY_PASSPHRASE]: KEY_PASSPHRASE,
};
const signerPublic = {
  [OPTION_OPENPGP_VERIFICATION_KEYS]: fixtureText("public-one.asc"),
};
const recipientsArmored =
  fixtureText("public-one.asc") + "\n" + fixtureText("public-two.asc");
const recipientsBinary = `base64:${Buffer.concat([
  readFileSync(resolve(FIXTURES, "public-one.gpg")),
  readFileSync(resolve(FIXTURES, "public-two.gpg")),
]).toString("base64")}`;

describe("OpenPGP GnuPG interoperability", () => {
  it.each(["gpg", "asc"])("decrypts GnuPG password-encrypted %s packets", async (extension) => {
    const result = await run("password-decrypt", fixture(`password-encrypted.${extension}`), {
      [OPTION_OPENPGP_PASSWORD]: MESSAGE_PASSWORD,
    });
    expect(resultBytes(result)).toEqual(plaintext);
    expect(field(result, "Literal filename")).toBe("literal-fixture.bin");
    expect(result.suggestedFilename).toBe("literal-fixture.bin");
    expect(result.mimeType).toBe("application/octet-stream");
  });

  it.each(["gpg", "asc"])("decrypts GnuPG multi-recipient %s packets with a protected key", async (extension) => {
    const first = await run("private-key-decrypt", fixture(`public-encrypted.${extension}`), privateOne);
    const second = await run(
      "private-key-decrypt",
      fixture(`public-encrypted.${extension}`),
      privateTwoBinary,
    );
    expect(resultBytes(first)).toEqual(plaintext);
    expect(resultBytes(second)).toEqual(plaintext);
  });

  it.each(["gpg", "asc"])("verifies GnuPG attached %s signatures and reports identity", async (extension) => {
    const result = await run("verify", fixture(`signed.${extension}`), signerPublic);
    expect(resultBytes(result)).toEqual(plaintext);
    expect(field(result, "Signature")).toBe("Valid");
    expect(field(result, "Signer identity")).toContain("OpenPGP Fixture One");
    expect(field(result, "Signer fingerprint")).toMatch(/^[0-9A-F]{40}$/);
  });

  it.each(["gpg", "asc"])("decrypts and verifies GnuPG encrypted-and-signed %s packets", async (extension) => {
    const result = await run(
      "decrypt-and-verify",
      fixture(`encrypted-and-signed.${extension}`),
      { ...privateTwoBinary, ...signerPublic },
    );
    expect(resultBytes(result)).toEqual(plaintext);
    expect(field(result, "Signature")).toBe("Valid");
    expect(field(result, "Literal filename")).toBe("literal-fixture.bin");
  });
});

describe("OpenPGP operations", () => {
  it.each(["binary", "armor"])("password-encrypts and decrypts in %s", async (output) => {
    const encrypted = await run(
      "password-encrypt",
      plaintext,
      {
        [OPTION_OPENPGP_PASSWORD]: MESSAGE_PASSWORD,
        [OPTION_OPENPGP_OUTPUT]: output,
      },
      { filename: "quarterly report.bin", mimeType: "application/octet-stream" },
    );
    expect(encrypted.suggestedFilename).toBe(
      output === "armor" ? "quarterly report.bin.asc" : "quarterly report.bin.pgp",
    );
    expect(encrypted.mimeType).toBe("application/pgp-encrypted");
    if (output === "armor") expect(encrypted.text).toMatch(/^-----BEGIN PGP MESSAGE-----/);
    const decrypted = await run("password-decrypt", resultBytes(encrypted), {
      [OPTION_OPENPGP_PASSWORD]: MESSAGE_PASSWORD,
    });
    expect(resultBytes(decrypted)).toEqual(plaintext);
    expect(field(decrypted, "Literal filename")).toBe("quarterly report.bin");
  });

  it.each(["binary", "armor"])("encrypts to multiple armored or binary recipients in %s", async (output) => {
    const encrypted = await run("public-key-encrypt", plaintext, {
      [OPTION_OPENPGP_RECIPIENT_KEYS]: output === "armor" ? recipientsArmored : recipientsBinary,
      [OPTION_OPENPGP_OUTPUT]: output,
    });
    expect(field(encrypted, "Recipients")).toBe("2");
    const first = await run("private-key-decrypt", resultBytes(encrypted), privateOne);
    const second = await run("private-key-decrypt", resultBytes(encrypted), privateTwoBinary);
    expect(resultBytes(first)).toEqual(plaintext);
    expect(resultBytes(second)).toEqual(plaintext);
  });

  it.each(["binary", "armor"])("signs and verifies in %s", async (output) => {
    const signed = await run("sign", plaintext, {
      ...privateOne,
      [OPTION_OPENPGP_OUTPUT]: output,
    });
    if (output === "armor") expect(signed.text).toMatch(/^-----BEGIN PGP MESSAGE-----/);
    expect(field(signed, "Signer identity")).toContain("OpenPGP Fixture One");
    const verified = await run("verify", resultBytes(signed), signerPublic);
    expect(resultBytes(verified)).toEqual(plaintext);
    expect(field(verified, "Signature")).toBe("Valid");
  });

  it.each(["binary", "armor"])("encrypts, signs, decrypts and verifies in %s", async (output) => {
    const encrypted = await run("encrypt-and-sign", plaintext, {
      ...privateOne,
      [OPTION_OPENPGP_RECIPIENT_KEYS]: recipientsArmored,
      [OPTION_OPENPGP_OUTPUT]: output,
    });
    expect(field(encrypted, "Recipients")).toBe("2");
    const recovered = await run("decrypt-and-verify", resultBytes(encrypted), {
      ...privateTwoBinary,
      ...signerPublic,
    });
    expect(resultBytes(recovered)).toEqual(plaintext);
    expect(field(recovered, "Signature")).toBe("Valid");
  });

  it("supports every compression selection", async () => {
    for (const compression of ["uncompressed", "zip", "zlib"]) {
      const encrypted = await run("password-encrypt", plaintext, {
        [OPTION_OPENPGP_PASSWORD]: MESSAGE_PASSWORD,
        [OPTION_OPENPGP_COMPRESSION]: compression,
      });
      const decrypted = await run("password-decrypt", resultBytes(encrypted), {
        [OPTION_OPENPGP_PASSWORD]: MESSAGE_PASSWORD,
      });
      expect(resultBytes(decrypted), compression).toEqual(plaintext);
    }
  });

  it.each(["aead-gcm", "aead-ocb"])(
    "supports RFC 9580 %s without enabling unauthenticated fallback",
    async (protection) => {
    const encrypted = await run("password-encrypt", plaintext, {
      [OPTION_OPENPGP_PASSWORD]: MESSAGE_PASSWORD,
      [OPTION_OPENPGP_PROTECTION]: protection,
    });
    expect(field(encrypted, "Integrity protection")).toBe("RFC 9580 AEAD");
    const decrypted = await run("password-decrypt", resultBytes(encrypted), {
      [OPTION_OPENPGP_PASSWORD]: MESSAGE_PASSWORD,
    });
    expect(resultBytes(decrypted)).toEqual(plaintext);
    },
  );
});

describe("OpenPGP failures and policy", () => {
  it("blocks every operation whose required credentials are absent", () => {
    for (const operation of [
      "password-encrypt",
      "password-decrypt",
      "public-key-encrypt",
      "private-key-decrypt",
      "sign",
      "verify",
      "encrypt-and-sign",
      "decrypt-and-verify",
    ]) {
      expect(lint(spec(operation)).hasErrors, operation).toBe(true);
    }
  });

  it("rejects wrong passwords, private-key passphrases and recipient keys", async () => {
    expect(
      (await run("password-decrypt", fixture("password-encrypted.gpg"), {
        [OPTION_OPENPGP_PASSWORD]: "wrong",
      })).error,
    ).toMatch(/wrong|integrity|decrypt/i);
    expect(
      (await run("private-key-decrypt", fixture("public-encrypted.gpg"), {
        [OPTION_OPENPGP_PRIVATE_KEYS]: fixtureText("private-one-protected.asc"),
        [OPTION_OPENPGP_KEY_PASSPHRASE]: "wrong",
      })).error,
    ).toMatch(/passphrase is wrong/i);
    expect(
      (await run("private-key-decrypt", fixture("public-encrypted.gpg"), {
        [OPTION_OPENPGP_PRIVATE_KEYS]: fixtureText("private-wrong-protected.asc"),
        [OPTION_OPENPGP_KEY_PASSPHRASE]: KEY_PASSPHRASE,
      })).error,
    ).toMatch(/wrong|decrypt|session key/i);
  });

  it.each(["gpg", "asc"])("rejects corrupted encrypted %s packets", async (extension) => {
    const result = await run("password-decrypt", fixture(`corrupt-integrity.${extension}`), {
      [OPTION_OPENPGP_PASSWORD]: MESSAGE_PASSWORD,
    });
    expect(result.error).toMatch(/integrity|modification|decrypt|authentication/i);
    expect(result.bytes).toBeUndefined();
  });

  it.each(["gpg", "asc"])("rejects corrupted %s signatures", async (extension) => {
    const result = await run("verify", fixture(`corrupt-signature.${extension}`), signerPublic);
    expect(result.error).toMatch(/signature.*failed/i);
    expect(field(result, "Signature")).toBe("Invalid");
  });

  it("marks every private value secret and strips all of them from share links", () => {
    const current = spec("encrypt-and-sign", {
      [OPTION_OPENPGP_PASSWORD]: MESSAGE_PASSWORD,
      [OPTION_OPENPGP_PRIVATE_KEYS]: fixtureText("private-one-protected.asc"),
      [OPTION_OPENPGP_KEY_PASSPHRASE]: KEY_PASSPHRASE,
      [OPTION_OPENPGP_RECIPIENT_KEYS]: fixtureText("public-two.asc"),
    });
    const shared = buildShareLink(
      "https://example.test/",
      "openpgp",
      tool.catalogue,
      current,
      EMPTY_INPUT,
      "hex-upper",
    );
    const parsed = parseShareLink(new URL(shared.url).hash)!;
    expect(parsed.options[OPTION_OPENPGP_PASSWORD]).toBeUndefined();
    expect(parsed.options[OPTION_OPENPGP_PRIVATE_KEYS]).toBeUndefined();
    expect(parsed.options[OPTION_OPENPGP_KEY_PASSPHRASE]).toBeUndefined();
    expect(parsed.options[OPTION_OPENPGP_RECIPIENT_KEYS]).toBeDefined();
    expect(shared.omittedSecrets.sort()).toEqual([
      "Message password",
      "Private key",
      "Private-key passphrase",
    ]);
  });

  it("declares buffered processing and a bounded file size", () => {
    expect(tool.streaming).toBe(false);
    expect(tool.createStream).toBeUndefined();
    expect(tool.sourcePolicy?.maxFileBytes).toBe(64 * 1024 * 1024);
  });

  it("exposes text output only for armor and byte spellings for binary", () => {
    expect(
      tool.outputEncodingsForSpec?.(
        spec("password-encrypt", { [OPTION_OPENPGP_OUTPUT]: "armor" }),
      ),
    ).toEqual(["utf-8"]);
    expect(
      tool.outputEncodingsForSpec?.(
        spec("password-encrypt", { [OPTION_OPENPGP_OUTPUT]: "binary" }),
      ),
    ).toContain("hex");
  });
});
