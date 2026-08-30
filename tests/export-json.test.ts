import { describe, expect, it } from "vitest";
import { TOOL_MANIFESTS } from "@ocs/registry";
import { buildExportPayload } from "../apps/web/app/export-json";
import type { InputState } from "../apps/web/app/input-state";
import type { ToolResult, ToolSpecBase } from "@ocs/engine";

describe("buildExportPayload", () => {
  it("exports Fernet encryption state matching the expected schema", () => {
    const fernetManifest = TOOL_MANIFESTS.find((m) => m.id === "fernet")!;

    const spec: ToolSpecBase = {
      specVersion: 1,
      options: {
        mode: "encrypt",
        key: "Wghwi-lJZNNXLSfgDWw2oTpkc2bexPuioh-bgXlED9c=",
        keySource: "directinput",
        kdfDerives: "key-iv",
        kdfEnvelope: "none",
        kdfHash: "sha256",
        kdfArgon2Variant: "argon2id",
        timestampFormat: "auto",
        nonce: "Rlg1V6oeciFjQh9YkvtKyw==",
      },
    };

    const input: InputState = {
      mode: "text",
      text: "123456789",
      textEncoding: "utf-8",
    };

    const result: ToolResult = {
      text: "gAAAAABqlEWhRlg1V6oeciFjQh9YkvtKy0g_yRUEqXd3iC6nK8kRZZtd9lEG2b-tsIUndZOTQqrXsnzS8SrbYhER0-aVgk2Qkw==",
      fields: [
        { label: "Construction", value: "Fernet" },
        { label: "Tag", value: "b27cd2f12adb621111d3e695824d9093" },
        {
          label: "Ciphertext without tag",
          value:
            "80000000006a9445a146583557aa1e722163421f5892fb4acb483fc91504a97777882ea72bc911659b5df65106d9bfadb0852775939342aad7",
        },
        { label: "Nonce", value: "46583557aa1e722163421f5892fb4acb" },
        { label: "Token timestamp", value: "2026-08-30T15:00:49Z (1788102049)" },
        { label: "Token IV", value: "46583557aa1e722163421f5892fb4acb" },
        {
          label: "HMAC",
          value: "5df65106d9bfadb0852775939342aad7b27cd2f12adb621111d3e695824d9093",
        },
      ],
    };

    const payload = buildExportPayload(fernetManifest, spec, input, result, "base64url");

    expect(payload.algorithm).toBe("Fernet");
    expect(payload.mode).toBe("encrypt");
    expect(payload.tool).toContain("/tools/fernet/");
    expect(payload.result.output).toBe(
      "gAAAAABqlEWhRlg1V6oeciFjQh9YkvtKy0g_yRUEqXd3iC6nK8kRZZtd9lEG2b-tsIUndZOTQqrXsnzS8SrbYhER0-aVgk2Qkw==",
    );
    expect(payload.result.construction).toBe("Fernet");
    expect(payload.result.tag).toBe("b27cd2f12adb621111d3e695824d9093");
    expect(payload.result.ciphertextWithoutTag).toBe(
      "80000000006a9445a146583557aa1e722163421f5892fb4acb483fc91504a97777882ea72bc911659b5df65106d9bfadb0852775939342aad7",
    );
    expect(payload.result.nonce).toBe("46583557aa1e722163421f5892fb4acb");
    expect(payload.result.timeStamp).toBe("2026-08-30T15:00:49Z (1788102049)");
    expect(payload.result.initialVector).toBe("46583557aa1e722163421f5892fb4acb");
    expect(payload.result.hmac).toBe(
      "5df65106d9bfadb0852775939342aad7b27cd2f12adb621111d3e695824d9093",
    );
    expect(typeof payload.serverTimestamp).toBe("string");
    expect((payload as unknown as Record<string, unknown>).timestamp).toBeUndefined();
    expect(payload.inputMessage).toBe("123456789");
    expect(payload.inputKey).toBe("Wghwi-lJZNNXLSfgDWw2oTpkc2bexPuioh-bgXlED9c=");
    expect(payload.options).toEqual({
      keySource: "directinput",
      kdfDerives: "key-iv",
      kdfEnvelope: "none",
      kdfHash: "sha256",
      kdfArgon2Variant: "argon2id",
      timestampFormat: "auto",
      nonce: "Rlg1V6oeciFjQh9YkvtKyw==",
    });

    // Verify key insertion order
    const keys = Object.keys(payload);
    expect(keys).toEqual([
      "tool",
      "mode",
      "algorithm",
      "result",
      "serverTimestamp",
      "inputMessage",
      "inputKey",
      "options",
    ]);

    // Must be cleanly JSON-serializable
    const jsonStr = JSON.stringify(payload, null, 2);
    const parsed = JSON.parse(jsonStr);
    expect(parsed.inputKey).toBe("Wghwi-lJZNNXLSfgDWw2oTpkc2bexPuioh-bgXlED9c=");
  });

  it("exports file input with only fileName and fileSize (no raw bytes)", () => {
    const sha256Manifest = TOOL_MANIFESTS.find((m) => m.id === "sha256")!;

    const spec: ToolSpecBase = {
      specVersion: 1,
      options: {},
    };

    const fakeFile = {
      name: "iso_archive.tar.gz",
      size: 104857600,
    } as unknown as File;

    const input: InputState = {
      mode: "file",
      text: "",
      textEncoding: "utf-8",
      file: fakeFile,
    };

    const result: ToolResult = {
      bytes: new Uint8Array([0xba, 0x78, 0x16, 0xbf]),
    };

    const payload = buildExportPayload(sha256Manifest, spec, input, result, "hex");

    expect(payload.algorithm).toBe("SHA-256");
    expect(payload.fileName).toBe("iso_archive.tar.gz");
    expect(payload.fileSize).toBe(104857600);
    expect(payload.inputMessage).toBeUndefined();
    expect(payload.result.output).toBe("ba7816bf");
  });

  it("adapts correctly across Asymmetric, MAC, KDF, Classical, and Encoding families", () => {
    // 1. MAC family (HMAC)
    const macManifest = TOOL_MANIFESTS.find((m) => m.id === "hmac")!;
    const macPayload = buildExportPayload(
      macManifest,
      { specVersion: 1, options: { key: "secret-key-123" } },
      { mode: "text", text: "authenticated message", textEncoding: "utf-8" },
      { bytes: new Uint8Array([0xaa, 0xbb, 0xcc]) },
      "hex",
    );
    expect(macPayload.mode).toBe("authenticate");
    expect(macPayload.inputKey).toBe("secret-key-123");
    expect(macPayload.inputMessage).toBe("authenticated message");
    expect(macPayload.result.output).toBe("aabbcc");

    // 2. KDF family (Argon2)
    const kdfManifest = TOOL_MANIFESTS.find((m) => m.id === "argon2")!;
    const kdfPayload = buildExportPayload(
      kdfManifest,
      {
        specVersion: 1,
        options: {
          password: "my-password",
          salt: "random-salt-16b",
          iterations: 3,
          memoryCost: 65536,
        },
      },
      { mode: "text", text: "", textEncoding: "utf-8" },
      {
        bytes: new Uint8Array([0x01, 0x02, 0x03]),
        fields: [{ label: "PHC String", value: "$argon2id$v=19$m=65536,t=3,p=4$..." }],
      },
      "hex",
    );
    expect(kdfPayload.mode).toBe("derive");
    expect(kdfPayload.inputKey).toBe("my-password");
    expect(kdfPayload.options?.salt).toBe("random-salt-16b");
    expect(kdfPayload.options?.iterations).toBe(3);
    expect(kdfPayload.result.phcString).toBe("$argon2id$v=19$m=65536,t=3,p=4$...");

    // 3. Classical family (Enigma)
    const enigmaManifest = TOOL_MANIFESTS.find((m) => m.id === "enigma")!;
    const enigmaPayload = buildExportPayload(
      enigmaManifest,
      { specVersion: 1, options: { rotors: "I II III", rings: "01 01 01" } },
      { mode: "text", text: "HELLOWORLD", textEncoding: "utf-8" },
      { text: "KFLMGOWRTY" },
      "utf-8",
    );
    expect(enigmaPayload.mode).toBe("encrypt");
    expect(enigmaPayload.options?.rotors).toBe("I II III");
    expect(enigmaPayload.result.output).toBe("KFLMGOWRTY");

    // 4. CRC family (CRC-8 / SMBus)
    const crc8Manifest = TOOL_MANIFESTS.find((m) => m.id === "crc8")!;
    const crc8Payload = buildExportPayload(
      crc8Manifest,
      { specVersion: 1, options: { model: "CRC-8/SMBUS" } },
      { mode: "text", text: "123456789", textEncoding: "utf-8" },
      { bytes: new Uint8Array([0xf4]) },
      "hex",
      [
        { label: "Model", value: "CRC-8/SMBUS" },
        { label: "Alias\n(Also known as)", value: "CRC-8, CRC-8/CCITT, SMBus" },
        { label: "Width", value: "8 bits" },
        { label: "Polynomial", value: "0x07" },
        { label: "Init", value: "0x00" },
        { label: "Reflect in / out", value: "false / false" },
        { label: "Final xor", value: "0x00" },
        { label: "Check value", value: "0xF4" },
        { label: "Residue", value: "0x00" },
      ],
    );
    expect(crc8Payload.algorithm).toBe("CRC-8");
    expect(crc8Payload.mode).toBe("hash");
    expect(crc8Payload.result.output).toBe("f4");
    expect(crc8Payload.info?.model).toBe("CRC-8/SMBUS");
    expect(crc8Payload.info?.alias).toBe("CRC-8, CRC-8/CCITT, SMBus");
    expect(crc8Payload.info?.width).toBe("8 bits");
    expect(crc8Payload.info?.polynomial).toBe("0x07");
    expect(crc8Payload.info?.init).toBe("0x00");
    expect(crc8Payload.info?.reflectInOut).toBe("false / false");
    expect(crc8Payload.info?.finalXor).toBe("0x00");
    expect(crc8Payload.info?.checkValue).toBe("0xF4");
    expect(crc8Payload.info?.residue).toBe("0x00");
  });
});
