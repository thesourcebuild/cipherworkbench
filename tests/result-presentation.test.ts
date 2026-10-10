import { describe, expect, it } from "vitest";
import {
  JSON_EXPORT_MAX_RESULT_BYTES,
  RESULT_PREVIEW_BYTES,
  jsonExportAvailability,
  presentResult,
} from "../apps/web/app/result-presentation";

describe("large result presentation", () => {
  it("renders small byte results in full", () => {
    expect(presentResult({ bytes: new Uint8Array([0xde, 0xad]) }, "hex", "0x")).toEqual({
      value: "0xdead",
      truncated: false,
      totalBytes: 2,
      omittedBytes: 0,
    });
  });

  it("bounds large byte results with exact byte counts and head/tail data", () => {
    const bytes = Uint8Array.from({ length: RESULT_PREVIEW_BYTES + 17 }, (_, i) => i & 0xff);
    const shown = presentResult({ bytes }, "hex");

    expect(shown.truncated).toBe(true);
    expect(shown.totalBytes).toBe(bytes.length);
    expect(shown.omittedBytes).toBe(17);
    expect(shown.value).toContain("... 17 bytes omitted ...");
    expect(shown.value.startsWith("00010203")).toBe(true);
    expect(shown.value.endsWith("0c0d0e0f10")).toBe(true);
    expect(shown.value.length).toBeLessThan(RESULT_PREVIEW_BYTES * 3);
  });

  it("disables JSON before encoding oversized binary output", () => {
    const result = { bytes: new Uint8Array(JSON_EXPORT_MAX_RESULT_BYTES + 1) };
    expect(jsonExportAvailability(result)).toEqual({
      allowed: false,
      reason:
        "JSON is disabled for results over 1 MiB; use Export to save the exact output bytes",
    });
  });

  it("accounts for text input that the JSON payload would include", () => {
    expect(
      jsonExportAvailability(
        { bytes: new Uint8Array([1]) },
        {
          mode: "text",
          text: "x".repeat(JSON_EXPORT_MAX_RESULT_BYTES + 1),
          textEncoding: "utf-8",
        },
      ).allowed,
    ).toBe(false);
  });

  it("keeps exact binary output available independently from JSON", () => {
    const result = { bytes: new Uint8Array(JSON_EXPORT_MAX_RESULT_BYTES + 1) };
    expect(presentResult(result, "base64").truncated).toBe(true);
    expect(result.bytes).toHaveLength(JSON_EXPORT_MAX_RESULT_BYTES + 1);
  });

  it("accounts for expanded binary output encoding", () => {
    expect(
      jsonExportAvailability(
        { bytes: new Uint8Array(200 * 1024) },
        undefined,
        undefined,
        undefined,
        "binary",
      ).allowed,
    ).toBe(false);
  });

  it("applies the JSON limit to output and metadata together", () => {
    expect(
      jsonExportAvailability({
        bytes: new Uint8Array(500 * 1024),
        fields: [{ label: "Metadata", value: "x".repeat(30_000) }],
      }).allowed,
    ).toBe(false);
  });
});
