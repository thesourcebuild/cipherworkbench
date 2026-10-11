import { describe, expect, it } from "vitest";
import {
  createBrowserFileSource,
  MAX_FILE_SOURCE_READ_BYTES,
} from "../apps/web/app/browser-file-source";

describe("browser ToolFileSource", () => {
  it("exposes metadata and exact random-access File.slice reads", async () => {
    const file = new File([Uint8Array.from([0, 1, 2, 3, 4, 5])], "artifact.bin", {
      type: "application/octet-stream",
      lastModified: 1234,
    });
    const source = createBrowserFileSource(file, 4);

    expect(source.metadata).toEqual({
      name: "artifact.bin",
      size: 6,
      mimeType: "application/octet-stream",
      lastModified: 1234,
    });
    expect(source.maxReadBytes).toBe(4);
    await expect(source.read(2, 3)).resolves.toEqual(Uint8Array.from([2, 3, 4]));
    await expect(source.read(6, 0)).resolves.toEqual(new Uint8Array());
  });

  it("rejects oversized, out-of-range, and fractional requests", async () => {
    const source = createBrowserFileSource(new File([new Uint8Array(8)], "bounded.bin"), 4);
    await expect(source.read(0, 5)).rejects.toThrow(/limited to 4 bytes/i);
    await expect(source.read(7, 2)).rejects.toThrow(/beyond the end/i);
    await expect(source.read(0.5, 1)).rejects.toThrow(/offset/i);
    expect(MAX_FILE_SOURCE_READ_BYTES).toBe(1024 * 1024);
  });
});
