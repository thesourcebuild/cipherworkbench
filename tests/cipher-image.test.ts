import { describe, expect, it } from "vitest";
import { encodeHex } from "@ocs/engine";
import {
  cipherToolDefinition,
  parseBmpImage,
  transformBmpAesEcb,
} from "@ocs/cipher/definition";
import { collectExportFiles } from "../apps/web/app/export-folder";
import { createBmpObjectUrl } from "../apps/web/app/cipher-image-object-url";

const fromHex = (hex: string): Uint8Array =>
  new Uint8Array(hex.match(/../g)?.map((byte) => Number.parseInt(byte, 16)) ?? []);

interface FixtureOptions {
  bitsPerPixel: 24 | 32;
  width: number;
  height?: number;
  pixelOffset?: number;
  pixels?: Uint8Array;
  trailer?: Uint8Array;
}

/** Authoritative tiny BI_RGB fixture builder: every header field follows the BMP file format. */
function bmpFixture({
  bitsPerPixel,
  width,
  height = 1,
  pixelOffset = 70,
  pixels,
  trailer = new Uint8Array(0),
}: FixtureOptions): Uint8Array {
  const rowStride = Math.floor((width * bitsPerPixel + 31) / 32) * 4;
  const pixelLength = rowStride * Math.abs(height);
  const pixelBytes = pixels ?? Uint8Array.from({ length: pixelLength }, (_, i) => i);
  if (pixelBytes.length !== pixelLength)
    throw new Error("Fixture pixels do not match dimensions");

  const bytes = new Uint8Array(pixelOffset + pixelLength + trailer.length);
  const view = new DataView(bytes.buffer);
  bytes[0] = 0x42;
  bytes[1] = 0x4d;
  view.setUint32(2, bytes.length, true);
  view.setUint32(10, pixelOffset, true);
  view.setUint32(14, 40, true);
  view.setInt32(18, width, true);
  view.setInt32(22, height, true);
  view.setUint16(26, 1, true);
  view.setUint16(28, bitsPerPixel, true);
  view.setUint32(30, 0, true);
  view.setUint32(34, pixelLength, true);
  for (let i = 54; i < pixelOffset; i++) bytes[i] = 0xa0 + (i - 54);
  bytes.set(pixelBytes, pixelOffset);
  bytes.set(trailer, pixelOffset + pixelLength);
  return bytes;
}

const PLAINTEXT_BLOCK = fromHex("00112233445566778899aabbccddeeff");

describe("Cipher Image BMP AES-ECB transform", () => {
  it.each([
    ["AES-128", "000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"],
    [
      "AES-192",
      "000102030405060708090a0b0c0d0e0f1011121314151617",
      "dda97ca4864cdfe06eaf70a0ec0d7191",
    ],
    [
      "AES-256",
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "8ea2b7ca516745bfeafc49904b496089",
    ],
  ])("matches the FIPS-197 %s block vector inside pixel data", (_name, keyHex, expected) => {
    const bmp = bmpFixture({ bitsPerPixel: 24, width: 5, pixels: PLAINTEXT_BLOCK });
    const result = transformBmpAesEcb(bmp, fromHex(keyHex), "encrypt");
    expect(encodeHex(result.bytes.subarray(70, 86)).toLowerCase()).toBe(expected);
    expect(result.transformedBlocks).toBe(1);
    expect(result.unchangedRemainderBytes).toBe(0);
  });

  it.each([
    [24 as const, 6],
    [32 as const, 5],
  ])("round-trips %i-bit BMPs and leaves the final partial block unchanged", (bits, width) => {
    const trailer = fromHex("deadbeef");
    const bmp = bmpFixture({ bitsPerPixel: bits, width, trailer });
    const key = fromHex("000102030405060708090a0b0c0d0e0f");
    const encrypted = transformBmpAesEcb(bmp, key, "encrypt");
    const decrypted = transformBmpAesEcb(encrypted.bytes, key, "decrypt");
    const tailStart = encrypted.info.pixelOffset + 16;
    const pixelEnd = encrypted.info.pixelOffset + encrypted.info.pixelLength;

    expect(encrypted.bytes).toHaveLength(bmp.length);
    expect(encrypted.bytes.subarray(0, encrypted.info.pixelOffset)).toEqual(
      bmp.subarray(0, encrypted.info.pixelOffset),
    );
    expect(encrypted.bytes.subarray(tailStart, pixelEnd)).toEqual(
      bmp.subarray(tailStart, pixelEnd),
    );
    expect(encrypted.bytes.subarray(pixelEnd)).toEqual(trailer);
    expect(encrypted.unchangedRemainderBytes).toBe(4);
    expect(decrypted.bytes).toEqual(bmp);
  });

  it("preserves a top-down bitmap's headers and pixel-data offset", () => {
    const bmp = bmpFixture({ bitsPerPixel: 24, width: 5, height: -2, pixelOffset: 86 });
    const info = parseBmpImage(bmp);
    expect(info).toMatchObject({ width: 5, height: 2, topDown: true, pixelOffset: 86 });
    const encrypted = transformBmpAesEcb(bmp, new Uint8Array(16), "encrypt");
    expect(encrypted.bytes.subarray(0, 86)).toEqual(bmp.subarray(0, 86));
  });

  it.each([
    ["PNG", Uint8Array.from([0x89, 0x50, 0x4e, 0x47])],
    ["JPEG", Uint8Array.from([0xff, 0xd8, 0xff, 0xe0])],
  ])("rejects %s input explicitly", (_name, signature) => {
    const bytes = new Uint8Array(54);
    bytes.set(signature);
    expect(() => parseBmpImage(bytes)).toThrow(/PNG and JPEG are not supported/);
  });

  it("strictly rejects compressed, unsupported and malformed BMP headers", () => {
    const valid = bmpFixture({ bitsPerPixel: 24, width: 6 });
    const mutate = (change: (view: DataView, bytes: Uint8Array) => void) => {
      const bytes = valid.slice();
      change(new DataView(bytes.buffer), bytes);
      return bytes;
    };

    expect(() => parseBmpImage(mutate((view) => view.setUint32(30, 1, true)))).toThrow(
      /compression must be BI_RGB/,
    );
    expect(() => parseBmpImage(mutate((view) => view.setUint16(28, 8, true)))).toThrow(
      /24-bit or 32-bit/,
    );
    expect(() => parseBmpImage(mutate((view) => view.setUint16(26, 2, true)))).toThrow(
      /planes field must be 1/,
    );
    expect(() => parseBmpImage(mutate((view) => view.setUint32(10, 20, true)))).toThrow(
      /pixel-data offset/,
    );
    expect(() => parseBmpImage(mutate((view) => view.setUint32(34, 19, true)))).toThrow(
      /dimensions require 20/,
    );
    expect(() => parseBmpImage(mutate((view) => view.setUint32(2, 1, true)))).toThrow(
      /declares 1 bytes/,
    );
    const truncated = valid.slice(0, valid.length - 1);
    new DataView(truncated.buffer).setUint32(2, truncated.length, true);
    expect(() => parseBmpImage(truncated)).toThrow(/pixel array needs/);
  });
});

describe("Cipher Image tool presentation contracts", () => {
  it("returns an exportable BMP with educational metadata", async () => {
    const tool = cipherToolDefinition("cipher-image");
    const spec = tool.createSpec();
    spec.options = {
      direction: "encrypt",
      key: "000102030405060708090a0b0c0d0e0f",
      keyEncoding: "hex",
    };
    const result = await tool.compute(spec, bmpFixture({ bitsPerPixel: 24, width: 6 }));

    expect(result.error).toBeUndefined();
    expect(result.mimeType).toBe("image/bmp");
    expect(result.suggestedFilename).toBe("cipher-image-encrypted.bmp");
    expect(result.fields?.find((field) => field.label === "Unchanged remainder")?.value).toBe(
      "4 bytes",
    );
    expect(result.working).toMatch(/pattern|repeated|silhouette/i);
    expect(collectExportFiles(result, tool, spec)).toEqual([
      {
        name: "cipher-image-encrypted.bmp",
        content: result.bytes,
        mimeType: "image/bmp",
      },
    ]);
    expect(tool.security).toBe("broken");
    expect(tool.sourcePolicy?.accept).toContain(".bmp");
  });

  it("creates image/bmp object URLs and revokes each URL exactly once", async () => {
    const created: Blob[] = [];
    const revoked: string[] = [];
    const resource = createBmpObjectUrl(new Uint8Array([0x42, 0x4d]), {
      createObjectURL(blob) {
        created.push(blob);
        return "blob:cipher-image-preview";
      },
      revokeObjectURL(url) {
        revoked.push(url);
      },
    });

    expect(resource.url).toBe("blob:cipher-image-preview");
    expect(created).toHaveLength(1);
    expect(created[0]?.type).toBe("image/bmp");
    expect(new Uint8Array(await created[0]!.arrayBuffer())).toEqual(
      new Uint8Array([0x42, 0x4d]),
    );
    resource.revoke();
    resource.revoke();
    expect(revoked).toEqual(["blob:cipher-image-preview"]);
  });
});
