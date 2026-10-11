import type { CipherDirection } from "./pure";
import { aesBlockCipher } from "./bindings";

const BMP_FILE_HEADER_BYTES = 14;
const BITMAP_INFO_HEADER_BYTES = 40;
const AES_BLOCK_BYTES = 16;

export interface BmpImageInfo {
  width: number;
  height: number;
  topDown: boolean;
  bitsPerPixel: 24 | 32;
  pixelOffset: number;
  pixelLength: number;
  rowStride: number;
}

export interface CipherImageResult {
  bytes: Uint8Array;
  info: BmpImageInfo;
  transformedBlocks: number;
  unchangedRemainderBytes: number;
}

function malformed(message: string): never {
  throw new Error(`Invalid BMP: ${message}`);
}

/** Strictly parses the BI_RGB BMP subset that remains displayable after a length-preserving transform. */
export function parseBmpImage(input: Uint8Array): BmpImageInfo {
  if (input[0] !== 0x42 || input[1] !== 0x4d) {
    throw new Error(
      "Unsupported image: expected an uncompressed 24-bit or 32-bit BMP file (BM signature). PNG and JPEG are not supported.",
    );
  }
  if (input.length < BMP_FILE_HEADER_BYTES + BITMAP_INFO_HEADER_BYTES) {
    malformed("the file is too short to contain BMP and BITMAPINFOHEADER headers.");
  }

  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const declaredFileSize = view.getUint32(2, true);
  if (declaredFileSize !== input.length) {
    malformed(
      `the header declares ${declaredFileSize} bytes but the file contains ${input.length}.`,
    );
  }

  const pixelOffset = view.getUint32(10, true);
  const dibSize = view.getUint32(14, true);
  if (dibSize < BITMAP_INFO_HEADER_BYTES) {
    throw new Error(
      `Unsupported BMP: DIB header size ${dibSize} is not a BITMAPINFOHEADER-compatible header.`,
    );
  }
  if (BMP_FILE_HEADER_BYTES + dibSize > input.length) {
    malformed("the DIB header extends beyond the end of the file.");
  }
  if (pixelOffset < BMP_FILE_HEADER_BYTES + dibSize || pixelOffset > input.length) {
    malformed(`pixel-data offset ${pixelOffset} overlaps the headers or lies beyond the file.`);
  }

  const width = view.getInt32(18, true);
  const signedHeight = view.getInt32(22, true);
  const planes = view.getUint16(26, true);
  const bitsPerPixel = view.getUint16(28, true);
  const compression = view.getUint32(30, true);
  const declaredImageSize = view.getUint32(34, true);

  if (width <= 0 || signedHeight === 0) {
    malformed(
      `dimensions must have a positive width and a non-zero height; found ${width} x ${signedHeight}.`,
    );
  }
  if (planes !== 1) malformed(`the planes field must be 1; found ${planes}.`);
  if (bitsPerPixel !== 24 && bitsPerPixel !== 32) {
    throw new Error(
      `Unsupported BMP: expected 24-bit or 32-bit pixels; found ${bitsPerPixel}-bit.`,
    );
  }
  if (compression !== 0) {
    throw new Error(`Unsupported BMP: compression must be BI_RGB (0); found ${compression}.`);
  }

  const height = Math.abs(signedHeight);
  const rowBits = width * bitsPerPixel;
  const rowStride = Math.floor((rowBits + 31) / 32) * 4;
  const pixelLength = rowStride * height;
  if (!Number.isSafeInteger(pixelLength))
    malformed("the dimensions overflow the BMP pixel-array size.");
  if (pixelOffset + pixelLength > input.length) {
    malformed(
      `the pixel array needs ${pixelLength} bytes at offset ${pixelOffset}, beyond the ${input.length}-byte file.`,
    );
  }
  if (declaredImageSize !== 0 && declaredImageSize !== pixelLength) {
    malformed(
      `the DIB header declares ${declaredImageSize} pixel bytes but the dimensions require ${pixelLength}.`,
    );
  }

  return {
    width,
    height,
    topDown: signedHeight < 0,
    bitsPerPixel,
    pixelOffset,
    pixelLength,
    rowStride,
  };
}

/** AES-ECB transforms whole pixel-data blocks and deliberately leaves the last short block unchanged. */
export function transformBmpAesEcb(
  input: Uint8Array,
  key: Uint8Array,
  direction: CipherDirection,
): CipherImageResult {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(
      `Cipher Image needs a 16, 24 or 32-byte AES key; this one is ${key.length}.`,
    );
  }

  const info = parseBmpImage(input);
  const output = input.slice();
  const cipher = aesBlockCipher(key);
  const transformedBlocks = Math.floor(info.pixelLength / AES_BLOCK_BYTES);
  const transformedLength = transformedBlocks * AES_BLOCK_BYTES;

  for (
    let relativeOffset = 0;
    relativeOffset < transformedLength;
    relativeOffset += AES_BLOCK_BYTES
  ) {
    const offset = info.pixelOffset + relativeOffset;
    const source = input.subarray(offset, offset + AES_BLOCK_BYTES);
    const target = output.subarray(offset, offset + AES_BLOCK_BYTES);
    if (direction === "encrypt") cipher.encryptBlock(source, target);
    else cipher.decryptBlock(source, target);
  }

  return {
    bytes: output,
    info,
    transformedBlocks,
    unchangedRemainderBytes: info.pixelLength - transformedLength,
  };
}
