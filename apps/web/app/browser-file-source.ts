import type { ToolFileSource } from "@ocs/engine";

export const MAX_FILE_SOURCE_READ_BYTES = 1024 * 1024;

/** Build the same bounded File.slice adapter in the worker and main-thread fallback. */
export function createBrowserFileSource(
  file: File,
  maxReadBytes = MAX_FILE_SOURCE_READ_BYTES,
): ToolFileSource {
  if (!Number.isSafeInteger(maxReadBytes) || maxReadBytes <= 0) {
    throw new RangeError("maxReadBytes must be a positive safe integer.");
  }

  return {
    metadata: {
      name: file.name,
      size: file.size,
      ...(file.type ? { mimeType: file.type } : {}),
      ...(Number.isFinite(file.lastModified) ? { lastModified: file.lastModified } : {}),
    },
    maxReadBytes,
    async read(offset, length) {
      if (!Number.isSafeInteger(offset) || offset < 0) {
        throw new RangeError("File read offset must be a non-negative safe integer.");
      }
      if (!Number.isSafeInteger(length) || length < 0) {
        throw new RangeError("File read length must be a non-negative safe integer.");
      }
      if (length > maxReadBytes) {
        throw new RangeError(`File reads are limited to ${maxReadBytes} bytes per request.`);
      }
      if (offset > file.size || length > file.size - offset) {
        throw new RangeError("File read extends beyond the end of the source.");
      }

      const bytes = new Uint8Array(await file.slice(offset, offset + length).arrayBuffer());
      if (bytes.length !== length) throw new Error("The file source returned a short read.");
      return bytes;
    },
  };
}
