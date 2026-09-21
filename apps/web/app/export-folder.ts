import type { ToolManifest, ToolResult, ToolSpecBase } from "@ocs/engine";

export interface ExportableFile {
  name: string;
  content: string | Uint8Array;
  mimeType?: string;
}

// Pre-computed CRC32 lookup table for standard IEEE 802.3 CRC-32
const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let k = 0; k < 8; k++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  CRC_TABLE[i] = c >>> 0;
}

export function calcCrc32(data: Uint8Array): number {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ data[i]!) & 0xff]!;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function toDosDateTime(d: Date): { time: number; date: number } {
  const year = Math.max(1980, d.getFullYear());
  const month = d.getMonth() + 1;
  const day = d.getDate();
  const hours = d.getHours();
  const minutes = d.getMinutes();
  const seconds = Math.floor(d.getSeconds() / 2);

  const date = ((year - 1980) << 9) | (month << 5) | day;
  const time = (hours << 11) | (minutes << 5) | seconds;
  return { time, date };
}

/**
 * Creates a standard uncompressed PKZIP (method 0) binary archive from an array of files.
 * Zero external dependencies, 100% compliant with standard ZIP specifications.
 */
export function createZipArchive(files: readonly ExportableFile[]): Uint8Array {
  const encoder = new TextEncoder();
  const now = new Date();
  const { time: dosTime, date: dosDate } = toDosDateTime(now);

  interface PreparedEntry {
    nameBytes: Uint8Array;
    contentBytes: Uint8Array;
    crc: number;
    localHeaderOffset: number;
  }

  const prepared: PreparedEntry[] = files.map((f) => {
    const nameBytes = encoder.encode(f.name.replace(/\\/g, "/"));
    const contentBytes =
      typeof f.content === "string" ? encoder.encode(f.content) : f.content;
    const crc = calcCrc32(contentBytes);
    return {
      nameBytes,
      contentBytes,
      crc,
      localHeaderOffset: 0,
    };
  });

  // Calculate exact total size
  let localHeadersTotalSize = 0;
  for (const entry of prepared) {
    // 30 bytes header + name + content
    localHeadersTotalSize += 30 + entry.nameBytes.length + entry.contentBytes.length;
  }

  let centralDirTotalSize = 0;
  for (const entry of prepared) {
    // 46 bytes central header + name
    centralDirTotalSize += 46 + entry.nameBytes.length;
  }

  const eocdSize = 22;
  const totalArchiveSize = localHeadersTotalSize + centralDirTotalSize + eocdSize;

  const out = new Uint8Array(totalArchiveSize);
  const view = new DataView(out.buffer);

  let cursor = 0;

  // 1. Write Local File Headers + Content
  for (const entry of prepared) {
    entry.localHeaderOffset = cursor;

    // Signature 0x04034b50 (PK\x03\x04)
    view.setUint32(cursor, 0x04034b50, true);
    view.setUint16(cursor + 4, 20, true); // Version needed: 2.0
    view.setUint16(cursor + 6, 0x0800, true); // Flags: UTF-8 filename
    view.setUint16(cursor + 8, 0, true); // Compression: 0 (Stored)
    view.setUint16(cursor + 10, dosTime, true);
    view.setUint16(cursor + 12, dosDate, true);
    view.setUint32(cursor + 14, entry.crc, true);
    view.setUint32(cursor + 18, entry.contentBytes.length, true); // Compressed size
    view.setUint32(cursor + 22, entry.contentBytes.length, true); // Uncompressed size
    view.setUint16(cursor + 26, entry.nameBytes.length, true);
    view.setUint16(cursor + 28, 0, true); // Extra field length

    cursor += 30;
    out.set(entry.nameBytes, cursor);
    cursor += entry.nameBytes.length;

    out.set(entry.contentBytes, cursor);
    cursor += entry.contentBytes.length;
  }

  const centralDirStartOffset = cursor;

  // 2. Write Central Directory Headers
  for (const entry of prepared) {
    // Signature 0x02014b50 (PK\x01\x02)
    view.setUint32(cursor, 0x02014b50, true);
    view.setUint16(cursor + 4, 20, true); // Version made by: 2.0
    view.setUint16(cursor + 6, 20, true); // Version needed: 2.0
    view.setUint16(cursor + 8, 0x0800, true); // Flags: UTF-8
    view.setUint16(cursor + 10, 0, true); // Compression: 0
    view.setUint16(cursor + 12, dosTime, true);
    view.setUint16(cursor + 14, dosDate, true);
    view.setUint32(cursor + 16, entry.crc, true);
    view.setUint32(cursor + 20, entry.contentBytes.length, true);
    view.setUint32(cursor + 24, entry.contentBytes.length, true);
    view.setUint16(cursor + 28, entry.nameBytes.length, true);
    view.setUint16(cursor + 30, 0, true); // Extra field length
    view.setUint16(cursor + 32, 0, true); // Comment length
    view.setUint16(cursor + 34, 0, true); // Disk number start
    view.setUint16(cursor + 36, 0, true); // Internal attributes
    view.setUint32(cursor + 38, 0x81a40000, true); // External attributes (regular file 0644)
    view.setUint32(cursor + 42, entry.localHeaderOffset, true); // Offset of local header

    cursor += 46;
    out.set(entry.nameBytes, cursor);
    cursor += entry.nameBytes.length;
  }

  // 3. Write End of Central Directory (EOCD)
  view.setUint32(cursor, 0x06054b50, true); // Signature PK\x05\x06
  view.setUint16(cursor + 4, 0, true); // Disk number
  view.setUint16(cursor + 6, 0, true); // Start disk
  view.setUint16(cursor + 8, prepared.length, true); // Entries on this disk
  view.setUint16(cursor + 10, prepared.length, true); // Total entries
  view.setUint32(cursor + 12, centralDirTotalSize, true); // Central directory size
  view.setUint32(cursor + 16, centralDirStartOffset, true); // Central directory offset
  view.setUint16(cursor + 20, 0, true); // Comment length

  return out;
}

/**
 * Initiates a browser download of a generated ZIP archive.
 */
export function downloadZipArchive(
  zipFilename: string,
  files: readonly ExportableFile[],
): void {
  const zipBytes = createZipArchive(files);
  const blob = new Blob([zipBytes as unknown as BlobPart], { type: "application/zip" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = zipFilename.endsWith(".zip") ? zipFilename : `${zipFilename}.zip`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

/**
 * Exports all files into a directory:
 * - Attempts to use the browser/Electron File System Access API (`showDirectoryPicker`) to save directly into a folder.
 * - If unsupported or aborted, falls back to downloading a standard `.zip` archive containing the files.
 */
export async function exportFilesToFolder(
  folderName: string,
  files: readonly ExportableFile[],
): Promise<{ method: "folder" | "zip" | "cancelled"; count: number }> {
  if (files.length === 0) return { method: "cancelled", count: 0 };

  // 1. Try File System Access API if available in Chromium / Electron / Edge / Chrome
  if (typeof window !== "undefined" && "showDirectoryPicker" in window) {
    try {
      const picker = (window as unknown as {
        showDirectoryPicker: (opts?: { mode?: string; startIn?: string }) => Promise<FileSystemDirectoryHandle>;
      }).showDirectoryPicker;

      const dirHandle = await picker({ mode: "readwrite", startIn: "downloads" });

      for (const file of files) {
        const parts = file.name.replace(/\\/g, "/").split("/");
        let currentDir = dirHandle;
        for (let i = 0; i < parts.length - 1; i++) {
          const part = parts[i];
          if (part && part !== ".") {
            currentDir = await currentDir.getDirectoryHandle(part, { create: true });
          }
        }
        const fileName = parts[parts.length - 1]!;
        const fileHandle = await currentDir.getFileHandle(fileName, { create: true });
        const writable = await fileHandle.createWritable();
        const data =
          typeof file.content === "string"
            ? new TextEncoder().encode(file.content)
            : file.content;
        await writable.write(data as unknown as BufferSource);
        await writable.close();
      }

      return { method: "folder", count: files.length };
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") {
        return { method: "cancelled", count: 0 };
      }
      // If error or denied permission, fall through to ZIP download below
    }
  }

  // 2. Universal fallback: Download as ZIP
  downloadZipArchive(folderName, files);
  return { method: "zip", count: files.length };
}

/**
 * Collects all exportable files from the current tool result:
 * - Uses `result.files` if explicitly provided by the tool (e.g. certificates, mTLS suite).
 * - Or synthesizes sensible files from `result.text` and `result.bytes`.
 */
export function collectExportFiles(
  result: ToolResult | undefined,
  manifest: ToolManifest | undefined,
  _spec: ToolSpecBase | undefined,
): ExportableFile[] {
  if (!result || result.error) return [];

  if (result.files && result.files.length > 0) {
    return result.files.map((f) => ({
      name: f.name,
      content: f.content,
      mimeType: f.mimeType,
    }));
  }

  const files: ExportableFile[] = [];
  const baseName = manifest?.id ?? "result";

  if (result.text && result.bytes) {
    files.push({ name: `${baseName}.txt`, content: result.text, mimeType: "text/plain" });
    files.push({ name: `${baseName}.bin`, content: result.bytes, mimeType: "application/octet-stream" });
  } else if (result.text) {
    files.push({ name: `${baseName}.txt`, content: result.text, mimeType: "text/plain" });
  } else if (result.bytes) {
    files.push({ name: `${baseName}.bin`, content: result.bytes, mimeType: "application/octet-stream" });
  }

  return files;
}
