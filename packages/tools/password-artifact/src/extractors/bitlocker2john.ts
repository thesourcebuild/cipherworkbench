import type { ToolFileSource } from "@ocs/engine";
import {
  ascii,
  checkedAdd,
  hex,
  readChunked,
  readExact,
  readUint16Le,
  readUint32Le,
  readUint64Le,
} from "./binary";

const BITLOCKER_SIGNATURE = "-FVE-FS-";
const BITLOCKER_TO_GO_SIGNATURE = "MSWIN4.1";
const ITERATION_COUNT = 0x100000;
const MAX_METADATA_BYTES = 16 * 1024 * 1024;
const KNOWN_VOLUME_GUIDS = new Set([
  "4967d63b2e294ad88399f6a339e3d001",
  "92a84d3bdd804d0e9e4eb1e3284eaed8",
]);

interface MetadataEntry {
  entryType: number;
  valueType: number;
  data: Uint8Array;
}

function parseEntry(
  bytes: Uint8Array,
  offset: number,
  context: string,
): { entry: MetadataEntry; next: number } {
  if (bytes.length - offset < 8) throw new Error(`${context} entry header is truncated.`);
  const size = readUint16Le(bytes, offset, `${context} entry size`);
  if (size < 8) throw new Error(`${context} entry size ${size} is invalid.`);
  const next = checkedAdd(offset, size, `${context} entry end`);
  if (next > bytes.length) throw new Error(`${context} entry extends beyond its container.`);
  const entryType = readUint16Le(bytes, offset + 2, `${context} entry type`);
  const valueType = readUint16Le(bytes, offset + 4, `${context} value type`);
  const version = readUint16Le(bytes, offset + 6, `${context} entry version`);
  if (version !== 1) throw new Error(`Unsupported ${context} entry version ${version}.`);
  return {
    entry: { entryType, valueType, data: bytes.subarray(offset + 8, next) },
    next,
  };
}

function descriptorLines(vmk: Uint8Array): string[] {
  if (vmk.length < 28) throw new Error("BitLocker VMK entry is truncated.");
  const protection = readUint16Le(vmk, 26, "BitLocker VMK protection type");
  if (protection !== 0x2000 && protection !== 0x800) return [];

  let salt: Uint8Array | undefined;
  const lines: string[] = [];
  let offset = 28;
  while (offset < vmk.length) {
    const parsed = parseEntry(vmk, offset, "BitLocker VMK property");
    offset = parsed.next;
    if (parsed.entry.valueType === 3) {
      if (parsed.entry.data.length < 20)
        throw new Error("BitLocker stretch-key property is truncated.");
      salt = parsed.entry.data.subarray(4, 20);
      const nested = parseEntry(parsed.entry.data, 20, "BitLocker stretch key");
      if (nested.next !== parsed.entry.data.length || nested.entry.valueType !== 5) {
        throw new Error("BitLocker stretch-key property has an unsupported nested value.");
      }
    } else if (parsed.entry.valueType === 5) {
      if (!salt) throw new Error("BitLocker AES-CCM VMK appears before its stretch-key salt.");
      if (parsed.entry.data.length < 29) throw new Error("BitLocker AES-CCM VMK is truncated.");
      const nonce = parsed.entry.data.subarray(0, 12);
      const encrypted = parsed.entry.data.subarray(12);
      const versions = protection === 0x2000 ? [0, 1] : [2, 3];
      for (const version of versions) {
        lines.push(
          `$bitlocker$${version}$${salt.length}$${hex(salt)}$${ITERATION_COUNT}$${nonce.length}$${hex(nonce)}$${encrypted.length}$${hex(encrypted)}`,
        );
      }
    }
  }
  if (offset !== vmk.length)
    throw new Error("BitLocker VMK properties do not end on an entry boundary.");
  return lines;
}

function parseMetadata(block: Uint8Array): string[] {
  if (block.length < 112) throw new Error("BitLocker FVE metadata block is truncated.");
  const lines: string[] = [];
  let offset = 112;
  while (offset < block.length) {
    const parsed = parseEntry(block, offset, "BitLocker FVE metadata");
    offset = parsed.next;
    if (parsed.entry.valueType === 8 && parsed.entry.entryType === 2) {
      lines.push(...descriptorLines(parsed.entry.data));
    }
  }
  if (offset !== block.length)
    throw new Error("BitLocker metadata does not end on an entry boundary.");
  return lines;
}

function guidBytesToCanonicalHex(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new Error("BitLocker volume GUID is truncated.");
  return hex(
    Uint8Array.of(
      bytes[3]!,
      bytes[2]!,
      bytes[1]!,
      bytes[0]!,
      bytes[5]!,
      bytes[4]!,
      bytes[7]!,
      bytes[6]!,
      ...bytes.subarray(8),
    ),
  );
}

/** Matches run/bitlocker2john.py for password and recovery-password VMKs. */
export async function extractBitLocker(
  source: ToolFileSource,
  partitionOffset: number,
): Promise<string> {
  if (!Number.isSafeInteger(partitionOffset) || partitionOffset < 0) {
    throw new Error("BitLocker partition offset must be a non-negative safe integer.");
  }
  const signatureOffset = checkedAdd(partitionOffset, 3, "BitLocker signature offset");
  const signature = ascii(
    await readExact(source, signatureOffset, 8, "BitLocker filesystem signature"),
    "BitLocker filesystem signature",
  );
  if (signature !== BITLOCKER_SIGNATURE && signature !== BITLOCKER_TO_GO_SIGNATURE) {
    throw new Error("Not a BitLocker partition: the filesystem signature is missing.");
  }
  const sectorBytes = await readExact(
    source,
    checkedAdd(signatureOffset, 8),
    2,
    "BitLocker sector size",
  );
  const sectorSize = readUint16Le(sectorBytes, 0, "BitLocker sector size");
  if (sectorSize < 512 || sectorSize > 65_536 || (sectorSize & (sectorSize - 1)) !== 0) {
    throw new Error(`BitLocker sector size ${sectorSize} is invalid.`);
  }

  const guidOffset = checkedAdd(
    partitionOffset,
    signature === BITLOCKER_SIGNATURE ? 0xa0 : 0x1a8,
    "BitLocker GUID offset",
  );
  const guidAndOffsets = await readExact(
    source,
    guidOffset,
    40,
    "BitLocker volume GUID and metadata offsets",
  );
  const guid = guidBytesToCanonicalHex(guidAndOffsets.subarray(0, 16));
  if (!KNOWN_VOLUME_GUIDS.has(guid))
    throw new Error(`Unsupported BitLocker volume GUID ${guid}.`);
  const metadataRelativeOffset = readUint64Le(
    guidAndOffsets,
    16,
    "BitLocker first metadata offset",
  );
  const metadataOffset = checkedAdd(
    partitionOffset,
    metadataRelativeOffset,
    "BitLocker metadata offset",
  );
  const metadataHeader = await readExact(
    source,
    metadataOffset,
    112,
    "BitLocker FVE metadata header",
  );
  const metadataSize = readUint32Le(metadataHeader, 64, "BitLocker FVE metadata size");
  if (metadataSize < 112)
    throw new Error("BitLocker FVE metadata size is smaller than its header.");
  const metadata = await readChunked(
    source,
    metadataOffset,
    metadataSize,
    MAX_METADATA_BYTES,
    "BitLocker FVE metadata block",
  );
  const lines = parseMetadata(metadata);
  if (lines.length === 0) {
    throw new Error("BitLocker metadata has no password or recovery-password VMK descriptor.");
  }
  return `${lines.join("\n")}\n`;
}
