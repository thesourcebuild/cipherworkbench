import type { ToolFileSource } from "@ocs/engine";
import {
  ascii,
  basename,
  checkedAdd,
  checkedMultiply,
  hex,
  johnName,
  readChunked,
  readExact,
  readUint32Be,
  readUint64Be,
  sourceName,
} from "./binary";

const V1_HEADER_SIZE = 1_276;
const V2_HEADER_SIZE = 76;
const V2_POINTER_SIZE = 20;
const V2_PASSWORD_HEADER_SIZE = 104;
const DATA_BLOCK_SIZE = 4_096;
const MAX_KEY_POINTERS = 4_096;
const MAX_KEY_BLOB_SIZE = 1_024;
const MAX_DATA_CHUNK_SIZE = 16 * 1024 * 1024;

function canonicalNames(source: ToolFileSource): { label: string; filename: string } {
  const name = sourceName(source);
  return { label: johnName(name), filename: johnName(basename(name)) };
}

async function extractV1(source: ToolFileSource): Promise<string> {
  if (source.metadata.size < V1_HEADER_SIZE) throw new Error("DMG v1 header is truncated.");
  const header = await readExact(
    source,
    source.metadata.size - V1_HEADER_SIZE,
    V1_HEADER_SIZE,
    "DMG v1 trailer header",
  );
  if (ascii(header.subarray(header.length - 8), "DMG v1 magic") !== "cdsaencr") {
    throw new Error("DMG v1 trailer magic is invalid.");
  }
  const iterations = readUint32Be(header, 48, "DMG v1 KDF iterations");
  const saltLength = readUint32Be(header, 52, "DMG v1 salt length");
  const aesKeyLength = readUint32Be(header, 136, "DMG v1 wrapped AES key length");
  const hmacKeyLength = readUint32Be(header, 436, "DMG v1 wrapped HMAC key length");
  if (iterations === 0) throw new Error("DMG v1 KDF iteration count must be non-zero.");
  if (saltLength > 48) throw new Error("DMG v1 salt length exceeds its 48-byte field.");
  if (aesKeyLength > 296) throw new Error("DMG v1 wrapped AES key length exceeds its field.");
  if (hmacKeyLength > 300) throw new Error("DMG v1 wrapped HMAC key length exceeds its field.");

  const salt = header.subarray(56, 56 + saltLength);
  const aesKey = header.subarray(140, 140 + aesKeyLength);
  const hmacKey = header.subarray(440, 440 + hmacKeyLength);
  const { label, filename } = canonicalNames(source);
  return `${label}:$dmg$1*${saltLength}*${hex(salt)}*${aesKeyLength}*${hex(aesKey)}*${hmacKeyLength}*${hex(hmacKey)}*${iterations}::::${filename}\n`;
}

async function extractV2(source: ToolFileSource): Promise<string> {
  const header = await readExact(source, 0, V2_HEADER_SIZE, "DMG v2 header");
  if (ascii(header.subarray(0, 8), "DMG v2 magic") !== "encrcdsa") {
    throw new Error("DMG v2 header magic is invalid.");
  }
  const version = readUint32Be(header, 8, "DMG v2 version");
  if (version !== 2) throw new Error(`Unsupported DMG v2 header version ${version}.`);
  const dataSize = readUint64Be(header, 56, "DMG v2 encrypted data size");
  const dataOffset = readUint64Be(header, 64, "DMG v2 encrypted data offset");
  const keyCount = readUint32Be(header, 72, "DMG v2 key header count");
  if (keyCount === 0 || keyCount > MAX_KEY_POINTERS) {
    throw new Error(`DMG v2 key header count ${keyCount} is unsupported.`);
  }
  checkedAdd(
    V2_HEADER_SIZE,
    checkedMultiply(keyCount, V2_POINTER_SIZE),
    "DMG key pointer table",
  );

  let passwordHeaderOffset: number | undefined;
  let declaredPasswordHeaderSize: number | undefined;
  for (let index = 0; index < keyCount; index++) {
    const pointerOffset = checkedAdd(
      V2_HEADER_SIZE,
      checkedMultiply(index, V2_POINTER_SIZE, "DMG key pointer offset"),
    );
    const pointer = await readExact(
      source,
      pointerOffset,
      V2_POINTER_SIZE,
      `DMG v2 key pointer ${index}`,
    );
    const type = readUint32Be(pointer, 0, `DMG v2 key pointer ${index} type`);
    if (type !== 1) continue;
    if (passwordHeaderOffset !== undefined) {
      throw new Error("DMG v2 images with multiple password key headers are unsupported.");
    }
    passwordHeaderOffset = readUint32Be(pointer, 8, "DMG v2 password header offset");
    declaredPasswordHeaderSize = readUint32Be(pointer, 16, "DMG v2 password header size");
  }
  if (passwordHeaderOffset === undefined || declaredPasswordHeaderSize === undefined) {
    throw new Error("DMG v2 image has no password key header.");
  }
  if (declaredPasswordHeaderSize < V2_PASSWORD_HEADER_SIZE) {
    throw new Error("DMG v2 password key header is shorter than its fixed fields.");
  }

  const passwordHeader = await readExact(
    source,
    passwordHeaderOffset,
    V2_PASSWORD_HEADER_SIZE,
    "DMG v2 password key header",
  );
  const iterations = readUint32Be(passwordHeader, 8, "DMG v2 KDF iterations");
  const saltLength = readUint32Be(passwordHeader, 12, "DMG v2 salt length");
  const ivLength = readUint32Be(passwordHeader, 48, "DMG v2 IV length");
  const keyBlobLength = readUint32Be(passwordHeader, 100, "DMG v2 encrypted key blob length");
  if (iterations === 0) throw new Error("DMG v2 KDF iteration count must be non-zero.");
  if (saltLength > 32) throw new Error("DMG v2 salt length exceeds its 32-byte field.");
  if (ivLength !== 32) throw new Error("DMG v2 IV length must be exactly 32 bytes.");
  if (keyBlobLength === 0 || keyBlobLength > MAX_KEY_BLOB_SIZE) {
    throw new Error(`DMG v2 encrypted key blob length ${keyBlobLength} is unsupported.`);
  }
  if (declaredPasswordHeaderSize < V2_PASSWORD_HEADER_SIZE + keyBlobLength) {
    throw new Error("DMG v2 password key header does not contain its declared key blob.");
  }
  const keyBlob = await readChunked(
    source,
    checkedAdd(passwordHeaderOffset, V2_PASSWORD_HEADER_SIZE),
    keyBlobLength,
    MAX_KEY_BLOB_SIZE,
    "DMG v2 encrypted key blob",
  );

  const sparseImage = sourceName(source).includes(".sparseimage");
  let chunkNumber: number;
  let lastChunkSize: number;
  if (sparseImage) {
    chunkNumber = 1;
    lastChunkSize = 8_192;
  } else {
    if (dataSize === 0) throw new Error("DMG v2 encrypted data size must be non-zero.");
    chunkNumber = Math.ceil(dataSize / DATA_BLOCK_SIZE) - 2;
    if (chunkNumber < 0)
      throw new Error("DMG v2 encrypted data is too short for canonical chunks.");
    lastChunkSize =
      dataSize - checkedMultiply(chunkNumber, DATA_BLOCK_SIZE, "DMG chunk offset");
  }
  if (lastChunkSize <= 0 || lastChunkSize > MAX_DATA_CHUNK_SIZE) {
    throw new Error(`DMG v2 canonical chunk size ${lastChunkSize} is unsupported.`);
  }
  const lastChunkOffset = checkedAdd(
    dataOffset,
    checkedMultiply(chunkNumber, DATA_BLOCK_SIZE, "DMG last chunk offset"),
  );
  const chunk1 = await readChunked(
    source,
    lastChunkOffset,
    lastChunkSize,
    MAX_DATA_CHUNK_SIZE,
    "DMG v2 last encrypted chunk",
  );
  const chunk2 = await readExact(
    source,
    dataOffset,
    DATA_BLOCK_SIZE,
    "DMG v2 first encrypted chunk",
  );
  const salt = passwordHeader.subarray(16, 16 + saltLength);
  const iv = passwordHeader.subarray(52, 84);
  const { label, filename } = canonicalNames(source);
  return `${label}:$dmg$2*${saltLength}*${hex(salt)}*32*${hex(iv)}*${keyBlobLength}*${hex(keyBlob)}*${chunkNumber}*${lastChunkSize}*${hex(chunk1)}*1*${hex(chunk2)}*${iterations}::::${filename}\n`;
}

/** Matches the current src/dmg2john.c file-image descriptors (bundles are not ToolFileSource files). */
export async function extractDmg(source: ToolFileSource): Promise<string> {
  if (source.metadata.size < 8) throw new Error("DMG file is truncated before its magic.");
  const leading = ascii(
    await readExact(source, 0, 8, "DMG leading magic"),
    "DMG leading magic",
  );
  if (leading === "encrcdsa") return extractV2(source);
  const trailing = ascii(
    await readExact(source, source.metadata.size - 8, 8, "DMG trailing magic"),
    "DMG trailing magic",
  );
  if (trailing === "cdsaencr") return extractV1(source);
  throw new Error("Not an encrypted DMG file: no supported v1 or v2 magic was found.");
}
