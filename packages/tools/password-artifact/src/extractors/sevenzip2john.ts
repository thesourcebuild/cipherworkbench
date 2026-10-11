import type { ToolFileSource } from "@ocs/engine";
import {
  basename,
  checkedAdd,
  hex,
  johnName,
  readChunked,
  readExact,
  readUint32Le,
  readUint64Le,
  sourceName,
} from "./binary";

const MAGIC = Uint8Array.of(0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c);
const AES = "06f10701";
const MAX_HEADER = 16 * 1024 * 1024;
const MAX_DATA = 64 * 1024 * 1024;

interface Coder {
  id: string;
  attributes: Uint8Array;
  inputs: number;
  outputs: number;
}

interface Folder {
  coders: Coder[];
  mainOutput: number;
  outputCount: number;
}

interface Streams {
  packPosition: number;
  packSizes: number[];
  folder: Folder;
  unpackSizes: number[];
  crc?: number;
  firstSubstreamSize?: number;
}

class SevenReader {
  position = 0;
  constructor(readonly bytes: Uint8Array) {}
  get remaining(): number {
    return this.bytes.length - this.position;
  }
  u8(label: string): number {
    if (this.position >= this.bytes.length) throw new Error(`7z ${label} is truncated.`);
    return this.bytes[this.position++]!;
  }
  take(length: number, label: string): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 0 || length > this.remaining)
      throw new Error(`7z ${label} is truncated or invalid.`);
    const value = this.bytes.subarray(this.position, this.position + length);
    this.position += length;
    return value;
  }
  number(label: string): number {
    const first = this.u8(label);
    let mask = 0x80;
    let value = 0;
    for (let index = 0; index < 8; index++) {
      if ((first & mask) === 0) {
        value += (first & (mask - 1)) * 2 ** (index * 8);
        if (!Number.isSafeInteger(value))
          throw new Error(`7z ${label} exceeds the safe integer range.`);
        return value;
      }
      value += this.u8(label) * 2 ** (index * 8);
      mask >>>= 1;
    }
    if (!Number.isSafeInteger(value))
      throw new Error(`7z ${label} exceeds the safe integer range.`);
    return value;
  }
}

function booleans(reader: SevenReader, count: number, allDefined: boolean): boolean[] {
  if (allDefined && reader.u8("defined-vector marker") === 1)
    return Array(count).fill(true) as boolean[];
  const output: boolean[] = [];
  let bits = 0;
  let mask = 0;
  for (let index = 0; index < count; index++) {
    if (mask === 0) {
      bits = reader.u8("boolean vector");
      mask = 0x80;
    }
    output.push((bits & mask) !== 0);
    mask >>>= 1;
  }
  return output;
}

function digests(reader: SevenReader, count: number): Array<number | undefined> {
  const defined = booleans(reader, count, true);
  return defined.map((present) =>
    present ? readUint32Le(reader.take(4, "CRC"), 0, "7z CRC") : undefined,
  );
}

function skipProperty(reader: SevenReader): void {
  reader.take(reader.number("property size"), "property");
}

function waitFor(reader: SevenReader, wanted: number, label: string): boolean {
  while (reader.remaining > 0) {
    const id = reader.number("property ID");
    if (id === wanted) return true;
    if (id === 0) return false;
    skipProperty(reader);
  }
  throw new Error(`7z ${label} is truncated.`);
}

function parsePackInfo(reader: SevenReader): { position: number; sizes: number[] } {
  const position = reader.number("pack position");
  const count = reader.number("pack-stream count");
  if (count !== 1)
    throw new Error(`7z archives with ${count} packed streams are unsupported safely.`);
  if (!waitFor(reader, 9, "pack sizes")) throw new Error("7z pack-size property is missing.");
  const sizes = [reader.number("pack size")];
  while (true) {
    const id = reader.number("pack-info property");
    if (id === 0) break;
    if (id === 10) digests(reader, count);
    else skipProperty(reader);
  }
  return { position, sizes };
}

function parseFolder(reader: SevenReader): Folder {
  const count = reader.number("coder count");
  if (count === 0 || count > 16) throw new Error(`7z coder count ${count} is unsupported.`);
  const coders: Coder[] = [];
  let totalInputs = 0;
  let totalOutputs = 0;
  for (let index = 0; index < count; index++) {
    const flags = reader.u8("coder flags");
    if ((flags & 0xc0) !== 0)
      throw new Error("7z coder uses unsupported alternative methods or reserved flags.");
    const idLength = flags & 0x0f;
    if (idLength === 0 || idLength > 8) throw new Error("7z coder ID length is invalid.");
    const id = hex(reader.take(idLength, "coder ID"));
    const inputs = (flags & 0x10) !== 0 ? reader.number("coder input count") : 1;
    const outputs = (flags & 0x10) !== 0 ? reader.number("coder output count") : 1;
    const attributes =
      (flags & 0x20) !== 0
        ? reader.take(reader.number("coder property size"), "coder properties")
        : new Uint8Array();
    coders.push({ id, attributes, inputs, outputs });
    totalInputs += inputs;
    totalOutputs += outputs;
  }
  if (totalInputs > 32 || totalOutputs > 32 || totalOutputs === 0)
    throw new Error("7z folder stream topology is unsupported.");
  const usedOutputs = new Set<number>();
  const usedInputs = new Set<number>();
  const bindPairs = totalOutputs - 1;
  for (let index = 0; index < bindPairs; index++) {
    const input = reader.number("folder bind input");
    const output = reader.number("folder bind output");
    if (
      input >= totalInputs ||
      output >= totalOutputs ||
      usedInputs.has(input) ||
      usedOutputs.has(output)
    )
      throw new Error("7z folder bind pairs are corrupt.");
    usedInputs.add(input);
    usedOutputs.add(output);
  }
  const packedStreams = totalInputs - bindPairs;
  if (packedStreams !== 1)
    throw new Error("7z folders with multiple packed streams are unsupported safely.");
  const mainOutput = Array.from({ length: totalOutputs }, (_, index) => index).find(
    (index) => !usedOutputs.has(index),
  );
  if (mainOutput === undefined) throw new Error("7z folder has no main output stream.");
  return { coders, mainOutput, outputCount: totalOutputs };
}

function parseUnpackInfo(reader: SevenReader): {
  folder: Folder;
  sizes: number[];
  crc?: number;
} {
  if (!waitFor(reader, 11, "folder property"))
    throw new Error("7z folder property is missing.");
  const count = reader.number("folder count");
  if (count !== 1) throw new Error(`7z archives with ${count} folders are unsupported safely.`);
  if (reader.u8("external-folder marker") !== 0)
    throw new Error("7z external folder metadata is unsupported.");
  const folder = parseFolder(reader);
  if (!waitFor(reader, 12, "unpack sizes"))
    throw new Error("7z unpack-size property is missing.");
  const sizes = Array.from({ length: folder.outputCount }, () => reader.number("unpack size"));
  let crc: number | undefined;
  while (true) {
    const id = reader.number("unpack-info property");
    if (id === 0) break;
    if (id === 10) crc = digests(reader, 1)[0];
    else skipProperty(reader);
  }
  return { folder, sizes, crc };
}

function parseSubstreams(
  reader: SevenReader,
  folderSize: number,
  folderCrc?: number,
): { firstSize: number; crc?: number } {
  let count = 1;
  let sizes: number[] = [];
  let id = reader.number("substreams property");
  while (id !== 0) {
    if (id === 13) {
      count = reader.number("substream count");
      if (count === 0 || count > 100_000) throw new Error("7z substream count is invalid.");
    } else if (id === 9) {
      let sum = 0;
      sizes = [];
      for (let index = 1; index < count; index++) {
        const size = reader.number("substream size");
        sizes.push(size);
        sum = checkedAdd(sum, size, "7z substream sizes");
      }
      if (sum > folderSize) throw new Error("7z substream sizes exceed their folder size.");
      sizes.push(folderSize - sum);
    } else if (id === 10) {
      const values =
        folderCrc !== undefined && count === 1 ? [folderCrc] : digests(reader, count);
      return { firstSize: sizes[0] ?? folderSize, crc: values[0] };
    } else skipProperty(reader);
    id = reader.number("substreams property");
  }
  return { firstSize: sizes[0] ?? folderSize, crc: folderCrc };
}

function parseStreams(reader: SevenReader): Streams {
  let id = reader.number("streams-info property");
  if (id !== 6) throw new Error("7z streams info has no PackInfo section.");
  const pack = parsePackInfo(reader);
  id = reader.number("streams-info property");
  if (id !== 7) throw new Error("7z streams info has no UnpackInfo section.");
  const unpack = parseUnpackInfo(reader);
  id = reader.number("streams-info property");
  let substream: { firstSize: number; crc?: number } | undefined;
  if (id === 8) {
    substream = parseSubstreams(reader, unpack.sizes[unpack.folder.mainOutput]!, unpack.crc);
    id = 0;
  }
  if (id !== 0) throw new Error(`Unsupported 7z streams-info property ${id}.`);
  return {
    packPosition: pack.position,
    packSizes: pack.sizes,
    folder: unpack.folder,
    unpackSizes: unpack.sizes,
    crc: substream?.crc ?? unpack.crc,
    firstSubstreamSize: substream?.firstSize ?? unpack.sizes[unpack.folder.mainOutput],
  };
}

function aesProperties(attributes: Uint8Array): {
  power: number;
  salt: Uint8Array;
  ivLength: number;
  iv: Uint8Array;
} {
  if (attributes.length < 1) throw new Error("7z AES coder properties are missing.");
  const first = attributes[0]!;
  const power = first & 0x3f;
  let saltLength = 0;
  let ivLength = 16;
  let offset = 1;
  if ((first & 0xc0) !== 0) {
    if (attributes.length < 2) throw new Error("7z AES length properties are truncated.");
    const second = attributes[1]!;
    saltLength = ((first >>> 7) & 1) + (second >>> 4);
    ivLength = ((first >>> 6) & 1) + (second & 0x0f);
    offset = 2;
  }
  if (saltLength > 16 || ivLength > 16 || offset + saltLength + ivLength > attributes.length) {
    throw new Error("7z AES salt or IV properties are invalid.");
  }
  const salt = attributes.slice(offset, offset + saltLength);
  const iv = new Uint8Array(16);
  iv.set(attributes.subarray(offset + saltLength, offset + saltLength + ivLength));
  return { power, salt, ivLength, iv };
}

function coderType(coder: Coder): { type: number; preprocessor: boolean } | undefined {
  const values: Record<string, { type: number; preprocessor: boolean }> = {
    "030101": { type: 1, preprocessor: false },
    "21": { type: 2, preprocessor: false },
    "040202": { type: 6, preprocessor: false },
    "040108": { type: 7, preprocessor: false },
    "03030103": { type: 1, preprocessor: true },
    "0303011b": { type: 2, preprocessor: true },
    "03030205": { type: 3, preprocessor: true },
    "03030401": { type: 4, preprocessor: true },
    "03030501": { type: 5, preprocessor: true },
    "03030701": { type: 6, preprocessor: true },
    "03030805": { type: 7, preprocessor: true },
    "03": { type: 9, preprocessor: true },
  };
  if (coder.id === "00") return undefined;
  return values[coder.id];
}

function additionalCoder(
  coders: Coder[],
  aesIndex: number,
): { type: number; attributes: string } {
  const others = coders.filter((_, index) => index !== aesIndex && coders[index]!.id !== "00");
  if (others.length === 0) return { type: 0, attributes: "" };
  if (others.length > 1)
    throw new Error(
      "7z folders with multiple compression/filter coders are unsupported by John safely.",
    );
  const coder = others[0]!;
  const mapped = coderType(coder);
  if (!mapped) throw new Error(`Unsupported 7z coder 0x${coder.id}.`);
  return {
    type: mapped.preprocessor ? mapped.type << 4 : mapped.type,
    attributes: hex(coder.attributes),
  };
}

/** Canonical 7z2john descriptor for one-stream AES folders, including encrypted headers. */
export async function extractSevenZip(source: ToolFileSource): Promise<string> {
  if (source.metadata.size < 32) throw new Error("7z signature header is truncated.");
  const header = await readExact(source, 0, 32, "7z signature header");
  if (!MAGIC.every((byte, index) => header[index] === byte))
    throw new Error("7z signature is invalid; SFX and split archives are unsupported.");
  if (header[6] !== 0) throw new Error(`Unsupported 7z major version ${header[6]}.`);
  const nextOffset = readUint64Le(header, 12, "7z next-header offset");
  const nextSize = readUint64Le(header, 20, "7z next-header size");
  if (nextSize === 0 || nextSize > MAX_HEADER)
    throw new Error(`7z next-header size ${nextSize} is unsupported.`);
  const nextPosition = checkedAdd(32, nextOffset, "7z next-header position");
  const next = await readChunked(source, nextPosition, nextSize, MAX_HEADER, "7z next header");
  const reader = new SevenReader(next);
  const headerType = reader.number("next-header type");
  let streams: Streams;
  if (headerType === 0x17) streams = parseStreams(reader);
  else if (headerType === 1) {
    const section = reader.number("header section");
    if (section !== 4)
      throw new Error("7z raw header has no supported MainStreamsInfo section.");
    streams = parseStreams(reader);
  } else throw new Error(`Unsupported 7z next-header type 0x${headerType.toString(16)}.`);
  const aesIndex = streams.folder.coders.findIndex((coder) => coder.id === AES);
  if (aesIndex < 0) throw new Error("7z archive contains no AES coder in its selected folder.");
  if (aesIndex !== 0)
    throw new Error("7z AES must be the first coder in the selected one-stream folder.");
  if (streams.crc === undefined)
    throw new Error("7z encrypted folder has no CRC required by John.");
  const aes = aesProperties(streams.folder.coders[aesIndex]!.attributes);
  const extra = additionalCoder(streams.folder.coders, aesIndex);
  const dataLength = streams.packSizes[0]!;
  if (dataLength > MAX_DATA)
    throw new Error(
      `7z encrypted data exceeds the ${MAX_DATA}-byte browser-safe inline limit.`,
    );
  const dataOffset = checkedAdd(32, streams.packPosition, "7z packed-data offset");
  const data = await readChunked(source, dataOffset, dataLength, MAX_DATA, "7z encrypted data");
  // Upstream indexes the AES pack stream here, not the folder's final output.
  const unpackSize = streams.unpackSizes[0]!;
  let descriptor = `${johnName(basename(sourceName(source)))}:$7z$${extra.type}$${aes.power}$${aes.salt.length}$${hex(aes.salt)}$${aes.ivLength}$${hex(aes.iv)}$${streams.crc}$${dataLength}$${unpackSize}$${hex(data)}`;
  if (extra.type !== 0)
    descriptor += `$${streams.firstSubstreamSize ?? unpackSize}$${extra.attributes}`;
  return `${descriptor}\n`;
}
