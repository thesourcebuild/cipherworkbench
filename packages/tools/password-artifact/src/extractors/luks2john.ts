import type { ToolFileSource } from "@ocs/engine";
import {
  base64,
  checkedMultiply,
  hex,
  nulTerminatedAscii,
  readChunked,
  readExact,
  readUint32Be,
} from "./binary";

const HEADER_SIZE = 592;
const SLOT_OFFSET = 208;
const SLOT_SIZE = 48;
const SLOT_COUNT = 8;
const ACTIVE_SLOT = 0x00ac71f3;
const SECTOR_SIZE = 512;
const MAX_KEY_MATERIAL_BYTES = 16 * 1024 * 1024;

interface LuksSlot {
  iterations: number;
  keyMaterialOffset: number;
  stripes: number;
}

/** Matches run/luks2john.py's supported LUKS1 profile. */
export async function extractLuks(source: ToolFileSource): Promise<string> {
  const header = await readExact(source, 0, HEADER_SIZE, "LUKS1 header");
  if (
    header[0] !== 0x4c ||
    header[1] !== 0x55 ||
    header[2] !== 0x4b ||
    header[3] !== 0x53 ||
    header[4] !== 0xba ||
    header[5] !== 0xbe
  ) {
    throw new Error("Not a LUKS volume: the LUKS magic is missing.");
  }
  const version = (header[6]! << 8) | header[7]!;
  if (version !== 1)
    throw new Error(`Unsupported LUKS version ${version}; only LUKS1 is supported.`);

  const cipher = nulTerminatedAscii(header.subarray(8, 40), "LUKS cipher name");
  const mode = nulTerminatedAscii(header.subarray(40, 72), "LUKS cipher mode");
  const hashSpec = nulTerminatedAscii(header.subarray(72, 104), "LUKS hash specification");
  if (cipher !== "aes")
    throw new Error(`Unsupported LUKS1 cipher ${cipher}; only AES is supported.`);
  if (mode !== "cbc-essiv:sha256") {
    throw new Error(
      `Unsupported LUKS1 cipher mode ${mode}; only cbc-essiv:sha256 is supported.`,
    );
  }
  if (hashSpec !== "sha1")
    throw new Error(`Unsupported LUKS1 hash ${hashSpec}; only SHA-1 is supported.`);

  const keyBytes = readUint32Be(header, 108, "LUKS key byte count");
  if (keyBytes === 0) throw new Error("LUKS key byte count must be non-zero.");
  let best: LuksSlot | undefined;
  for (let index = 0; index < SLOT_COUNT; index++) {
    const offset = SLOT_OFFSET + index * SLOT_SIZE;
    const active = readUint32Be(header, offset, `LUKS keyslot ${index} active flag`);
    const iterations = readUint32Be(header, offset + 4, `LUKS keyslot ${index} iterations`);
    const keyMaterialOffset = readUint32Be(
      header,
      offset + 40,
      `LUKS keyslot ${index} material offset`,
    );
    const stripes = readUint32Be(header, offset + 44, `LUKS keyslot ${index} stripe count`);
    if (active === ACTIVE_SLOT && iterations > 1 && (!best || iterations < best.iterations)) {
      if (keyMaterialOffset === 0 || stripes === 0) {
        throw new Error(`LUKS keyslot ${index} has an invalid zero offset or stripe count.`);
      }
      best = { iterations, keyMaterialOffset, stripes };
    }
  }
  if (!best) throw new Error("LUKS1 volume has no supported active password keyslot.");

  const rawSize = checkedMultiply(keyBytes, best.stripes, "LUKS anti-forensic material size");
  const sectors = Math.ceil(rawSize / SECTOR_SIZE);
  const materialSize = checkedMultiply(sectors, SECTOR_SIZE, "LUKS anti-forensic sector size");
  const materialOffset = checkedMultiply(
    best.keyMaterialOffset,
    SECTOR_SIZE,
    "LUKS key material offset",
  );
  const material = await readChunked(
    source,
    materialOffset,
    materialSize,
    MAX_KEY_MATERIAL_BYTES,
    "LUKS key material",
  );
  const masterKeyDigest = header.subarray(112, 132);
  return `$luks$1$${HEADER_SIZE}$${hex(header)}$${materialSize}$${base64(material)}$${hex(masterKeyDigest)}\n`;
}
