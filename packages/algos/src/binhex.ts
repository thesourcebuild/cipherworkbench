/**
 * BinHex 4.0:
 * Classic Macintosh 6-bit RLE encoded binary format with CRC-16 (poly 0x1021).
 */

const BINHEX_CHARS =
  "!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

const BINHEX_REV = new Map<string, number>();
for (let i = 0; i < BINHEX_CHARS.length; i++) {
  BINHEX_REV.set(BINHEX_CHARS[i]!, i);
}

function binhexCrc(data: Uint8Array): number {
  let crc = 0;
  for (let i = 0; i < data.length; i++) {
    crc ^= (data[i]! << 8);
    for (let j = 0; j < 8; j++) {
      if (crc & 0x8000) {
        crc = ((crc << 1) ^ 0x1021) & 0xffff;
      } else {
        crc = (crc << 1) & 0xffff;
      }
    }
  }
  return crc & 0xffff;
}

function rleCompress(data: Uint8Array): Uint8Array {
  const out: number[] = [];
  let i = 0;
  while (i < data.length) {
    const b = data[i]!;
    let run = 1;
    while (i + run < data.length && data[i + run] === b && run < 255) {
      run++;
    }

    if (b === 0x90) {
      // 0x90 is RLE marker: escape as 0x90, 0x00
      out.push(0x90, 0x00);
      i++;
    } else if (run >= 3) {
      out.push(b, 0x90, run);
      i += run;
    } else {
      out.push(b);
      i++;
    }
  }
  return new Uint8Array(out);
}

function rleDecompress(data: Uint8Array): Uint8Array {
  const out: number[] = [];
  let i = 0;
  while (i < data.length) {
    const b = data[i]!;
    if (b === 0x90 && i + 1 < data.length) {
      const count = data[i + 1]!;
      if (count === 0x00) {
        out.push(0x90);
      } else {
        const prev = out[out.length - 1] ?? 0;
        for (let r = 0; r < count - 1; r++) {
          out.push(prev);
        }
      }
      i += 2;
    } else {
      out.push(b);
      i++;
    }
  }
  return new Uint8Array(out);
}

export function binhexEncode(data: Uint8Array, filename = "data"): string {
  // Build Macintosh file header:
  // [nameLen (1B)] [name (nameLen B)] [version (1B=0)] [type (4B)] [creator (4B)] [flags (2B)] [dataLen (4B)] [rsrcLen (4B)] [headerCRC (2B)]
  const nameBytes = new TextEncoder().encode(filename.slice(0, 63));
  const hLen = 1 + nameBytes.length + 1 + 4 + 4 + 2 + 4 + 4;
  const header = new Uint8Array(hLen);
  header[0] = nameBytes.length;
  header.set(nameBytes, 1);
  let pos = 1 + nameBytes.length;
  header[pos++] = 0; // version
  header.set(new TextEncoder().encode("TEXT"), pos); pos += 4; // type
  header.set(new TextEncoder().encode("ttxt"), pos); pos += 4; // creator
  pos += 2; // flags = 0
  new DataView(header.buffer).setUint32(pos, data.length, false); pos += 4;
  new DataView(header.buffer).setUint32(pos, 0, false); pos += 4; // rsrcLen = 0

  const hCrc = binhexCrc(header);
  const dataCrc = binhexCrc(data);
  const rsrcCrc = binhexCrc(new Uint8Array(0));

  const payload = new Uint8Array(hLen + 2 + data.length + 2 + 0 + 2);
  payload.set(header, 0);
  payload[hLen] = (hCrc >>> 8) & 0xff;
  payload[hLen + 1] = hCrc & 0xff;
  payload.set(data, hLen + 2);
  const dEnd = hLen + 2 + data.length;
  payload[dEnd] = (dataCrc >>> 8) & 0xff;
  payload[dEnd + 1] = dataCrc & 0xff;
  payload[dEnd + 2] = (rsrcCrc >>> 8) & 0xff;
  payload[dEnd + 3] = rsrcCrc & 0xff;

  // RLE compress
  const rle = rleCompress(payload);

  // 6-bit encode
  let bitBuf = 0;
  let bitCount = 0;
  let encodedChars = "";

  for (let i = 0; i < rle.length; i++) {
    bitBuf = (bitBuf << 8) | rle[i]!;
    bitCount += 8;
    while (bitCount >= 6) {
      bitCount -= 6;
      const idx = (bitBuf >>> bitCount) & 0x3f;
      encodedChars += BINHEX_CHARS[idx]!;
    }
  }
  if (bitCount > 0) {
    const idx = (bitBuf << (6 - bitCount)) & 0x3f;
    encodedChars += BINHEX_CHARS[idx]!;
  }

  // Format into 64-char lines enclosed in colons
  const lines: string[] = [];
  for (let i = 0; i < encodedChars.length; i += 64) {
    lines.push(encodedChars.slice(i, i + 64));
  }

  return `(This file must be converted with BinHex 4.0)\n\n:${lines.join("\n")}:`;
}

export function binhexDecode(text: string): Uint8Array {
  // Extract content between first and last colon
  const firstColon = text.indexOf(":");
  const lastColon = text.lastIndexOf(":");
  if (firstColon === -1 || lastColon <= firstColon) {
    throw new Error("Invalid BinHex: missing surrounding colons.");
  }

  const clean = text.slice(firstColon + 1, lastColon).replace(/[\r\n\s]/g, "");
  // 6-bit decode
  let bitBuf = 0;
  let bitCount = 0;
  const rawBytes: number[] = [];

  for (let i = 0; i < clean.length; i++) {
    const val = BINHEX_REV.get(clean[i]!);
    if (val === undefined) continue;
    bitBuf = (bitBuf << 6) | val;
    bitCount += 6;
    while (bitCount >= 8) {
      bitCount -= 8;
      rawBytes.push((bitBuf >>> bitCount) & 0xff);
    }
  }

  const rleData = new Uint8Array(rawBytes);
  const decomp = rleDecompress(rleData);

  // Parse header to extract data fork
  if (decomp.length < 22) throw new Error("Invalid BinHex payload.");
  const nameLen = decomp[0]!;
  const pos = 1 + nameLen + 1 + 4 + 4 + 2;
  const view = new DataView(decomp.buffer, decomp.byteOffset, decomp.length);
  const dataLen = view.getUint32(pos, false);
  const dataStart = 1 + nameLen + 1 + 4 + 4 + 2 + 4 + 4 + 2; // + 2 for header CRC

  return decomp.slice(dataStart, dataStart + dataLen);
}
