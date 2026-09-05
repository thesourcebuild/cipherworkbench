/**
 * OpenPGP ASCII Armor (RFC 4880 Section 6):
 * Radix-64 encoding with CRC-24 (poly 0x864cfb, init 0xb704ce) checksum and header framing.
 */

const B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_REV = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64_ALPHABET.length; i++) table[B64_ALPHABET.charCodeAt(i)] = i;
  return table;
})();

function base64Encode(data: Uint8Array): string {
  let str = "";
  for (let i = 0; i < data.length; i += 3) {
    const b0 = data[i]!;
    const b1 = i + 1 < data.length ? data[i + 1]! : 0;
    const b2 = i + 2 < data.length ? data[i + 2]! : 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;

    str += B64_ALPHABET[(triple >>> 18) & 0x3f]!;
    str += B64_ALPHABET[(triple >>> 12) & 0x3f]!;
    str += i + 1 < data.length ? B64_ALPHABET[(triple >>> 6) & 0x3f]! : "=";
    str += i + 2 < data.length ? B64_ALPHABET[triple & 0x3f]! : "=";
  }
  return str;
}

function base64Decode(str: string): Uint8Array {
  const clean = str.replace(/[^A-Za-z0-9+/=]/g, "");
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 4) {
    const a = B64_REV[clean.charCodeAt(i)] ?? -1;
    const b = B64_REV[clean.charCodeAt(i + 1)] ?? -1;
    const c = clean[i + 2] === "=" ? -1 : (B64_REV[clean.charCodeAt(i + 2)] ?? -1);
    const d = clean[i + 3] === "=" ? -1 : (B64_REV[clean.charCodeAt(i + 3)] ?? -1);

    if (a < 0 || b < 0) break;
    const triple = (a << 18) | (b << 12) | ((c < 0 ? 0 : c) << 6) | (d < 0 ? 0 : d);
    out.push((triple >>> 16) & 0xff);
    if (c >= 0) out.push((triple >>> 8) & 0xff);
    if (d >= 0) out.push(triple & 0xff);
  }
  return new Uint8Array(out);
}

export function crc24(data: Uint8Array): number {
  const CRC24_INIT = 0xb704ce;
  const CRC24_POLY = 0x1864cfb;
  let crc = CRC24_INIT;

  for (let i = 0; i < data.length; i++) {
    crc ^= (data[i]! << 16);
    for (let j = 0; j < 8; j++) {
      crc <<= 1;
      if (crc & 0x1000000) {
        crc ^= CRC24_POLY;
      }
    }
  }
  return crc & 0xffffff;
}

export function openpgpArmorEncode(data: Uint8Array, messageType = "MESSAGE"): string {
  const header = `-----BEGIN PGP ${messageType}-----\nVersion: CipherWorkbench 0.8.0\n\n`;
  const footer = `\n-----END PGP ${messageType}-----`;

  // Base64 encode in 64-char lines
  const b64 = base64Encode(data);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }

  // Checksum: 24-bit CRC encoded in 4 Base64 characters with '=' prefix
  const checksumVal = crc24(data);
  const checkBytes = new Uint8Array([
    (checksumVal >>> 16) & 0xff,
    (checksumVal >>> 8) & 0xff,
    checksumVal & 0xff,
  ]);
  const checkB64 = "=" + base64Encode(checkBytes);

  return header + lines.join("\n") + "\n" + checkB64 + footer;
}

export function openpgpArmorDecode(armor: string): Uint8Array {
  // Strip headers and footers
  const lines = armor.split(/\r?\n/);
  const dataLines: string[] = [];
  let inData = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith("-----BEGIN PGP")) {
      inData = true;
      continue;
    }
    if (trimmed.startsWith("-----END PGP")) {
      break;
    }
    if (!inData || trimmed.length === 0 || trimmed.includes(":")) {
      continue;
    }
    if (trimmed.startsWith("=")) {
      // Checksum line
      continue;
    }
    dataLines.push(trimmed);
  }

  const b64 = dataLines.join("");
  return base64Decode(b64);
}

export const openPgpArmorEncode = openpgpArmorEncode;
export const openPgpArmorDecode = openpgpArmorDecode;
export const openPgpCrc24 = crc24;
