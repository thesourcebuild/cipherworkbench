/**
 * UUEncode and UUDecode (Unix-to-Unix Encoding).
 * Classic 6-bit encoding adding 32 (ASCII space offset to printable chars 32..95).
 * Each line starts with a character indicating line byte count.
 */

export function encodeUU(data: Uint8Array, filename = "file.txt"): string {
  let out = `begin 644 ${filename}\n`;

  for (let i = 0; i < data.length; i += 45) {
    const chunk = data.subarray(i, i + 45);
    const lineLenChar = String.fromCharCode(chunk.length + 32);
    let line = lineLenChar;

    for (let j = 0; j < chunk.length; j += 3) {
      const b0 = chunk[j] ?? 0;
      const b1 = chunk[j + 1] ?? 0;
      const b2 = chunk[j + 2] ?? 0;

      const c0 = (b0 >>> 2) & 0x3f;
      const c1 = (((b0 << 4) & 0x30) | ((b1 >>> 4) & 0x0f)) & 0x3f;
      const c2 = (((b1 << 2) & 0x3c) | ((b2 >>> 6) & 0x03)) & 0x3f;
      const c3 = b2 & 0x3f;

      line += String.fromCharCode(c0 === 0 ? 96 : c0 + 32);
      line += String.fromCharCode(c1 === 0 ? 96 : c1 + 32);
      line += String.fromCharCode(c2 === 0 ? 96 : c2 + 32);
      line += String.fromCharCode(c3 === 0 ? 96 : c3 + 32);
    }
    out += line + "\n";
  }

  out += "`\nend\n";
  return out;
}

export function decodeUU(str: string): Uint8Array {
  const lines = str.trim().split(/\r?\n/);
  const bytes: number[] = [];

  for (const line of lines) {
    if (line.startsWith("begin ") || line === "end" || line === "`" || line.length === 0) {
      continue;
    }

    const firstChar = line.charCodeAt(0);
    const count = (firstChar === 96 ? 0 : firstChar - 32) & 0x3f;
    if (count <= 0 || count > 45) continue;

    const dataPart = line.slice(1);
    let bytesRead = 0;

    for (let i = 0; i < dataPart.length && bytesRead < count; i += 4) {
      const c0 = (dataPart.charCodeAt(i) - 32) & 0x3f;
      const c1 = (dataPart.charCodeAt(i + 1) - 32) & 0x3f;
      const c2 = (dataPart.charCodeAt(i + 2) - 32) & 0x3f;
      const c3 = (dataPart.charCodeAt(i + 3) - 32) & 0x3f;

      const b0 = ((c0 << 2) | (c1 >>> 4)) & 0xff;
      const b1 = ((c1 << 4) | (c2 >>> 2)) & 0xff;
      const b2 = ((c2 << 6) | c3) & 0xff;

      bytes.push(b0);
      bytesRead++;
      if (bytesRead < count) {
        bytes.push(b1);
        bytesRead++;
      }
      if (bytesRead < count) {
        bytes.push(b2);
        bytesRead++;
      }
    }
  }

  return new Uint8Array(bytes);
}
