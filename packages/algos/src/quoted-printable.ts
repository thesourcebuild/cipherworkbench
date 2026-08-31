/**
 * Quoted-Printable Encoding and Decoding (RFC 2045 / MIME).
 * Encodes non-ASCII or unprintable 8-bit bytes into =XX hexadecimal escape sequences.
 */

export function encodeQuotedPrintable(data: Uint8Array): string {
  let out = "";
  let lineLen = 0;

  for (let i = 0; i < data.length; i++) {
    const b = data[i]!;
    // Printable ASCII (33-60 and 62-126) and space/tab when not at end of line
    if ((b >= 33 && b <= 60) || (b >= 62 && b <= 126)) {
      if (lineLen >= 75) {
        out += "=\r\n";
        lineLen = 0;
      }
      out += String.fromCharCode(b);
      lineLen += 1;
    } else if (b === 9 || b === 32) {
      if (lineLen >= 75) {
        out += "=\r\n";
        lineLen = 0;
      }
      out += String.fromCharCode(b);
      lineLen += 1;
    } else {
      if (lineLen >= 73) {
        out += "=\r\n";
        lineLen = 0;
      }
      const hex = b.toString(16).toUpperCase().padStart(2, "0");
      out += `=${hex}`;
      lineLen += 3;
    }
  }

  return out;
}

export function decodeQuotedPrintable(str: string): Uint8Array {
  // Remove soft line breaks (=\r\n or =\n)
  const normalized = str.replace(/=\r?\n/g, "");
  const bytes: number[] = [];

  let i = 0;
  while (i < normalized.length) {
    if (normalized[i] === "=" && i + 2 < normalized.length) {
      const hex = normalized.slice(i + 1, i + 3);
      if (/^[0-9A-Fa-f]{2}$/.test(hex)) {
        bytes.push(parseInt(hex, 16));
        i += 3;
        continue;
      }
    }
    bytes.push(normalized.charCodeAt(i));
    i++;
  }

  return new Uint8Array(bytes);
}
