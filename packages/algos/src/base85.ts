/**
 * Base85 (Ascii85 & Z85 & RFC 1924) -- 4-byte to 5-character binary-to-text encoding.
 *
 * Implements:
 * - Standard Adobe Ascii85 (<~ ... ~>, with 'z' abbreviation for all-zero words).
 * - ZeroMQ Z85 (32-printable character set for wire protocol formatting).
 * - IPv6 RFC 1924 Base85.
 */

const Z85_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
const RFC1924_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";

export type Base85Variant = "ascii85" | "z85" | "rfc1924";

export function base85Encode(data: Uint8Array, variant: Base85Variant = "ascii85"): string {
  if (data.length === 0) return "";

  if (variant === "z85") {
    if (data.length % 4 !== 0) {
      throw new Error(`Z85 data length must be a multiple of 4 bytes; got ${data.length}`);
    }
    let res = "";
    for (let i = 0; i < data.length; i += 4) {
      let val = ((data[i]! << 24) | (data[i + 1]! << 16) | (data[i + 2]! << 8) | data[i + 3]!) >>> 0;
      let chars = "";
      for (let j = 0; j < 5; j++) {
        chars = Z85_ALPHABET[val % 85] + chars;
        val = Math.floor(val / 85);
      }
      res += chars;
    }
    return res;
  }

  if (variant === "rfc1924") {
    let res = "";
    for (let i = 0; i < data.length; i += 4) {
      const chunk = data.subarray(i, i + 4);
      let val = 0;
      for (let j = 0; j < 4; j++) {
        val = ((val << 8) | (chunk[j] ?? 0)) >>> 0;
      }
      let chars = "";
      for (let j = 0; j < 5; j++) {
        chars = RFC1924_ALPHABET[val % 85] + chars;
        val = Math.floor(val / 85);
      }
      if (chunk.length < 4) {
        chars = chars.slice(0, chunk.length + 1);
      }
      res += chars;
    }
    return res;
  }

  // Standard Adobe Ascii85
  let res = "";
  for (let i = 0; i < data.length; i += 4) {
    const chunk = data.subarray(i, i + 4);
    let val = 0;
    for (let j = 0; j < 4; j++) {
      val = ((val << 8) | (chunk[j] ?? 0)) >>> 0;
    }

    if (chunk.length === 4 && val === 0) {
      res += "z";
      continue;
    }

    let chars = "";
    for (let j = 0; j < 5; j++) {
      chars = String.fromCharCode(33 + (val % 85)) + chars;
      val = Math.floor(val / 85);
    }

    // Truncate padded chars for partial trailing chunk
    if (chunk.length < 4) {
      chars = chars.slice(0, chunk.length + 1);
    }
    res += chars;
  }

  return res;
}

export function base85Decode(text: string, variant: Base85Variant = "ascii85"): Uint8Array {
  if (text.length === 0) return new Uint8Array(0);

  if (variant === "z85") {
    const clean = text.replace(/\s+/g, "");
    if (clean.length % 5 !== 0) {
      throw new Error(`Z85 text length must be a multiple of 5 characters; got ${clean.length}`);
    }
    const out = new Uint8Array((clean.length / 5) * 4);
    let outIdx = 0;

    for (let i = 0; i < clean.length; i += 5) {
      let val = 0;
      for (let j = 0; j < 5; j++) {
        const idx = Z85_ALPHABET.indexOf(clean[i + j]!);
        if (idx === -1) throw new Error(`Invalid Z85 character: ${clean[i + j]}`);
        val = val * 85 + idx;
      }
      out[outIdx++] = (val >>> 24) & 0xff;
      out[outIdx++] = (val >>> 16) & 0xff;
      out[outIdx++] = (val >>> 8) & 0xff;
      out[outIdx++] = val & 0xff;
    }
    return out;
  }

  if (variant === "rfc1924") {
    const clean = text.replace(/\s+/g, "");
    const outBytes: number[] = [];

    let i = 0;
    while (i < clean.length) {
      let chunk = clean.slice(i, i + 5);
      const chunkLen = chunk.length;
      while (chunk.length < 5) {
        chunk += "~"; // pad with last character in alphabet (value 84)
      }

      let val = 0;
      for (let j = 0; j < 5; j++) {
        const idx = RFC1924_ALPHABET.indexOf(chunk[j]!);
        if (idx === -1) throw new Error(`Invalid RFC 1924 character: ${chunk[j]}`);
        val = val * 85 + idx;
      }

      const b0 = (val >>> 24) & 0xff;
      const b1 = (val >>> 16) & 0xff;
      const b2 = (val >>> 8) & 0xff;
      const b3 = val & 0xff;

      if (chunkLen >= 2) outBytes.push(b0);
      if (chunkLen >= 3) outBytes.push(b1);
      if (chunkLen >= 4) outBytes.push(b2);
      if (chunkLen >= 5) outBytes.push(b3);

      i += chunkLen;
    }

    return new Uint8Array(outBytes);
  }

  // Ascii85 decoding
  const clean = text.replace(/^<~/, "").replace(/~>$/, "").replace(/\s+/g, "");
  const outBytes: number[] = [];

  let i = 0;
  while (i < clean.length) {
    if (clean[i] === "z") {
      outBytes.push(0, 0, 0, 0);
      i++;
      continue;
    }

    let chunk = clean.slice(i, i + 5);
    const chunkLen = chunk.length;
    while (chunk.length < 5) {
      chunk += "u"; // pad with 'u' (value 84)
    }

    let val = 0;
    for (let j = 0; j < 5; j++) {
      const code = chunk.charCodeAt(j) - 33;
      if (code < 0 || code >= 85) throw new Error(`Invalid Ascii85 character: ${chunk[j]}`);
      val = val * 85 + code;
    }

    const b0 = (val >>> 24) & 0xff;
    const b1 = (val >>> 16) & 0xff;
    const b2 = (val >>> 8) & 0xff;
    const b3 = val & 0xff;

    if (chunkLen >= 2) outBytes.push(b0);
    if (chunkLen >= 3) outBytes.push(b1);
    if (chunkLen >= 4) outBytes.push(b2);
    if (chunkLen >= 5) outBytes.push(b3);

    i += chunkLen;
  }

  return new Uint8Array(outBytes);
}
