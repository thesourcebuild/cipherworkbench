/**
 * GSM 03.38 7-bit Cellular Alphabet:
 * Standard SMS default alphabet and extension escape table.
 */

export const GSM_BASIC = [
  "@", "£", "$", "¥", "è", "é", "ù", "ì", "ò", "Ç", "\n", "Ø", "ø", "\r", "Å", "å",
  "Δ", "_", "Φ", "Γ", "Λ", "Ω", "Π", "Ψ", "Σ", "Θ", "Ξ", "\x1b", "Æ", "æ", "ß", "É",
  " ", "!", "\"", "#", "¤", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/",
  "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?",
  "¡", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
  "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "Ä", "Ö", "Ñ", "Ü", "§",
  "¿", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
  "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "ä", "ö", "ñ", "ü", "à",
];

export const GSM_EXTENSION: Record<number, string> = {
  0x0a: "\f",
  0x14: "^",
  0x28: "{",
  0x29: "}",
  0x2f: "\\",
  0x3c: "[",
  0x3d: "~",
  0x3e: "]",
  0x40: "|",
  0x65: "€",
};

const CHAR_TO_GSM = new Map<string, number>();
for (let i = 0; i < GSM_BASIC.length; i++) {
  CHAR_TO_GSM.set(GSM_BASIC[i]!, i);
}

const EXT_TO_GSM = new Map<string, number>();
for (const [code, ch] of Object.entries(GSM_EXTENSION)) {
  EXT_TO_GSM.set(ch, Number(code));
}

export function gsm0338Encode(text: string): Uint8Array {
  const bytes: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (EXT_TO_GSM.has(ch)) {
      bytes.push(0x1b); // escape
      bytes.push(EXT_TO_GSM.get(ch)!);
    } else if (CHAR_TO_GSM.has(ch)) {
      bytes.push(CHAR_TO_GSM.get(ch)!);
    } else {
      bytes.push(0x3f); // '?' fallback
    }
  }
  return new Uint8Array(bytes);
}

export function gsm0338Decode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    if (b === 0x1b && i + 1 < bytes.length) {
      i++;
      const extChar = GSM_EXTENSION[bytes[i]!];
      out += extChar ?? "?";
    } else {
      out += GSM_BASIC[b] ?? "?";
    }
  }
  return out;
}

/**
 * Pack GSM 03.38 septets into 8-bit octets (7-bit PDU packing).
 * Each character is first looked up in the GSM alphabet, then the 7-bit codes
 * are bit-packed into a continuous stream of 8-bit bytes.
 */
export function gsm0338Pack(text: string): Uint8Array {
  const septets: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const extVal = EXT_TO_GSM.get(ch);
    if (extVal !== undefined) {
      septets.push(0x1b, extVal); // escape + extension byte
    } else {
      const val = CHAR_TO_GSM.get(ch);
      septets.push(val !== undefined ? val : 0x3f); // '?' fallback
    }
  }

  const numOctets = Math.ceil((septets.length * 7) / 8);
  const octets = new Uint8Array(numOctets);
  let bitOffset = 0;
  for (let i = 0; i < septets.length; i++) {
    const s = septets[i]! & 0x7f;
    const byteIdx = Math.floor(bitOffset / 8);
    const shift = bitOffset % 8;
    octets[byteIdx] = (octets[byteIdx]! | ((s << shift) & 0xff)) & 0xff;
    if (shift > 1 && byteIdx + 1 < numOctets) {
      octets[byteIdx + 1] = (octets[byteIdx + 1]! | (s >>> (8 - shift))) & 0xff;
    }
    bitOffset += 7;
  }
  return octets;
}

/**
 * Unpack 7-bit PDU octets back into a string using the GSM 03.38 alphabet.
 */
export function gsm0338Unpack(octets: Uint8Array, septetCount?: number): string {
  const total = septetCount ?? Math.floor((octets.length * 8) / 7);
  const septets: number[] = [];
  let bitOffset = 0;
  for (let i = 0; i < total; i++) {
    const byteIdx = Math.floor(bitOffset / 8);
    const shift = bitOffset % 8;
    let s = (octets[byteIdx]! >>> shift) & 0x7f;
    if (shift > 1 && byteIdx + 1 < octets.length) {
      s = (s | ((octets[byteIdx + 1]! << (8 - shift)) & 0x7f)) & 0x7f;
    }
    septets.push(s);
    bitOffset += 7;
  }

  let out = "";
  for (let i = 0; i < septets.length; i++) {
    const s = septets[i]!;
    if (s === 0x1b && i + 1 < septets.length) {
      i++;
      out += GSM_EXTENSION[septets[i]!] ?? "?";
    } else {
      out += GSM_BASIC[s] ?? "?";
    }
  }
  return out;
}
