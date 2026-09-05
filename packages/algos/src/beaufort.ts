/**
 * Beaufort Cipher & Variant Beaufort:
 * Reciprocal polyalphabetic substitution cipher: C = (K - P) mod 26.
 */

export function beaufortEncrypt(text: string, key: string): string {
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, "") || "A";
  let result = "";
  let kIdx = 0;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const isUpper = ch >= "A" && ch <= "Z";
    const isLower = ch >= "a" && ch <= "z";
    if (!isUpper && !isLower) {
      result += ch;
      continue;
    }
    const p = (isUpper ? ch.charCodeAt(0) - 65 : ch.charCodeAt(0) - 97);
    const k = cleanKey.charCodeAt(kIdx % cleanKey.length) - 65;
    kIdx++;
    // Beaufort: C = (K - P) mod 26
    const c = (k - p + 26) % 26;
    result += String.fromCharCode(isUpper ? c + 65 : c + 97);
  }
  return result;
}

export function beaufortDecrypt(text: string, key: string): string {
  // Beaufort is self-reciprocal: D(C) = (K - C) mod 26 = P
  return beaufortEncrypt(text, key);
}

export function variantBeaufortEncrypt(text: string, key: string): string {
  // Variant Beaufort: C = (P - K) mod 26
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, "") || "A";
  let result = "";
  let kIdx = 0;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const isUpper = ch >= "A" && ch <= "Z";
    const isLower = ch >= "a" && ch <= "z";
    if (!isUpper && !isLower) {
      result += ch;
      continue;
    }
    const p = (isUpper ? ch.charCodeAt(0) - 65 : ch.charCodeAt(0) - 97);
    const k = cleanKey.charCodeAt(kIdx % cleanKey.length) - 65;
    kIdx++;
    const c = (p - k + 26) % 26;
    result += String.fromCharCode(isUpper ? c + 65 : c + 97);
  }
  return result;
}

export function variantBeaufortDecrypt(text: string, key: string): string {
  // Inverse of Variant Beaufort is Vigenere: P = (C + K) mod 26
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, "") || "A";
  let result = "";
  let kIdx = 0;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const isUpper = ch >= "A" && ch <= "Z";
    const isLower = ch >= "a" && ch <= "z";
    if (!isUpper && !isLower) {
      result += ch;
      continue;
    }
    const c = (isUpper ? ch.charCodeAt(0) - 65 : ch.charCodeAt(0) - 97);
    const k = cleanKey.charCodeAt(kIdx % cleanKey.length) - 65;
    kIdx++;
    const p = (c + k) % 26;
    result += String.fromCharCode(isUpper ? p + 65 : p + 97);
  }
  return result;
}
