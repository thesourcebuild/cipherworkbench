/**
 * Autokey Cipher:
 * Blaise de Vigenère's authentic autokey cipher where the plaintext extends the keystream.
 */

export function autokeyEncrypt(text: string, key: string): string {
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, "") || "A";
  let result = "";
  const keystream: number[] = [];
  for (let i = 0; i < cleanKey.length; i++) {
    keystream.push(cleanKey.charCodeAt(i) - 65);
  }

  let streamIdx = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const isUpper = ch >= "A" && ch <= "Z";
    const isLower = ch >= "a" && ch <= "z";
    if (!isUpper && !isLower) {
      result += ch;
      continue;
    }
    const p = (isUpper ? ch.charCodeAt(0) - 65 : ch.charCodeAt(0) - 97);
    const k = keystream[streamIdx++]!;
    const c = (p + k) % 26;
    keystream.push(p); // plaintext extends the keystream
    result += String.fromCharCode(isUpper ? c + 65 : c + 97);
  }
  return result;
}

export function autokeyDecrypt(text: string, key: string): string {
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, "") || "A";
  let result = "";
  const keystream: number[] = [];
  for (let i = 0; i < cleanKey.length; i++) {
    keystream.push(cleanKey.charCodeAt(i) - 65);
  }

  let streamIdx = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const isUpper = ch >= "A" && ch <= "Z";
    const isLower = ch >= "a" && ch <= "z";
    if (!isUpper && !isLower) {
      result += ch;
      continue;
    }
    const c = (isUpper ? ch.charCodeAt(0) - 65 : ch.charCodeAt(0) - 97);
    const k = keystream[streamIdx++]!;
    const p = (c - k + 26) % 26;
    keystream.push(p); // recovered plaintext extends the keystream
    result += String.fromCharCode(isUpper ? p + 65 : p + 97);
  }
  return result;
}
