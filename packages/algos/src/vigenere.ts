/**
 * Vigenère & Beaufort Ciphers -- Polyalphabetic Tabula Recta Substitution.
 *
 * Implements:
 * - Standard Vigenère: C_i = (P_i + K_i) mod 26
 * - Beaufort Reciprocal: C_i = (K_i - P_i) mod 26
 * - Variant Beaufort: C_i = (P_i - K_i) mod 26
 * - Autokey Vigenère (using plaintext as subsequent key stream).
 */

export interface VigenereOptions {
  key?: string;
  variant?: "vigenere" | "beaufort" | "variant-beaufort" | "autokey";
  mode?: "encrypt" | "decrypt";
}

function sanitizeKey(key: string): string {
  const clean = key.toUpperCase().replace(/[^A-Z]/g, "");
  return clean.length === 0 ? "KEY" : clean;
}

export function vigenereEncrypt(text: string, options: VigenereOptions = {}): string {
  const key = sanitizeKey(options.key ?? "KEY");
  const variant = options.variant ?? "vigenere";
  let keyIndex = 0;
  let result = "";

  const autokeyStream = key.split("");

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const upper = ch.toUpperCase();
    const p = upper.charCodeAt(0) - 65;

    if (p < 0 || p >= 26) {
      result += ch;
      continue;
    }

    const currentKeyChar = variant === "autokey" && keyIndex >= key.length
      ? autokeyStream[keyIndex]!
      : key[keyIndex % key.length]!;

    const k = currentKeyChar.charCodeAt(0) - 65;
    let c: number;

    if (variant === "vigenere" || variant === "autokey") {
      c = (p + k) % 26;
      if (variant === "autokey") autokeyStream.push(upper);
    } else if (variant === "beaufort") {
      c = (k - p + 26) % 26;
    } else {
      // variant-beaufort
      c = (p - k + 26) % 26;
    }

    const outChar = String.fromCharCode(65 + c);
    result += ch === ch.toLowerCase() ? outChar.toLowerCase() : outChar;
    keyIndex++;
  }

  return result;
}

export function vigenereDecrypt(text: string, options: VigenereOptions = {}): string {
  const key = sanitizeKey(options.key ?? "KEY");
  const variant = options.variant ?? "vigenere";
  let keyIndex = 0;
  let result = "";

  const autokeyStream = key.split("");

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const upper = ch.toUpperCase();
    const c = upper.charCodeAt(0) - 65;

    if (c < 0 || c >= 26) {
      result += ch;
      continue;
    }

    const currentKeyChar = variant === "autokey" && keyIndex >= key.length
      ? autokeyStream[keyIndex]!
      : key[keyIndex % key.length]!;

    const k = currentKeyChar.charCodeAt(0) - 65;
    let p: number;

    if (variant === "vigenere" || variant === "autokey") {
      p = (c - k + 26) % 26;
      if (variant === "autokey") autokeyStream.push(String.fromCharCode(65 + p));
    } else if (variant === "beaufort") {
      // Beaufort is self-reciprocal
      p = (k - c + 26) % 26;
    } else {
      // variant-beaufort
      p = (c + k) % 26;
    }

    const outChar = String.fromCharCode(65 + p);
    result += ch === ch.toLowerCase() ? outChar.toLowerCase() : outChar;
    keyIndex++;
  }

  return result;
}
