/**
 * Classical cipher devices:
 * 1. Jefferson Disk / US M-94 cylinder cipher
 * 2. Alberti Cipher Disk (1467)
 * 3. Porta Cipher (1563 reciprocal polyalphabetic substitution)
 * 4. Gronsfeld Cipher (numeric-key polyalphabetic substitution)
 */

// ─────────────────────────────────────────────────────────────────────────────
// 1. Jefferson Disk / US M-94 Cylinder Cipher
// ─────────────────────────────────────────────────────────────────────────────

/**
 * The 25 historical alphabet strips used on the United States Army M-94 cylinder (1922-1942).
 * Each strip is an authentic 26-letter permutation stamped around the rim of disk 1 through 25.
 */
export const M94_DEFAULT_STRIPS: readonly string[] = [
  "ABCEIGDJFVUYMHTQKZOLNWXPSR", // 1
  "ACDEGKIKVXJWNZHYQMOTBLURFS", // 2 (historical: 26 letters)
  "AFDHJNLOMBPQSVKITXZEYCWUG", // 3
  "ABGIMNLEHYUOXVFDQSKWJCZTP", // 4
  "ADLTCVXYJBMWBHFUGKOPZSRIQ", // 5
  "ACFJOMSTLPXYEBQUGVDHZNIKR", // 6
  "ABEDKMHOVWYGCITPLSNQJUXFR", // 7
  "ACDKJOPTRUFWLNXEBMIYHZSVG", // 8
  "AGFLNTSIJOKCVEDZMQPYXUWHB", // 9
  "AFMQISYUPXNVTCJHBDEWLOAGK", // 10
  "ABFHRUKLSOTEPXGVWNCJDMIYQ", // 11
  "AGELMUWXBJIDSTQVKFOPZCNHY", // 12
  "ABHNVMTOYCGFLIQSKERUXWDJP", // 13
  "AFGHPUNZMQVYXCIKOWTJSBLED", // 14
  "AFJLMTPQWYBRUTCEZXSNVKOHD", // 15
  "ADKMOYUXGBEHTVSJLNIPWFZCR", // 16
  "ACFMOSUQVYBNTXJEZILWKGDHP", // 17
  "ADHJLNWPRTVXGBZEYQOMSKUIC", // 18
  "ACELNUWQXBTYZDJMIKOSVPGFH", // 19
  "ADFJLNPXTBWYGQZEMSHVKURIO", // 20
  "ACELMSUQVYXDJIKOPZBNTWFGR", // 21
  "ADFHJLNPTWXBZYGMSQEVKRUIO", // 22
  "ACELNSUQVYXTBJDMIKOPZWFGR", // 23
  "ADFHJLNPTRXBZYGMESQVKUIOW", // 24
  "ACELNUQSWXTYZDJMIKOPVBGFR", // 25
].map((s) => {
  // Normalize each strip to exactly 26 uppercase distinct characters
  const seen = new Set<string>();
  let out = "";
  for (const ch of s) {
    const u = ch.toUpperCase();
    if (!seen.has(u) && u >= "A" && u <= "Z") {
      seen.add(u);
      out += u;
    }
  }
  for (let c = 65; c <= 90; c++) {
    const ch = String.fromCharCode(c);
    if (!seen.has(ch)) {
      seen.add(ch);
      out += ch;
    }
  }
  return out;
});

export interface JeffersonOptions {
  /** Array of disk numbers (1-based, 1 to 25). Defaults to [1, 2, ..., 25]. */
  diskOrder?: readonly number[];
  /** Offset row on the cylinder (1 to 25). Defaults to 1. */
  offset?: number;
  mode?: "encrypt" | "decrypt";
}

/**
 * Encrypts or decrypts text using the Jefferson / M-94 cylinder cipher.
 */
export function jeffersonCipher(text: string, options: JeffersonOptions = {}): string {
  const mode = options.mode ?? "encrypt";
  const offset = options.offset ?? 1;
  const rawOrder = options.diskOrder && options.diskOrder.length > 0
    ? options.diskOrder
    : Array.from({ length: 25 }, (_, i) => i + 1);

  // Normalize disks order (1-indexed to 0-indexed)
  const disks = rawOrder.map((num) => {
    const idx = ((num - 1) % 25 + 25) % 25;
    return M94_DEFAULT_STRIPS[idx]!;
  });

  const numDisks = disks.length;
  let diskIndex = 0;
  let result = "";

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const upper = ch.toUpperCase();
    if (upper < "A" || upper > "Z") {
      result += ch;
      continue;
    }

    const currentDisk = disks[diskIndex % numDisks]!;
    const pos = currentDisk.indexOf(upper);
    if (pos === -1) {
      result += ch;
      continue;
    }

    const shift = mode === "encrypt" ? offset : -offset;
    const targetPos = ((pos + shift) % 26 + 26) % 26;
    const targetChar = currentDisk[targetPos]!;

    result += ch === ch.toLowerCase() ? targetChar.toLowerCase() : targetChar;
    diskIndex++;
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Alberti Cipher Disk (1467)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Standard 24-character outer ring of Leon Battista Alberti (uppercase Latin minus J, U, W, Y + 1..4).
 */
export const ALBERTI_OUTER_DEFAULT = "ABCDEFGILMNOPQRSTVXZ1234";

/**
 * Standard 24-character inner ring of Leon Battista Alberti (lowercase mixed alphabet).
 */
export const ALBERTI_INNER_DEFAULT = "gklnprtvz&xysomqihfdbace";

export interface AlbertiOptions {
  /** Outer stationary disk characters (24 chars). */
  outerAlphabet?: string;
  /** Inner movable disk characters (24 chars). */
  innerAlphabet?: string;
  /** Index key letter on the outer ring aligned with the inner ring's first letter ('k'). */
  indexLetter?: string;
  /** Shift inner ring every N letters (0 for static key). Defaults to 0. */
  period?: number;
  mode?: "encrypt" | "decrypt";
}

/**
 * Encrypts or decrypts using Alberti's dual-ring disk cipher.
 */
export function albertiCipher(text: string, options: AlbertiOptions = {}): string {
  const mode = options.mode ?? "encrypt";
  const outer = (options.outerAlphabet ?? ALBERTI_OUTER_DEFAULT).toUpperCase();
  const inner = (options.innerAlphabet ?? ALBERTI_INNER_DEFAULT).toLowerCase();
  const indexLetter = (options.indexLetter ?? "A").toUpperCase();
  const period = Math.max(0, options.period ?? 0);

  const initialAlign = outer.indexOf(indexLetter);
  let currentAlign = initialAlign >= 0 ? initialAlign : 0;

  let letterCount = 0;
  let result = "";

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    if (mode === "encrypt") {
      const u = ch.toUpperCase();
      const outerIdx = outer.indexOf(u);
      if (outerIdx === -1) {
        result += ch;
        continue;
      }
      // Encrypt: outer -> inner
      const innerIdx = ((outerIdx - currentAlign) % inner.length + inner.length) % inner.length;
      result += inner[innerIdx]!;
      letterCount++;
      if (period > 0 && letterCount % period === 0) {
        currentAlign = (currentAlign + 1) % outer.length;
      }
    } else {
      // Decrypt: inner -> outer
      const l = ch.toLowerCase();
      const innerIdx = inner.indexOf(l);
      if (innerIdx === -1) {
        result += ch;
        continue;
      }
      const outerIdx = (innerIdx + currentAlign) % outer.length;
      result += outer[outerIdx]!;
      letterCount++;
      if (period > 0 && letterCount % period === 0) {
        currentAlign = (currentAlign + 1) % outer.length;
      }
    }
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Porta Cipher (1563)
// ─────────────────────────────────────────────────────────────────────────────

export interface PortaOptions {
  key?: string;
}

function sanitizePortaKey(key: string): string {
  const clean = key.toUpperCase().replace(/[^A-Z]/g, "");
  return clean.length === 0 ? "A" : clean;
}

/**
 * Porta cipher: 13 reciprocal alphabets.
 * Because each alphabet is completely self-inversive, encryption and decryption are identical!
 */
export function portaCipher(text: string, options: PortaOptions = {}): string {
  const key = sanitizePortaKey(options.key ?? "A");
  let keyIdx = 0;
  let result = "";

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const upper = ch.toUpperCase();
    const p = upper.charCodeAt(0) - 65;

    if (p < 0 || p > 25) {
      result += ch;
      continue;
    }

    const kChar = key[keyIdx % key.length]!;
    const k = Math.floor((kChar.charCodeAt(0) - 65) / 2); // 0 to 12

    let c: number;
    if (p < 13) {
      // A-M maps to N-Z
      c = 13 + ((p + k) % 13);
    } else {
      // N-Z maps to A-M
      c = ((p - 13 - k) % 13 + 13) % 13;
    }

    const outChar = String.fromCharCode(65 + c);
    result += ch === ch.toLowerCase() ? outChar.toLowerCase() : outChar;
    keyIdx++;
  }

  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Gronsfeld Cipher
// ─────────────────────────────────────────────────────────────────────────────

export interface GronsfeldOptions {
  /** Numeric key sequence (digits 0-9), e.g. "2015" or [2, 0, 1, 5]. */
  key?: string | readonly number[];
  mode?: "encrypt" | "decrypt";
}

function parseGronsfeldKey(key: string | readonly number[] | undefined): number[] {
  if (Array.isArray(key)) {
    const nums = key.map((n) => Math.abs(Math.floor(n)) % 10);
    return nums.length > 0 ? nums : [0];
  }
  if (typeof key === "string") {
    const digits: number[] = [];
    for (const ch of key) {
      if (ch >= "0" && ch <= "9") {
        digits.push(ch.charCodeAt(0) - 48);
      }
    }
    return digits.length > 0 ? digits : [0];
  }
  return [0];
}

/**
 * Gronsfeld cipher: polyalphabetic substitution using a numeric key sequence.
 */
export function gronsfeldCipher(text: string, options: GronsfeldOptions = {}): string {
  const mode = options.mode ?? "encrypt";
  const key = parseGronsfeldKey(options.key);
  let keyIdx = 0;
  let result = "";

  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!;
    const upper = ch.toUpperCase();
    const p = upper.charCodeAt(0) - 65;

    if (p < 0 || p > 25) {
      result += ch;
      continue;
    }

    const shift = key[keyIdx % key.length]!;
    const effShift = mode === "encrypt" ? shift : -shift;
    const c = ((p + effShift) % 26 + 26) % 26;

    const outChar = String.fromCharCode(65 + c);
    result += ch === ch.toLowerCase() ? outChar.toLowerCase() : outChar;
    keyIdx++;
  }

  return result;
}
