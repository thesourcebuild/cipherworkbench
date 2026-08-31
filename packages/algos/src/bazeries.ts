/**
 * Bazeries Cylinder / US Army M-94 Cipher (1922-1942).
 * 25 aluminium discs rotatable on a central spindle, each carrying a different mixed alphabet.
 */

const M94_DISCS: readonly string[] = [
  "ABCEIGDJFVUYMHTQKZOLNXWPSR",
  "ACDEHFIJKLMOPQSTUVWXYZBNGR",
  "ADFGJKLMNOQRTUVXYZBCEHIPSW",
  "AFGHKLMNOQRTUVXYZBCDEIJPSW",
  "AGIKLMNOQRTUVXYZBCDEFHJPSW",
  "AHIKLMNOQRTUVXYZBCDEFGJPSW",
  "AIJKLMNOQRTUVXYZBCDEFGHPSW",
  "AKLMNOQRTUVXYZBCDEFGHIJPSW",
  "ALMNOQRTUVXYZBCDEFGHIJKPSW",
  "AMNOQRTUVXYZBCDEFGHIJKLPSW",
  "ANOQRTUVXYZBCDEFGHIJKLMPSW",
  "AOQRTUVXYZBCDEFGHIJKLMNPSW",
  "APQRTUVXYZBCDEFGHIJKLMNOPSW",
  "AQRTUVXYZBCDEFGHIJKLMNPOSW",
  "ARTUVXYZBCDEFGHIJKLMNPQOSW",
  "ASTUVXYZBCDEFGHIJKLMNPQORS",
  "ATUVXYZBCDEFGHIJKLMNPQORSW",
  "AUVXYZBCDEFGHIJKLMNPQORSTW",
  "AVXYZBCDEFGHIJKLMNPQORSTUW",
  "AXYZBCDEFGHIJKLMNPQORSTUVW",
  "AZBCDEFGHIJKLMNPQORSTUVWXY",
  "BCDEFGHIJKLMNOPQRSTUVWXYZAZ",
  "CDEFGHIJKLMNOPQRSTUVWXYZABA",
  "DEFGHIJKLMNOPQRSTUVWXYZABCB",
  "EFGHIJKLMNOPQRSTUVWXYZABCDC",
];

export interface BazeriesOptions {
  offset?: number; // Row offset on the cylinder (1..25)
  direction?: "encrypt" | "decrypt";
}

export function bazeriesCrypt(text: string, options: BazeriesOptions = {}): string {
  const offset = ((options.offset ?? 6) % 26 + 26) % 26;
  const isDecrypt = options.direction === "decrypt";
  const clean = text.toUpperCase();
  let result = "";

  let discIdx = 0;
  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i]!;
    const disc = M94_DISCS[discIdx % M94_DISCS.length]!;
    const pos = disc.indexOf(ch);
    if (pos === -1) {
      result += ch;
      continue;
    }

    const shift = isDecrypt ? (pos - offset + 26) % 26 : (pos + offset) % 26;
    result += disc[shift];
    discIdx++;
  }

  return result;
}
