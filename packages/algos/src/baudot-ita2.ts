/**
 * Baudot ITA2 (International Telegraph Alphabet No. 2) Encoding and Decoding.
 * 5-level teleprinter code using LTRS (Letters) and FIGS (Figures) shift states.
 */

const LTRS_TABLE: Record<number, string> = {
  0b00000: "", // Blank / Null
  0b00100: " ",
  0b11000: "A",
  0b10011: "B",
  0b01110: "C",
  0b10010: "D",
  0b10000: "E",
  0b10110: "F",
  0b01011: "G",
  0b00101: "H",
  0b01100: "I",
  0b11010: "J",
  0b11110: "K",
  0b01001: "L",
  0b00111: "M",
  0b00110: "N",
  0b00011: "O",
  0b01101: "P",
  0b11101: "Q",
  0b01010: "R",
  0b10100: "S",
  0b00001: "T",
  0b11100: "U",
  0b01111: "V",
  0b11001: "W",
  0b10111: "X",
  0b10101: "Y",
  0b10001: "Z",
  0b01000: "\r",
  0b00010: "\n",
};

const FIGS_TABLE: Record<number, string> = {
  0b00000: "",
  0b00100: " ",
  0b11000: "-",
  0b10011: "?",
  0b01110: ":",
  0b10010: "$",
  0b10000: "3",
  0b10110: "!",
  0b01011: "&",
  0b00101: "#",
  0b01100: "8",
  0b11010: "'",
  0b11110: "(",
  0b01001: ")",
  0b00111: ".",
  0b00110: ",",
  0b00011: "9",
  0b01101: "0",
  0b11101: "1",
  0b01010: "4",
  0b10100: "'",
  0b00001: "5",
  0b11100: "7",
  0b01111: "=",
  0b11001: "2",
  0b10111: "/",
  0b10101: "6",
  0b10001: "+",
  0b01000: "\r",
  0b00010: "\n",
};

const CODE_LTRS = 0b11111;
const CODE_FIGS = 0b11011;

export function encodeBaudotIta2(text: string): Uint8Array {
  const clean = text.toUpperCase();
  const codes: number[] = [];
  let isFigs = false;

  const charToLtrs: Record<string, number> = {};
  for (const [codeStr, ch] of Object.entries(LTRS_TABLE)) {
    if (ch) charToLtrs[ch] = Number(codeStr);
  }

  const charToFigs: Record<string, number> = {};
  for (const [codeStr, ch] of Object.entries(FIGS_TABLE)) {
    if (ch) charToFigs[ch] = Number(codeStr);
  }

  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i]!;
    if (ch in charToLtrs) {
      if (isFigs) {
        codes.push(CODE_LTRS);
        isFigs = false;
      }
      codes.push(charToLtrs[ch]!);
    } else if (ch in charToFigs) {
      if (!isFigs) {
        codes.push(CODE_FIGS);
        isFigs = true;
      }
      codes.push(charToFigs[ch]!);
    }
  }

  return new Uint8Array(codes);
}

export function decodeBaudotIta2(codes: Uint8Array): string {
  let result = "";
  let isFigs = false;

  for (let i = 0; i < codes.length; i++) {
    const c = codes[i]! & 0x1f;
    if (c === CODE_LTRS) {
      isFigs = false;
    } else if (c === CODE_FIGS) {
      isFigs = true;
    } else {
      const ch = isFigs ? FIGS_TABLE[c] : LTRS_TABLE[c];
      if (ch) result += ch;
    }
  }

  return result;
}
