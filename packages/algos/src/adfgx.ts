/**
 * ADFGX Cipher -- WWI German Army Field Cipher (March 1918).
 *
 * Predecessor to ADFGVX using a 5x5 Polybius grid with coordinates A, D, F, G, X.
 * Letters I and J share a single grid cell.
 */

export interface AdfgxOptions {
  /** Keyword for the 5x5 Polybius grid substitution. */
  gridKey?: string;
  /** Keyword for the columnar transposition stage. */
  transpositionKey?: string;
  direction?: "encrypt" | "decrypt";
}

const HEADERS = ["A", "D", "F", "G", "X"] as const;

export function buildAdfgxSquare(gridKey = ""): string {
  const seen = new Set<string>();
  const clean = (gridKey + "ABCDEFGHIKLMNOPQRSTUVWXYZ").toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
  let square = "";

  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i]!;
    if (!seen.has(ch)) {
      seen.add(ch);
      square += ch;
    }
  }
  return square;
}

export function adfgxEncrypt(text: string, options: AdfgxOptions = {}): string {
  const square = buildAdfgxSquare(options.gridKey ?? "");
  const transKey = (options.transpositionKey ?? "CIPHER").toUpperCase().replace(/[^A-Z]/g, "") || "CIPHER";

  const cleanText = text.toUpperCase().replace(/[^A-Z]/g, "").replace(/J/g, "I");
  if (cleanText.length === 0) return "";

  // Step 1: Polybius fractionating substitution
  let fractionated = "";
  for (let i = 0; i < cleanText.length; i++) {
    const ch = cleanText[i]!;
    const idx = square.indexOf(ch);
    if (idx !== -1) {
      const row = Math.floor(idx / 5);
      const col = idx % 5;
      fractionated += HEADERS[row]! + HEADERS[col]!;
    }
  }

  // Step 2: Columnar Transposition
  const colCount = transKey.length;
  const columns: string[] = Array.from({ length: colCount }, () => "");

  for (let i = 0; i < fractionated.length; i++) {
    columns[i % colCount] += fractionated[i]!;
  }

  // Sort columns by keyword letter order
  const keyWithIndices = transKey.split("").map((ch, idx) => ({ ch, idx }));
  keyWithIndices.sort((a, b) => a.ch.localeCompare(b.ch) || a.idx - b.idx);

  return keyWithIndices.map(({ idx }) => columns[idx]!).join("");
}

export function adfgxDecrypt(ciphertext: string, options: AdfgxOptions = {}): string {
  const square = buildAdfgxSquare(options.gridKey ?? "");
  const transKey = (options.transpositionKey ?? "CIPHER").toUpperCase().replace(/[^A-Z]/g, "") || "CIPHER";

  const cleanCipher = ciphertext.toUpperCase().replace(/[^ADFGX]/g, "");
  if (cleanCipher.length === 0) return "";

  // Step 1: Reverse Columnar Transposition
  const colCount = transKey.length;
  const numRows = Math.floor(cleanCipher.length / colCount);
  const extraCols = cleanCipher.length % colCount;

  const keyWithIndices = transKey.split("").map((ch, idx) => ({ ch, idx }));
  keyWithIndices.sort((a, b) => a.ch.localeCompare(b.ch) || a.idx - b.idx);

  const colLengths: number[] = Array.from({ length: colCount }, (_, idx) =>
    numRows + (idx < extraCols ? 1 : 0),
  );

  const columns: string[] = Array.from({ length: colCount }, () => "");
  let readPos = 0;

  for (const { idx } of keyWithIndices) {
    const len = colLengths[idx]!;
    columns[idx] = cleanCipher.slice(readPos, readPos + len);
    readPos += len;
  }

  // Read row-by-row
  let fractionated = "";
  const maxColLen = Math.ceil(cleanCipher.length / colCount);
  for (let r = 0; r < maxColLen; r++) {
    for (let c = 0; c < colCount; c++) {
      if (r < columns[c]!.length) {
        fractionated += columns[c]![r]!;
      }
    }
  }

  // Step 2: Reverse Polybius substitution
  let plaintext = "";
  for (let i = 0; i < fractionated.length; i += 2) {
    const rChar = fractionated[i]!;
    const cChar = fractionated[i + 1]!;
    const row = HEADERS.indexOf(rChar as (typeof HEADERS)[number]);
    const col = HEADERS.indexOf(cChar as (typeof HEADERS)[number]);
    if (row !== -1 && col !== -1) {
      plaintext += square[row * 5 + col]!;
    }
  }

  return plaintext;
}
