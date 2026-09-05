/**
 * Scytale (Spartan Cylinder Transposition):
 * Ancient Spartan cryptographic staff wrapping transposition cipher.
 */

export function scytaleEncrypt(text: string, diameter = 4): string {
  const d = Math.max(2, diameter);
  const clean = text.replace(/[\r\n]/g, "");
  const numRows = Math.ceil(clean.length / d);

  let result = "";
  for (let c = 0; c < d; c++) {
    for (let r = 0; r < numRows; r++) {
      const idx = r * d + c;
      if (idx < clean.length) {
        result += clean[idx]!;
      }
    }
  }
  return result;
}

export function scytaleDecrypt(text: string, diameter = 4): string {
  const d = Math.max(2, diameter);
  const clean = text.replace(/[\r\n]/g, "");
  const numRows = Math.ceil(clean.length / d);
  const fullCols = clean.length % d === 0 ? d : clean.length % d;

  const grid: string[][] = Array.from({ length: numRows }, () => new Array<string>(d).fill(""));
  let charIdx = 0;

  for (let c = 0; c < d; c++) {
    const colLen = (c < fullCols || clean.length % d === 0) ? numRows : numRows - 1;
    for (let r = 0; r < colLen; r++) {
      if (charIdx < clean.length) {
        grid[r]![c] = clean[charIdx++]!;
      }
    }
  }

  let result = "";
  for (let r = 0; r < numRows; r++) {
    for (let c = 0; c < d; c++) {
      if (grid[r]![c]) {
        result += grid[r]![c]!;
      }
    }
  }
  return result;
}
