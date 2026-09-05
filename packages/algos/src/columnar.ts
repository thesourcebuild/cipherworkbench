/**
 * Columnar Transposition Cipher:
 * Single and Double transposition cipher based on alphabetical key ordering.
 */

function getKeyOrder(key: string): number[] {
  const cleanKey = key.toUpperCase().replace(/[^A-Z]/g, "") || "A";
  const indexed = cleanKey.split("").map((ch, idx) => ({ ch, idx }));
  indexed.sort((a, b) => {
    if (a.ch !== b.ch) return a.ch.localeCompare(b.ch);
    return a.idx - b.idx;
  });
  const order = new Array<number>(cleanKey.length);
  for (let rank = 0; rank < indexed.length; rank++) {
    order[indexed[rank]!.idx] = rank;
  }
  return order;
}

export function columnarTranspositionEncrypt(text: string, key: string): string {
  const cleanText = text.replace(/[\r\n]/g, "");
  const numCols = Math.max(1, key.toUpperCase().replace(/[^A-Z]/g, "").length || 1);
  const order = getKeyOrder(key);
  const numRows = Math.ceil(cleanText.length / numCols);

  // Fill grid
  const grid: string[][] = [];
  let charIdx = 0;
  for (let r = 0; r < numRows; r++) {
    const row: string[] = [];
    for (let c = 0; c < numCols; c++) {
      row.push(charIdx < cleanText.length ? cleanText[charIdx++]! : "X");
    }
    grid.push(row);
  }

  // Read out columns in sorted order
  let result = "";
  for (let rank = 0; rank < numCols; rank++) {
    const colIdx = order.indexOf(rank);
    for (let r = 0; r < numRows; r++) {
      result += grid[r]![colIdx]!;
    }
  }
  return result;
}

export function columnarTranspositionDecrypt(text: string, key: string): string {
  const cleanText = text.replace(/[\r\n]/g, "");
  const numCols = Math.max(1, key.toUpperCase().replace(/[^A-Z]/g, "").length || 1);
  const order = getKeyOrder(key);
  const numRows = Math.ceil(cleanText.length / numCols);

  const grid: string[][] = Array.from({ length: numRows }, () => new Array<string>(numCols).fill(""));
  let charIdx = 0;

  for (let rank = 0; rank < numCols; rank++) {
    const colIdx = order.indexOf(rank);
    for (let r = 0; r < numRows; r++) {
      if (charIdx < cleanText.length) {
        grid[r]![colIdx] = cleanText[charIdx++]!;
      }
    }
  }

  let result = "";
  for (let r = 0; r < numRows; r++) {
    for (let c = 0; c < numCols; c++) {
      result += grid[r]![c]!;
    }
  }
  return result;
}

export function doubleColumnarTranspositionEncrypt(text: string, key1: string, key2: string): string {
  const pass1 = columnarTranspositionEncrypt(text, key1);
  return columnarTranspositionEncrypt(pass1, key2);
}

export function doubleColumnarTranspositionDecrypt(text: string, key1: string, key2: string): string {
  const pass1 = columnarTranspositionDecrypt(text, key2);
  return columnarTranspositionDecrypt(pass1, key1);
}
