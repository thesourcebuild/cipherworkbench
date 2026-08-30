/**
 * Trifid Cipher -- Félix Delastelle's 3-Coordinate Fractionating Classical Cipher (1901).
 *
 * Implements:
 * - 3x3x3 27-symbol cube (A-Z plus '#').
 * - 3D coordinate fractionating transposition by period blocks.
 * - Bidirectional encryption / decryption.
 */

export interface TrifidOptions {
  key?: string;
  period?: number; // Block length (default 5)
}

const DEFAULT_TRIFID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ#";

function getTrifidCube(key: string = ""): string[][][] {
  const cleanKey = (key + DEFAULT_TRIFID_ALPHABET).toUpperCase().replace(/[^A-Z#]/g, "");
  const seen = new Set<string>();
  const alphabet: string[] = [];

  for (const ch of cleanKey) {
    if (!seen.has(ch)) {
      seen.add(ch);
      alphabet.push(ch);
    }
  }

  const cube: string[][][] = [];
  let idx = 0;
  for (let l = 0; l < 3; l++) {
    const layer: string[][] = [];
    for (let r = 0; r < 3; r++) {
      layer.push(alphabet.slice(idx, idx + 3));
      idx += 3;
    }
    cube.push(layer);
  }
  return cube;
}

function findCubeCoords(cube: string[][][], ch: string): [number, number, number] {
  for (let l = 0; l < 3; l++) {
    for (let r = 0; r < 3; r++) {
      for (let c = 0; c < 3; c++) {
        if (cube[l]![r]![c] === ch) return [l + 1, r + 1, c + 1];
      }
    }
  }
  return [1, 1, 1];
}

export function trifidEncrypt(text: string, options: TrifidOptions = {}): string {
  const period = options.period ?? 5;
  const cube = getTrifidCube(options.key ?? "TRIFID");
  const clean = text.toUpperCase().replace(/[^A-Z#]/g, "");

  let result = "";
  for (let p = 0; p < clean.length; p += period) {
    const block = clean.slice(p, p + period);
    const layers: number[] = [];
    const rows: number[] = [];
    const cols: number[] = [];

    for (const ch of block) {
      const [l, r, c] = findCubeCoords(cube, ch);
      layers.push(l);
      rows.push(r);
      cols.push(c);
    }

    const combined = [...layers, ...rows, ...cols];
    for (let i = 0; i < combined.length; i += 3) {
      const l = combined[i]! - 1;
      const r = combined[i + 1]! - 1;
      const c = combined[i + 2]! - 1;
      result += cube[l]![r]![c]!;
    }
  }

  return result;
}

export function trifidDecrypt(text: string, options: TrifidOptions = {}): string {
  const period = options.period ?? 5;
  const cube = getTrifidCube(options.key ?? "TRIFID");
  const clean = text.toUpperCase().replace(/[^A-Z#]/g, "");

  let result = "";
  for (let p = 0; p < clean.length; p += period) {
    const block = clean.slice(p, p + period);
    const combined: number[] = [];

    for (const ch of block) {
      const [l, r, c] = findCubeCoords(cube, ch);
      combined.push(l, r, c);
    }

    const n = block.length;
    const layers = combined.slice(0, n);
    const rows = combined.slice(n, n * 2);
    const cols = combined.slice(n * 2);

    for (let i = 0; i < n; i++) {
      const l = layers[i]! - 1;
      const r = rows[i]! - 1;
      const c = cols[i]! - 1;
      result += cube[l]![r]![c]!;
    }
  }

  return result;
}
