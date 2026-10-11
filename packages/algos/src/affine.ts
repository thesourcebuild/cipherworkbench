/** Affine substitution over the 26 ASCII letters: E(x) = (ax + b) mod 26. */

export interface AffineOptions {
  multiplier: number;
  offset: number;
}

const ALPHABET_SIZE = 26;

function modulo(value: number, modulus: number): number {
  return ((value % modulus) + modulus) % modulus;
}

function gcd(a: number, b: number): number {
  let x = Math.abs(a);
  let y = Math.abs(b);
  while (y !== 0) [x, y] = [y, x % y];
  return x;
}

function validateOptions(options: AffineOptions): { multiplier: number; offset: number } {
  if (!Number.isInteger(options.multiplier) || !Number.isInteger(options.offset)) {
    throw new Error("Affine multiplier and offset must be integers.");
  }
  const multiplier = modulo(options.multiplier, ALPHABET_SIZE);
  const offset = modulo(options.offset, ALPHABET_SIZE);
  if (gcd(multiplier, ALPHABET_SIZE) !== 1) {
    throw new Error(`Affine multiplier ${options.multiplier} is not coprime with 26.`);
  }
  return { multiplier, offset };
}

function inverseModulo(value: number): number {
  for (let candidate = 1; candidate < ALPHABET_SIZE; candidate++) {
    if ((value * candidate) % ALPHABET_SIZE === 1) return candidate;
  }
  throw new Error(`Affine multiplier ${value} has no inverse modulo 26.`);
}

function transform(text: string, multiplier: number, offset: number): string {
  let output = "";
  for (const character of text) {
    const code = character.codePointAt(0)!;
    const base = code >= 65 && code <= 90 ? 65 : code >= 97 && code <= 122 ? 97 : -1;
    output +=
      base === -1
        ? character
        : String.fromCharCode(
            base + modulo(multiplier * (code - base) + offset, ALPHABET_SIZE),
          );
  }
  return output;
}

export function affineEncrypt(text: string, options: AffineOptions): string {
  const { multiplier, offset } = validateOptions(options);
  return transform(text, multiplier, offset);
}

export function affineDecrypt(text: string, options: AffineOptions): string {
  const { multiplier, offset } = validateOptions(options);
  const inverse = inverseModulo(multiplier);
  return transform(text, inverse, -inverse * offset);
}
