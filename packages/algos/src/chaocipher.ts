/**
 * Chaocipher -- Dynamic Two-Rotor Permutation Cipher (John F. Byrne, 1918).
 *
 * Simulates the mechanical action of two revolving alphabetic wheels (Left and Right)
 * with dynamic permutation after each enciphered character.
 */

export const DEFAULT_CHAOCIPHER_LEFT = "HXUCZVAMDSLKPEJRIGTWFOBNYQ";
export const DEFAULT_CHAOCIPHER_RIGHT = "PTLNBQDEOYSFAVZKGJRIHWXUMC";

export function permuteLeftDisk(disk: string[], index: number): void {
  // Rotate disk so index letter is at zenith (position 0)
  const rotated = disk.slice(index).concat(disk.slice(0, index));
  // Extract letter at position 1 and insert at nadir (position 13)
  const extracted = rotated.splice(1, 1)[0]!;
  rotated.splice(13, 0, extracted);
  for (let i = 0; i < 26; i++) {
    disk[i] = rotated[i]!;
  }
}

export function permuteRightDisk(disk: string[], index: number): void {
  // Rotate disk so index letter is at zenith + 1 (position 1)
  const rotateAmount = (index + 1) % 26;
  const rotated = disk.slice(rotateAmount).concat(disk.slice(0, rotateAmount));
  // Extract letter at position 2 and insert at nadir (position 13)
  const extracted = rotated.splice(2, 1)[0]!;
  rotated.splice(13, 0, extracted);
  for (let i = 0; i < 26; i++) {
    disk[i] = rotated[i]!;
  }
}

export function chaoEncrypt(
  plaintext: string,
  leftAlphabet: string = DEFAULT_CHAOCIPHER_LEFT,
  rightAlphabet: string = DEFAULT_CHAOCIPHER_RIGHT,
): string {
  const left = leftAlphabet.toUpperCase().split("");
  const right = rightAlphabet.toUpperCase().split("");
  const clean = plaintext.toUpperCase().replace(/[^A-Z]/g, "");

  let ciphertext = "";
  for (const ch of clean) {
    const rIdx = right.indexOf(ch);
    if (rIdx === -1) continue;

    // Encipher: right letter maps directly across to left letter
    const cipherChar = left[rIdx]!;
    ciphertext += cipherChar;

    // Permute wheels
    permuteLeftDisk(left, rIdx);
    permuteRightDisk(right, rIdx);
  }

  return ciphertext;
}

export function chaoDecrypt(
  ciphertext: string,
  leftAlphabet: string = DEFAULT_CHAOCIPHER_LEFT,
  rightAlphabet: string = DEFAULT_CHAOCIPHER_RIGHT,
): string {
  const left = leftAlphabet.toUpperCase().split("");
  const right = rightAlphabet.toUpperCase().split("");
  const clean = ciphertext.toUpperCase().replace(/[^A-Z]/g, "");

  let plaintext = "";
  for (const ch of clean) {
    const lIdx = left.indexOf(ch);
    if (lIdx === -1) continue;

    // Decipher: left letter maps directly across to right letter
    const plainChar = right[lIdx]!;
    plaintext += plainChar;

    // Permute wheels
    permuteLeftDisk(left, lIdx);
    permuteRightDisk(right, lIdx);
  }

  return plaintext;
}
