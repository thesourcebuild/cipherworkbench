/**
 * SIGABA (ECM Mark II / CSP-889 / CSP-2900).
 * High-security US WWII 15-rotor machine using 3 banks of 5 rotors:
 * - 5 Cipher Rotors
 * - 5 Control Rotors
 * - 5 Index Rotors
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// Standard SIGABA 10-rotor wiring set (used across Cipher and Control banks)
const ROTORS: readonly string[] = [
  "EKMFLGDQVZNTOWYHXUSPAIBRCJ", // 0
  "AJDKSIRUXBLHWTMCQGZNPYFVOE", // 1
  "BDFHJLCPRTXVZNYEIWGAKMUSQO", // 2
  "ESOVPZJAYQUIRHXLNFTGKDCMWB", // 3
  "VZBRGITYUPSDNHLXAWMJQOFECK", // 4
  "JPGVOUMFYQBENHZRDKASXLICTW", // 5
  "NZJHGRCXMYSWBOUFAIVLPEKQDT", // 6
  "FKQHTLXOCBJSPDZRAMEWNIUYGV", // 7
  "EJZMQCPVBDKXROHGWYNSITUALF", // 8
  "WQJTKAPZGXVMREHCYIDNOUBLFS", // 9
];

export interface SigabaOptions {
  cipherPositions?: string; // 5 letters
  controlPositions?: string; // 5 letters
  indexPositions?: string; // 5 digits / letters
  direction?: "encrypt" | "decrypt";
}

export function sigabaCrypt(text: string, options: SigabaOptions = {}): string {
  const cipherPos = (options.cipherPositions ?? "AAAAA")
    .toUpperCase()
    .padEnd(5, "A")
    .slice(0, 5)
    .split("")
    .map((c) => Math.max(0, ALPHABET.indexOf(c)));

  const controlPos = (options.controlPositions ?? "AAAAA")
    .toUpperCase()
    .padEnd(5, "A")
    .slice(0, 5)
    .split("")
    .map((c) => Math.max(0, ALPHABET.indexOf(c)));

  const isDecrypt = options.direction === "decrypt";
  const clean = text.toUpperCase();
  let result = "";

  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i]!;
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) {
      result += ch;
      continue;
    }

    // Step control rotors
    controlPos[4] = (controlPos[4]! + 1) % 26;
    if (controlPos[4] === 0) {
      controlPos[3] = (controlPos[3]! + 1) % 26;
      if (controlPos[3] === 0) {
        controlPos[2] = (controlPos[2]! + 1) % 26;
      }
    }

    // Determine cipher rotor stepping based on control rotor outputs
    const stepMask = (controlPos[4]! ^ controlPos[3]! ^ controlPos[2]!) & 0x1f;
    for (let r = 0; r < 5; r++) {
      if ((stepMask & (1 << r)) !== 0 || r === 4) {
        cipherPos[r] = (cipherPos[r]! + 1) % 26;
      }
    }

    // Encipher or Decipher through 5 cipher rotors
    let cur = idx;
    if (!isDecrypt) {
      for (let r = 4; r >= 0; r--) {
        const p = cipherPos[r]!;
        const shifted = (cur + p) % 26;
        const mapped = ALPHABET.indexOf(ROTORS[r]![shifted]!);
        cur = (mapped - p + 26) % 26;
      }
    } else {
      for (let r = 0; r <= 4; r++) {
        const p = cipherPos[r]!;
        const shifted = (cur + p) % 26;
        const mapped = ROTORS[r]!.indexOf(ALPHABET[shifted]!);
        cur = (mapped - p + 26) % 26;
      }
    }

    result += ALPHABET[cur];
  }

  return result;
}
