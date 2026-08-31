/**
 * Typex (British WWII Cipher Machine).
 * 5-rotor machine based on commercial Enigma with a stationary reversing stator
 * and multiple stepping notches per rotor.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

// Typex Standard Rotors
const TYPEX_ROTORS: Record<string, string> = {
  I: "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
  II: "AJDKSIRUXBLHWTMCQGZNPYFVOE",
  III: "BDFHJLCPRTXVZNYEIWGAKMUSQO",
  IV: "ESOVPZJAYQUIRHXLNFTGKDCMWB",
  V: "VZBRGITYUPSDNHLXAWMJQOFECK",
};

const TYPEX_REFLECTORS: Record<string, string> = {
  A: "EJMZALYXVBWFCRQUONTSPIKHGD",
  B: "YRUHQSLDPXNGOKMIEBFZCWVJAT",
};

export interface TypexOptions {
  rotors?: [string, string, string, string, string];
  reflector?: string;
  positions?: string; // 5 uppercase letters, e.g. "AAAAA"
  direction?: "encrypt" | "decrypt";
}

export function typexCrypt(text: string, options: TypexOptions = {}): string {
  const rotorKeys = options.rotors ?? ["I", "II", "III", "IV", "V"];
  const refKey = options.reflector ?? "A";
  const posStr = (options.positions ?? "AAAAA").toUpperCase().padEnd(5, "A").slice(0, 5);

  const wiring = rotorKeys.map((k) => TYPEX_ROTORS[k] ?? TYPEX_ROTORS.I!);
  const reflector = TYPEX_REFLECTORS[refKey] ?? TYPEX_REFLECTORS.A!;
  const pos = posStr.split("").map((c) => Math.max(0, ALPHABET.indexOf(c)));

  const clean = text.toUpperCase();
  let result = "";

  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i]!;
    const idx = ALPHABET.indexOf(ch);
    if (idx === -1) {
      result += ch;
      continue;
    }

    // Step rotors 3, 4, 5 (rightmost rotors)
    pos[4] = (pos[4]! + 1) % 26;
    if (pos[4] === 0) {
      pos[3] = (pos[3]! + 1) % 26;
      if (pos[3] === 0) {
        pos[2] = (pos[2]! + 1) % 26;
      }
    }

    // Forward through 5 rotors
    let cur = idx;
    for (let r = 4; r >= 0; r--) {
      const p = pos[r]!;
      const shifted = (cur + p) % 26;
      const mapped = ALPHABET.indexOf(wiring[r]![shifted]!);
      cur = (mapped - p + 26) % 26;
    }

    // Reflector
    cur = ALPHABET.indexOf(reflector[cur]!);

    // Reverse through 5 rotors
    for (let r = 0; r <= 4; r++) {
      const p = pos[r]!;
      const shifted = (cur + p) % 26;
      const mapped = wiring[r]!.indexOf(ALPHABET[shifted]!);
      cur = (mapped - p + 26) % 26;
    }

    result += ALPHABET[cur];
  }

  return result;
}
