/**
 * Enigma Machine M3 / M4 Simulation -- WWII German Wehrmacht and Kriegsmarine Electromechanical Cipher.
 *
 * Implements:
 * - Rotors I, II, III, IV, V, VI, VII, VIII, Beta, Gamma with exact historical wiring and notches.
 * - Reflectors: UKW-A, UKW-B, UKW-C, UKW-B Thin, UKW-C Thin.
 * - Ringstellung (ring settings 1..26).
 * - Grundstellung (rotor starting positions A..Z).
 * - Steckerbrett (plugboard letter pairs swap).
 * - Historical mechanical anomaly: Double-stepping of the middle rotor.
 */

export interface RotorWiring {
  name: string;
  wiring: string; // Forward 26-char mapping
  turnoverNotches: string; // Notches that trigger the turnover of the left neighbor
}

export const ENIGMA_ROTORS: Record<string, RotorWiring> = {
  I: { name: "I", wiring: "EKMFLGDQVZNTOWYHXUSPAIBRCJ", turnoverNotches: "Q" },
  II: { name: "II", wiring: "AJDKSIRUXBLHWTMCQGZNPYFVOE", turnoverNotches: "E" },
  III: { name: "III", wiring: "BDFHJLCPRTXVZNYEIWGAKMUSQO", turnoverNotches: "V" },
  IV: { name: "IV", wiring: "ESOVPZJAYQUIRHXLNFTGKDCMWB", turnoverNotches: "J" },
  V: { name: "V", wiring: "VZBRGITYUPSDNHLXAWMJQOFECK", turnoverNotches: "Z" },
  VI: { name: "VI", wiring: "JPGVOUMFYQBENHZRDKASXLICTW", turnoverNotches: "ZM" },
  VII: { name: "VII", wiring: "NZJHGRCXMYSWBOUFAIVLPEKQDT", turnoverNotches: "ZM" },
  VIII: { name: "VIII", wiring: "FKQHTLXOCBJSPDZRAMEWNIUYGV", turnoverNotches: "ZM" },
  Beta: { name: "Beta", wiring: "LEYJVCNIXWPBQMDRTAKZGFUHOS", turnoverNotches: "" },
  Gamma: { name: "Gamma", wiring: "FSOKANUERHMBTIYCWLQPZXVGJD", turnoverNotches: "" },
};

export const ENIGMA_REFLECTORS: Record<string, string> = {
  "UKW-A": "EJMZALYXVBWFCRQUONTSPIKHGD",
  "UKW-B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
  "UKW-C": "FVPJIAOYEDRZXWGCTKUQSBNMHL",
  "UKW-B-Thin": "ENKQAUYWJICOPBLMDXZVFTHRGE",
  "UKW-C-Thin": "RDOBJNTKVEHMLFCWZAXGYQSUIP",
};

export const ENIGMA_DIGIT_HANDLING = ["preserve", "german", "english"] as const;
export type EnigmaDigitHandling = (typeof ENIGMA_DIGIT_HANDLING)[number];

export const GERMAN_ENIGMA_DIGITS: Readonly<Record<string, string>> = {
  "0": "NULL",
  "1": "EINS",
  "2": "ZWEI",
  "3": "DREI",
  "4": "VIER",
  "5": "FUENF",
  "6": "SECHS",
  "7": "SIEBEN",
  "8": "ACHT",
  "9": "NEUN",
};

export const ENGLISH_ENIGMA_DIGITS: Readonly<Record<string, string>> = {
  "0": "ZERO",
  "1": "ONE",
  "2": "TWO",
  "3": "THREE",
  "4": "FOUR",
  "5": "FIVE",
  "6": "SIX",
  "7": "SEVEN",
  "8": "EIGHT",
  "9": "NINE",
};

export interface EnigmaConfig {
  rotors?: string[]; // e.g. ["I", "II", "III"] or ["Beta", "I", "II", "III"]
  reflector?: string; // e.g. "UKW-B"
  positions?: string; // e.g. "AAA" or "AAAA"
  ringSettings?: number[]; // e.g. [1, 1, 1]
  plugboard?: string; // e.g. "AV BS CG DL FU HZ IN KM OW RX"
  digits?: EnigmaDigitHandling; // "preserve" | "german" | "english"
}

export class EnigmaMachine {
  private rotorConfigs: RotorWiring[];
  private reflectorWiring: string;
  private positions: number[];
  private ringSettings: number[];
  private plugboardMap: number[];
  private digitHandling: EnigmaDigitHandling;

  constructor(config: EnigmaConfig = {}) {
    this.digitHandling = config.digits ?? "preserve";
    const rotorNames = config.rotors ?? ["I", "II", "III"];
    this.rotorConfigs = rotorNames.map((name) => {
      const r = ENIGMA_ROTORS[name];
      if (!r) throw new Error(`Unknown Enigma rotor: ${name}`);
      return r;
    });

    const reflName = config.reflector ?? "UKW-B";
    this.reflectorWiring = ENIGMA_REFLECTORS[reflName] ?? ENIGMA_REFLECTORS["UKW-B"]!;

    const posStr = (config.positions ?? "A".repeat(rotorNames.length)).toUpperCase();
    this.positions = [];
    for (let i = 0; i < rotorNames.length; i++) {
      const charCode = (posStr[i] ?? "A").charCodeAt(0) - 65;
      this.positions.push((charCode + 26) % 26);
    }

    const rings = config.ringSettings ?? Array(rotorNames.length).fill(1);
    this.ringSettings = rings.map((r) => (r - 1 + 26) % 26);

    // Initialize plugboard identity
    this.plugboardMap = Array.from({ length: 26 }, (_, i) => i);
    if (config.plugboard) {
      const pairs = config.plugboard.toUpperCase().split(/[^A-Z]+/).filter((p) => p.length === 2);
      for (const pair of pairs) {
        const a = pair.charCodeAt(0) - 65;
        const b = pair.charCodeAt(1) - 65;
        if (a >= 0 && a < 26 && b >= 0 && b < 26) {
          this.plugboardMap[a] = b;
          this.plugboardMap[b] = a;
        }
      }
    }
  }

  private stepRotors() {
    const n = this.positions.length;
    if (n < 3) {
      this.positions[n - 1] = (this.positions[n - 1]! + 1) % 26;
      return;
    }

    // Rightmost rotor index: n - 1, Middle: n - 2, Left: n - 3
    const rightRotor = this.rotorConfigs[n - 1]!;
    const midRotor = this.rotorConfigs[n - 2]!;

    const rightPosChar = String.fromCharCode(65 + this.positions[n - 1]!);
    const midPosChar = String.fromCharCode(65 + this.positions[n - 2]!);

    const rightAtNotch = rightRotor.turnoverNotches.includes(rightPosChar);
    const midAtNotch = midRotor.turnoverNotches.includes(midPosChar);

    // Double stepping mechanism: if middle rotor is at notch, both left and middle step
    if (midAtNotch) {
      this.positions[n - 3] = (this.positions[n - 3]! + 1) % 26;
      this.positions[n - 2] = (this.positions[n - 2]! + 1) % 26;
    } else if (rightAtNotch) {
      this.positions[n - 2] = (this.positions[n - 2]! + 1) % 26;
    }

    // Right rotor always steps on every keypress
    this.positions[n - 1] = (this.positions[n - 1]! + 1) % 26;
  }

  private forwardRotor(c: number, rotorIdx: number): number {
    const rotor = this.rotorConfigs[rotorIdx]!;
    const pos = this.positions[rotorIdx]!;
    const ring = this.ringSettings[rotorIdx]!;

    const shift = (pos - ring + 26) % 26;
    const entry = (c + shift) % 26;
    const charOut = rotor.wiring.charCodeAt(entry) - 65;
    return (charOut - shift + 26) % 26;
  }

  private backwardRotor(c: number, rotorIdx: number): number {
    const rotor = this.rotorConfigs[rotorIdx]!;
    const pos = this.positions[rotorIdx]!;
    const ring = this.ringSettings[rotorIdx]!;

    const shift = (pos - ring + 26) % 26;
    const entry = (c + shift) % 26;
    const charIn = String.fromCharCode(65 + entry);
    const wireIndex = rotor.wiring.indexOf(charIn);
    return (wireIndex - shift + 26) % 26;
  }

  public processChar(ch: string): string {
    const upper = ch.toUpperCase();
    const code = upper.charCodeAt(0) - 65;
    if (code < 0 || code >= 26) return ch; // Pass through non-letters

    // 1. Advance stepping mechanism
    this.stepRotors();

    // 2. Steckerbrett entry
    let signal = this.plugboardMap[code]!;

    // 3. Forward pass through rotors (right to left)
    for (let r = this.positions.length - 1; r >= 0; r--) {
      signal = this.forwardRotor(signal, r);
    }

    // 4. Reflector pass
    const reflChar = this.reflectorWiring.charCodeAt(signal) - 65;
    signal = reflChar;

    // 5. Reverse pass through rotors (left to right)
    for (let r = 0; r < this.positions.length; r++) {
      signal = this.backwardRotor(signal, r);
    }

    // 6. Steckerbrett exit
    signal = this.plugboardMap[signal]!;

    const outChar = String.fromCharCode(65 + signal);
    return ch === ch.toLowerCase() ? outChar.toLowerCase() : outChar;
  }

  public process(text: string): string {
    let input = text;
    if (this.digitHandling === "german") {
      input = input.replace(/[0-9]/g, (d) => GERMAN_ENIGMA_DIGITS[d] ?? d);
    } else if (this.digitHandling === "english") {
      input = input.replace(/[0-9]/g, (d) => ENGLISH_ENIGMA_DIGITS[d] ?? d);
    }

    let result = "";
    for (let i = 0; i < input.length; i++) {
      result += this.processChar(input[i]!);
    }
    return result;
  }
}

export function enigmaCrypt(text: string, config: EnigmaConfig = {}): string {
  const machine = new EnigmaMachine(config);
  return machine.process(text);
}
