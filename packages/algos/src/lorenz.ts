/**
 * Lorenz SZ40 / SZ42 Teleprinter Cipher Machine Simulator.
 *
 * Used by the German High Command (OKW) in WWII for strategic teleprinter communications.
 * Contains 12 cam wheels:
 * - 5 Chi (χ) wheels (sizes 41, 31, 29, 26, 23) - regular stepping
 * - 2 Motor (μ) wheels (sizes 61, 37) - μ61 steps regularly, μ37 steps when μ61 has active cam
 * - 5 Psi (ψ) wheels (sizes 43, 47, 51, 53, 59) - step irregularly when μ37 has active cam
 *
 * Input: standard text / ITA2 Baudot letters (5 bits per character).
 */

export const LORENZ_CHI_SIZES = [41, 31, 29, 26, 23] as const;
export const LORENZ_MU_SIZES = [61, 37] as const;
export const LORENZ_PSI_SIZES = [43, 47, 51, 53, 59] as const;

export interface LorenzConfig {
  /** 12-letter initial wheel positions (5 Chi, 2 Mu, 5 Psi). Default: all 'A'. */
  wheelPositions?: string;
  /** Optional custom pin/cam patterns for the 12 wheels. */
  camPatterns?: {
    chi?: string[];
    mu?: string[];
    psi?: string[];
  };
  direction?: "encrypt" | "decrypt";
}

// Standard historical SZ40/SZ42 default cam patterns
export const DEFAULT_CHI_CAMS: string[] = [
  "10101010101010101010101010101010101010101", // 41
  "1010101010101010101010101010101",           // 31
  "10101010101010101010101010101",             // 29
  "10101010101010101010101010",                 // 26
  "10101010101010101010101",                   // 23
];

export const DEFAULT_MU_CAMS: string[] = [
  "1001001001001001001001001001001001001001001001001001001001001", // 61
  "1010101010101010101010101010101010101",                         // 37
];

export const DEFAULT_PSI_CAMS: string[] = [
  "1010101010101010101010101010101010101010101", // 43
  "10101010101010101010101010101010101010101010101", // 47
  "101010101010101010101010101010101010101010101010101", // 51
  "101010101010101010101010101010101010101010101010101010", // 53
  "10101010101010101010101010101010101010101010101010101010101", // 59
];

// ITA2 / Baudot 5-bit character encoding table for letters A-Z (0-31 representation)
export const ITA2_LETTERS: Record<string, number> = {
  E: 1,  // 00001
  T: 2,  // 00010
  A: 3,  // 00011
  O: 4,  // 00100
  S: 5,  // 00101
  I: 6,  // 00110
  N: 7,  // 00111
  U: 8,  // 01000
  R: 10, // 01010
  D: 11, // 01011
  H: 12, // 01100
  L: 13, // 01101
  C: 14, // 01110
  M: 15, // 01111
  P: 16, // 10000
  Q: 17, // 10001
  G: 18, // 10010
  I_ALT: 19,
  B: 20, // 10100
  Z: 21, // 10101
  Y: 22, // 10110
  F: 23, // 10111
  X: 24, // 11000
  V: 25, // 11001
  W: 26, // 11010
  J: 27, // 11011
  K: 30, // 11110
};

export class LorenzMachine {
  private chiPos: number[];
  private muPos: number[];
  private psiPos: number[];

  private chiCams: boolean[][];
  private muCams: boolean[][];
  private psiCams: boolean[][];

  constructor(config: LorenzConfig = {}) {
    const rawPos = (config.wheelPositions ?? "AAAAAAAAAAAA").toUpperCase().padEnd(12, "A").slice(0, 12);
    this.chiPos = [0, 0, 0, 0, 0];
    for (let i = 0; i < 5; i++) {
      this.chiPos[i] = (rawPos.charCodeAt(i) - 65) % LORENZ_CHI_SIZES[i]!;
    }
    this.muPos = [0, 0];
    for (let i = 0; i < 2; i++) {
      this.muPos[i] = (rawPos.charCodeAt(5 + i) - 65) % LORENZ_MU_SIZES[i]!;
    }
    this.psiPos = [0, 0, 0, 0, 0];
    for (let i = 0; i < 5; i++) {
      this.psiPos[i] = (rawPos.charCodeAt(7 + i) - 65) % LORENZ_PSI_SIZES[i]!;
    }

    const cCams = config.camPatterns?.chi ?? DEFAULT_CHI_CAMS;
    this.chiCams = cCams.map((s, idx) => {
      const len = LORENZ_CHI_SIZES[idx]!;
      return Array.from({ length: len }, (_, j) => s[j % s.length] === "1");
    });

    const mCams = config.camPatterns?.mu ?? DEFAULT_MU_CAMS;
    this.muCams = mCams.map((s, idx) => {
      const len = LORENZ_MU_SIZES[idx]!;
      return Array.from({ length: len }, (_, j) => s[j % s.length] === "1");
    });

    const pCams = config.camPatterns?.psi ?? DEFAULT_PSI_CAMS;
    this.psiCams = pCams.map((s, idx) => {
      const len = LORENZ_PSI_SIZES[idx]!;
      return Array.from({ length: len }, (_, j) => s[j % s.length] === "1");
    });
  }

  /**
   * Process a single character and step the 12 wheels according to SZ42 motor logic.
   */
  public step(ch: string): string {
    const upper = ch.toUpperCase();
    const code = upper.charCodeAt(0) - 65;
    if (code < 0 || code >= 26) {
      return ch;
    }

    // Generate 5-bit keystream K = Chi XOR Psi
    let chiBits = 0;
    for (let i = 0; i < 5; i++) {
      const bit = this.chiCams[i]![this.chiPos[i]! % LORENZ_CHI_SIZES[i]!] ? 1 : 0;
      chiBits |= bit << i;
    }

    let psiBits = 0;
    for (let i = 0; i < 5; i++) {
      const bit = this.psiCams[i]![this.psiPos[i]! % LORENZ_PSI_SIZES[i]!] ? 1 : 0;
      psiBits |= bit << i;
    }

    const key5 = chiBits ^ psiBits;

    // Direct alphabetic Vernam stream addition modulo 26
    const outCode = (code ^ key5) % 26;
    const outChar = String.fromCharCode(65 + outCode);

    // Motor Stepping Rules:
    // 1. Chi wheels always advance 1 position
    for (let i = 0; i < 5; i++) {
      this.chiPos[i] = (this.chiPos[i]! + 1) % LORENZ_CHI_SIZES[i]!;
    }

    // 2. Mu61 always advances 1 position
    const mu61Active = this.muCams[0]![this.muPos[0]! % LORENZ_MU_SIZES[0]!];
    this.muPos[0] = (this.muPos[0]! + 1) % LORENZ_MU_SIZES[0]!;

    // 3. Mu37 advances if Mu61 cam was active
    let mu37Active = false;
    if (mu61Active) {
      mu37Active = !!this.muCams[1]![this.muPos[1]! % LORENZ_MU_SIZES[1]!];
      this.muPos[1] = (this.muPos[1]! + 1) % LORENZ_MU_SIZES[1]!;
    }

    // 4. Psi wheels advance together if Mu37 was active
    if (mu37Active) {
      for (let i = 0; i < 5; i++) {
        this.psiPos[i] = (this.psiPos[i]! + 1) % LORENZ_PSI_SIZES[i]!;
      }
    }

    return ch === ch.toLowerCase() ? outChar.toLowerCase() : outChar;
  }

  public process(text: string): string {
    let out = "";
    for (let i = 0; i < text.length; i++) {
      out += this.step(text[i]!);
    }
    return out;
  }
}

export function lorenzCrypt(text: string, config: LorenzConfig = {}): string {
  const machine = new LorenzMachine(config);
  return machine.process(text);
}
