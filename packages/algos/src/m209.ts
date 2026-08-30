/**
 * Hagelin M-209 / CSP-1500 Mechanical Cipher Machine Simulator.
 *
 * The M-209 was a portable mechanical cipher machine used by the US military during WWII and the Korean War.
 * It operates with:
 * - 6 Key Wheels with mutually prime lengths: 26, 25, 23, 21, 19, 17.
 * - 27 Drum Bars with 2 movable lugs each (settings 0-6).
 * - Reciprocal ciphering: C = (25 - P + D) mod 26, where D is the count of active lugs.
 */

export interface M209Config {
  /**
   * Starting letter positions of the 6 key wheels (e.g. "AAAAAA").
   */
  rotorPositions?: string;
  /**
   * Active pins for each of the 6 wheels (array of binary strings or 0/1 arrays).
   * Default provides standard factory pin settings.
   */
  pinSettings?: string[];
  /**
   * Drum lugs: array of 27 pairs [lug1, lug2] where 0 means inactive, 1-6 designates wheel.
   */
  drumLugs?: [number, number][];
  /**
   * Direction: 'encrypt' or 'decrypt'. (M-209 is self-reciprocal).
   */
  direction?: "encrypt" | "decrypt";
}

export const M209_WHEEL_SIZES = [26, 25, 23, 21, 19, 17] as const;

export const DEFAULT_M209_PINS: string[] = [
  "11010001000101101000110101", // 26
  "1001010100101100101100100",  // 25
  "10100101001010010010101",    // 23
  "001010010001010100101",      // 21
  "0101010011001010010",        // 19
  "10101010100101010",          // 17
];

export const DEFAULT_M209_LUGS: [number, number][] = [
  [0, 0], [0, 0], [0, 1], [0, 1], [0, 2], [0, 2], [0, 3], [0, 3],
  [0, 4], [0, 4], [0, 5], [0, 5], [0, 6], [0, 6], [1, 2], [1, 3],
  [1, 4], [1, 5], [2, 4], [2, 5], [2, 6], [3, 4], [3, 5], [3, 6],
  [4, 5], [4, 6], [5, 6],
];

export class M209Machine {
  private offsets: number[];
  private readonly pins: boolean[][];
  private readonly lugs: [number, number][];

  constructor(config: M209Config = {}) {
    const pos = (config.rotorPositions ?? "AAAAAA").toUpperCase().padEnd(6, "A").slice(0, 6);
    this.offsets = [0, 0, 0, 0, 0, 0];
    for (let i = 0; i < 6; i++) {
      const code = pos.charCodeAt(i) - 65;
      this.offsets[i] = (code >= 0 && code < 26 ? code : 0) % M209_WHEEL_SIZES[i]!;
    }

    const rawPins = config.pinSettings ?? DEFAULT_M209_PINS;
    this.pins = rawPins.map((pStr, idx) => {
      const size = M209_WHEEL_SIZES[idx]!;
      const arr: boolean[] = [];
      for (let j = 0; j < size; j++) {
        arr.push(pStr[j % pStr.length] === "1");
      }
      return arr;
    });

    this.lugs = config.drumLugs ?? DEFAULT_M209_LUGS;
  }

  /**
   * Process a single character through the machine and advance wheels.
   */
  public step(ch: string): string {
    const upper = ch.toUpperCase();
    const p = upper.charCodeAt(0) - 65;
    if (p < 0 || p >= 26) {
      return ch;
    }

    // Determine which wheels currently have an active pin at the guide
    const activeWheels = [false, false, false, false, false, false, false]; // 0=dummy, 1-6
    for (let i = 0; i < 6; i++) {
      const size = M209_WHEEL_SIZES[i]!;
      const pinActive = this.pins[i]![this.offsets[i]! % size]!;
      if (pinActive) {
        activeWheels[i + 1] = true;
      }
    }

    // Count how many drum bars are pushed (have at least one lug hitting an active wheel pin)
    let displacement = 0;
    for (const [w1, w2] of this.lugs) {
      if ((w1 > 0 && activeWheels[w1]) || (w2 > 0 && activeWheels[w2])) {
        displacement++;
      }
    }

    // M-209 reciprocal cipher formula: C = (25 - P + D) mod 26
    const c = (25 - p + displacement + 2600) % 26;
    const outChar = String.fromCharCode(65 + c);

    // Advance all 6 wheels by 1 position
    for (let i = 0; i < 6; i++) {
      this.offsets[i] = (this.offsets[i]! + 1) % M209_WHEEL_SIZES[i]!;
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

export function m209Crypt(text: string, config: M209Config = {}): string {
  const machine = new M209Machine(config);
  return machine.process(text);
}
