/**
 * The Caesar cipher: every letter moved a fixed number of places along the alphabet.
 *
 * `E(x) = (x + k) mod 26` and `D(x) = (x - k) mod 26`, over the 26 letters of the Latin alphabet and
 * nothing else. It is the simplest cipher there is and the implementation is six lines, so what is
 * worth writing down is the set of decisions *around* it -- because those are where two Caesar tools
 * disagree and produce different answers for the same input and shift.
 *
 * **Only A-Z and a-z shift. Everything else passes through untouched.** Digits, punctuation, spaces,
 * and -- the case worth stating -- letters outside the 26. A Caesar shift over `e-acute` or over a
 * Cyrillic letter is not the Caesar cipher; it is a different scheme defined over a different
 * alphabet, and inventing one silently would make this tool disagree with every published example. The
 * same objection applies to shifting hex digits or bytes: the alphabet is 26 letters, and a tool that
 * quietly extended it would be answering a question nobody asked.
 *
 * **The shift is reduced with a floored modulus, not a truncated one.** JavaScript's `%` keeps the
 * sign of the dividend, so `-3 % 26` is `-3` rather than `23`, and a decryption written as
 * `(x - k) % 26` indexes off the front of the alphabet. `normaliseShift` is the one place that is
 * handled -- the same trap `roadrunner.ts` records for its key cursor, in a much smaller cipher.
 *
 * **Case is preserved by default and can be flattened.** Preserving it is what almost every
 * implementation does and it keeps the transformation reversible on the exact input. Upper-casing is
 * how the classical presentation prints -- `HELLO` to `KHOOR` -- and is offered because that is the
 * form somebody comparing against a textbook has in front of them.
 */

/** The alphabet's size, and the only modulus in here. */
export const CAESAR_ALPHABET = 26;

export type CaesarLetterCase = "preserve" | "upper" | "lower";

export interface CaesarOptions {
  /** Places to move forward. Any integer: reduced modulo 26, negatives included. */
  shift: number;
  /** What to do with the case of each letter. Default `preserve`. */
  letterCase?: CaesarLetterCase;
}

export interface CaesarResult {
  text: string;
  /** How many characters were letters, and therefore actually moved. */
  shifted: number;
  /** How many passed through unchanged. `shifted + passed` is the input's length in code points. */
  passed: number;
}

/**
 * A shift reduced to `[0, 26)`.
 *
 * Exported because it is the one piece of arithmetic here that can be wrong, and the tool reports the
 * reduced value: somebody who types 29 should be told the cipher used 3, not left to work it out.
 */
export function normaliseShift(shift: number): number {
  if (!Number.isFinite(shift)) throw new Error(`Caesar needs a finite shift, got ${shift}`);
  const whole = Math.trunc(shift);
  return ((whole % CAESAR_ALPHABET) + CAESAR_ALPHABET) % CAESAR_ALPHABET;
}

const UPPER_A = 65;
const LOWER_A = 97;

/**
 * Shifts every letter forward by `shift`. Decryption is this with the shift negated.
 *
 * Iterated over code points rather than UTF-16 units, so an astral character -- an emoji, a rarer CJK
 * ideograph -- passes through as one unit instead of being split into a surrogate pair. Neither half of
 * a surrogate is a letter, so a unit-wise loop would happen to produce the right *text*; it would
 * report the wrong count of characters passed through, which is a number this tool puts on screen.
 */
export function caesarShift(text: string, options: CaesarOptions): CaesarResult {
  const shift = normaliseShift(options.shift);
  const letterCase = options.letterCase ?? "preserve";
  let out = "";
  let shifted = 0;
  let passed = 0;

  for (const character of text) {
    const code = character.codePointAt(0)!;
    let base = -1;
    if (code >= UPPER_A && code <= UPPER_A + 25) base = UPPER_A;
    else if (code >= LOWER_A && code <= LOWER_A + 25) base = LOWER_A;

    if (base === -1) {
      out += character;
      passed += 1;
      continue;
    }

    const moved = String.fromCharCode(base + ((code - base + shift) % CAESAR_ALPHABET));
    out += letterCase === "upper" ? moved.toUpperCase() : letterCase === "lower" ? moved.toLowerCase() : moved;
    shifted += 1;
  }

  return { text: out, shifted, passed };
}

/**
 * Every one of the 26 shifts of `text`, indexed by shift.
 *
 * This is what a Caesar tool is actually *for* beyond the arithmetic: 26 keys is a keyspace you read
 * rather than search, so given a ciphertext the answer is in this list and finding it is the whole
 * task. Returned as data rather than formatted here, because the family owns how it is laid out and
 * this package holds no opinion about tables.
 *
 * Index 0 is the input unchanged, which is correct and worth keeping in the list: seeing it there is
 * what tells a reader the table is every shift rather than every shift except the useless one.
 */
export function caesarAllShifts(text: string, letterCase?: CaesarLetterCase): string[] {
  const out: string[] = [];
  for (let shift = 0; shift < CAESAR_ALPHABET; shift++) {
    out.push(caesarShift(text, { shift, letterCase }).text);
  }
  return out;
}
