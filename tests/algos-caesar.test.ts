import { describe, expect, it } from "vitest";

import {
  CAESAR_ALPHABET,
  caesarAllShifts,
  caesarShift,
  normaliseShift,
} from "../packages/algos/src/caesar";

/**
 * The Caesar cipher, and what there is to test in six lines of arithmetic.
 *
 * Not the arithmetic. `(x + k) mod 26` is not where a Caesar implementation goes wrong -- the published
 * examples below would catch that immediately, and they are the first thing anybody tries. What goes
 * wrong is everything *around* it, and each of those has a test here:
 *
 *  - the sign of the modulus, because JavaScript's `%` keeps the sign of the dividend, so a decryption
 *    written as `(x - k) % 26` indexes off the front of the alphabet for every k above x;
 *  - which characters are in the alphabet, because a tool that shifted digits or accented letters
 *    would disagree with every published example while looking perfectly reasonable;
 *  - and the counts the tool puts on screen, which are the only part a wrong loop would report wrongly
 *    while still producing the right text.
 */

describe("caesarShift", () => {
  /** The examples from every description of this cipher, including the one that prompted the tool. */
  it("reproduces the classical examples", () => {
    expect(caesarShift("HELLO", { shift: 3 }).text).toBe("KHOOR");
    expect(caesarShift("HELLO", { shift: 5 }).text).toBe("MJQQT");
    // And the individual letters the description spells out: A to D, X to A, Y to B, Z to C.
    expect(caesarShift("ABCXYZ", { shift: 3 }).text).toBe("DEFABC");
  });

  it("decrypts by negating the shift", () => {
    expect(caesarShift("KHOOR", { shift: -3 }).text).toBe("HELLO");
    expect(caesarShift("MJQQT", { shift: -5 }).text).toBe("HELLO");
  });

  /**
   * The negative modulus, which is the one arithmetic trap in this file.
   *
   * `-3 % 26` is `-3` in JavaScript, not `23`. An implementation using the remainder directly produces
   * a character below `A` for every letter whose position is under the shift -- so `A` shifted back 3
   * would land three code points before `A`, which is `>`. Asserting the character rather than only
   * the round trip is what catches it: a round trip through the same broken arithmetic can still
   * cancel out.
   */
  it("wraps rather than running off the front of the alphabet", () => {
    expect(caesarShift("ABC", { shift: -3 }).text).toBe("XYZ");
    expect(caesarShift("A", { shift: -1 }).text).toBe("Z");
    expect(caesarShift("abc", { shift: -3 }).text).toBe("xyz");
    // No character outside A-Z can appear in the output of an all-letters input.
    for (let shift = -100; shift <= 100; shift++) {
      expect(caesarShift("ABCDEFGHIJKLMNOPQRSTUVWXYZ", { shift }).text).toMatch(/^[A-Z]{26}$/);
    }
  });

  it("is the identity at 0 and at any multiple of 26", () => {
    for (const shift of [0, 26, 52, -26, -52, 260]) {
      expect(caesarShift("Attack at dawn!", { shift }).text, `shift ${shift}`).toBe("Attack at dawn!");
    }
  });

  /**
   * A shift of 13 is its own inverse, which the tool states in two places and so is worth pinning.
   *
   * Half of 26, so applying it twice returns the input -- and encryption and decryption are the same
   * operation, which is the one surprising consequence and the thing `X003` exists to say.
   */
  it("is its own inverse at 13", () => {
    const once = caesarShift("Spoiler ahead", { shift: 13 }).text;
    expect(once).toBe("Fcbvyre nurnq");
    expect(caesarShift(once, { shift: 13 }).text).toBe("Spoiler ahead");
    expect(caesarShift("Spoiler ahead", { shift: -13 }).text).toBe(once);
  });

  it("round-trips every shift over a mixed-case alphabet", () => {
    const message = "The Quick Brown Fox Jumps Over The Lazy Dog";
    for (let shift = 0; shift < CAESAR_ALPHABET; shift++) {
      const enciphered = caesarShift(message, { shift }).text;
      expect(caesarShift(enciphered, { shift: -shift }).text, `shift ${shift}`).toBe(message);
    }
  });

  /**
   * The alphabet is 26 letters and nothing else, which is the claim the tool's Info panel makes.
   *
   * Digits, punctuation and whitespace pass through because they are not letters. An accented letter
   * passes through for a subtler reason worth asserting separately: it *is* a letter, and shifting it
   * would mean choosing an alphabet -- which is a different cipher, not this one. Same for Cyrillic and
   * for Greek.
   */
  it("touches only A-Z and a-z", () => {
    expect(caesarShift("abc XYZ 123 !?", { shift: 1 }).text).toBe("bcd YZA 123 !?");
    // Letters outside the 26, left exactly as they are.
    for (const outside of ["é", "ñ", "Ω", "Д", "中", "ß"]) {
      expect(caesarShift(outside, { shift: 5 }).text, outside).toBe(outside);
    }
    // And a full stop is not a letter even though `.` sits near the letters in ASCII.
    expect(caesarShift("a.z", { shift: 1 }).text).toBe("b.a");
  });

  it("preserves case by default and can flatten it either way", () => {
    expect(caesarShift("Hello, World!", { shift: 3 }).text).toBe("Khoor, Zruog!");
    expect(caesarShift("Hello, World!", { shift: 3, letterCase: "upper" }).text).toBe(
      "KHOOR, ZRUOG!",
    );
    expect(caesarShift("Hello, World!", { shift: 3, letterCase: "lower" }).text).toBe(
      "khoor, zruog!",
    );
    // Flattening touches only the letters that moved: the comma and the exclamation stay put.
    expect(caesarShift("A!", { shift: 0, letterCase: "lower" }).text).toBe("a!");
  });

  /**
   * The counts, which the tool reports and which a unit-wise loop would get wrong.
   *
   * Iterating UTF-16 units rather than code points splits an astral character into a surrogate pair.
   * Neither half is a letter, so the *text* would come out right -- and `passed` would be one too many,
   * which is a number this tool puts on screen.
   */
  it("counts letters moved and characters passed through", () => {
    const plain = caesarShift("abc 12!", { shift: 1 });
    expect(plain.shifted).toBe(3);
    expect(plain.passed).toBe(4);

    const astral = caesarShift("a🙂b", { shift: 1 });
    expect(astral.text).toBe("b🙂c");
    expect(astral.shifted).toBe(2);
    // One, not two: the emoji is a single code point even though it is two UTF-16 units.
    expect(astral.passed).toBe(1);
  });

  it("handles an empty input", () => {
    const empty = caesarShift("", { shift: 7 });
    expect(empty).toEqual({ text: "", shifted: 0, passed: 0 });
  });
});

describe("normaliseShift", () => {
  it("reduces into [0, 26) with a floored modulus", () => {
    expect(normaliseShift(0)).toBe(0);
    expect(normaliseShift(3)).toBe(3);
    expect(normaliseShift(26)).toBe(0);
    expect(normaliseShift(29)).toBe(3);
    // The cases JavaScript's own `%` gets wrong for this purpose.
    expect(normaliseShift(-1)).toBe(25);
    expect(normaliseShift(-3)).toBe(23);
    expect(normaliseShift(-26)).toBe(0);
    expect(normaliseShift(-29)).toBe(23);
  });

  it("truncates a fractional shift rather than producing a fractional offset", () => {
    expect(normaliseShift(3.7)).toBe(3);
    expect(normaliseShift(-3.7)).toBe(23);
  });

  it("refuses a shift that is not a number", () => {
    expect(() => normaliseShift(Number.NaN)).toThrow(/finite shift/);
    expect(() => normaliseShift(Number.POSITIVE_INFINITY)).toThrow(/finite shift/);
  });
});

describe("caesarAllShifts", () => {
  it("returns 26 rows, indexed by shift, starting with the input unchanged", () => {
    const all = caesarAllShifts("HELLO");
    expect(all).toHaveLength(CAESAR_ALPHABET);
    // Index 0 is the input, which is what makes this "every shift" rather than "every useful shift".
    expect(all[0]).toBe("HELLO");
    expect(all[3]).toBe("KHOOR");
    expect(all[5]).toBe("MJQQT");
    // Row k is the same as asking for shift k directly -- the table cannot drift from the cipher.
    for (let shift = 0; shift < CAESAR_ALPHABET; shift++) {
      expect(all[shift], `row ${shift}`).toBe(caesarShift("HELLO", { shift }).text);
    }
  });

  /**
   * The plaintext of a ciphertext is in the list, which is the whole point of the table.
   *
   * Asserted with the sample the tool ships: a cryptogram at shift 7, so its plaintext is at row 19
   * (26 - 7) of the table computed over the ciphertext.
   */
  it("holds the plaintext of a ciphertext at 26 - k", () => {
    const plain = "The quick brown fox jumps over 1 lazy dog!";
    const cipher = caesarShift(plain, { shift: 7 }).text;
    expect(cipher).toBe("Aol xbpjr iyvdu mve qbtwz vcly 1 shgf kvn!");
    expect(caesarAllShifts(cipher)[CAESAR_ALPHABET - 7]).toBe(plain);
  });

  it("applies the case setting to every row", () => {
    const all = caesarAllShifts("Hello", "upper");
    expect(all[0]).toBe("HELLO");
    expect(all[3]).toBe("KHOOR");
  });
});
