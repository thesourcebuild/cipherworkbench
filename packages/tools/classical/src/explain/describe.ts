import { CAESAR_ALPHABET, normaliseShift } from "@ocs/algos";
import { readDirection, readLetterCase, readShift } from "../pure";
import { resolveClassical } from "../resolve";
import type { ClassicalSpec } from "../spec";

/**
 * One sentence under the tool's name, from the spec alone.
 *
 * Reads the spec and nothing else, so it is on screen before anything is typed. It names the shift and
 * the direction because those are the two things that decide the answer -- and it names the *effective*
 * shift for a decryption, since "back 3" and "forward 23" are the same operation and seeing both is
 * what makes the modular arithmetic concrete.
 */
export function describeSpec(spec: ClassicalSpec): string {
  const resolution = resolveClassical(spec);
  if (!resolution.ok) return resolution.problem;
  const { tool, affineMultiplier, affineOffset, rotVariant } = resolution.value;
  switch (tool.kind) {
    case "caesar": {
      const shift = readShift(spec.options);
      const direction = readDirection(spec.options);
      const cased = readLetterCase(spec.options);
      const casing =
        cased === "preserve"
          ? ""
          : cased === "upper"
            ? ", output in upper case"
            : ", output in lower case";
      if (direction === "encrypt") {
        return `Moves each letter forward ${shift} place${shift === 1 ? "" : "s"}${casing}.`;
      }
      const forward = normaliseShift(-shift);
      return `Moves each letter back ${shift} place${shift === 1 ? "" : "s"} -- forward ${forward} mod ${CAESAR_ALPHABET}${casing}.`;
    }
    case "affine":
      return `${readDirection(spec.options) === "encrypt" ? "Encrypts" : "Decrypts"} with the affine key a=${affineMultiplier}, b=${affineOffset}.`;
    case "atbash":
      return "Reverses the alphabet; the same operation encrypts and decrypts.";
    case "polybius":
      return readDirection(spec.options) === "encrypt"
        ? "Maps letters to coordinates in the standard 5 x 5 I/J square."
        : "Strictly decodes coordinates from the standard 5 x 5 I/J square.";
    case "a1z26":
      return readDirection(spec.options) === "encrypt"
        ? "Maps A through Z to the numbers 1 through 26."
        : "Strictly decodes hyphen-separated values from 1 through 26.";
    case "rot":
      return `Applies ${rotVariant.toUpperCase()}, a reciprocal rotation.`;
    case "adfgvx":
    case "vic-cipher":
    case "hill-cipher":
    case "foursquare":
    case "chaocipher":
    case "enigma":
    case "vigenere":
    case "playfair":
    case "bifid":
    case "trifid":
    case "bacon":
    case "railfence":
    case "m209":
    case "lorenz":
    case "solitaire":
    case "adfgx":
    case "nihilist":
    case "straddling-checkerboard":
    default:
      return tool.summary;
  }
}
