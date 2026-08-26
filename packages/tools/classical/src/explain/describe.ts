import { CAESAR_ALPHABET, normaliseShift } from "@ocs/algos";
import { requireClassicalTool } from "../catalogue/tool-meta";
import { readDirection, readLetterCase, readShift } from "../pure";
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
  const tool = requireClassicalTool(spec.variant);
  switch (tool.kind) {
    case "caesar": {
      const shift = readShift(spec.options);
      const direction = readDirection(spec.options);
      const cased = readLetterCase(spec.options);
      const casing =
        cased === "preserve" ? "" : cased === "upper" ? ", output in upper case" : ", output in lower case";
      if (direction === "encrypt") {
        return `Moves each letter forward ${shift} place${shift === 1 ? "" : "s"}${casing}.`;
      }
      const forward = normaliseShift(-shift);
      return `Moves each letter back ${shift} place${shift === 1 ? "" : "s"} -- forward ${forward} mod ${CAESAR_ALPHABET}${casing}.`;
    }
  }
}
