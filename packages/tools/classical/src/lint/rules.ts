import type { LintRule } from "@ocs/contracts/diagnostic";
import { requireClassicalTool } from "../catalogue/tool-meta";
import { DEFAULT_SHIFT, OPTION_SHIFT, readDirection, readShift, withShift } from "../pure";
import type { ClassicalSpec } from "../spec";

export const RULE_CODES = ["X001", "X002", "X003"] as const;

/**
 * Three rules, and the bar is the one this repo applies everywhere: would this change what somebody
 * does.
 *
 * Note what is *not* here. There is no rule saying "use AES instead", because that is not a fix for
 * anyone who came to this tool -- they are solving a puzzle, reading a cryptogram, or checking a
 * textbook exercise, and telling them to reach for a modern AEAD answers a question they did not ask.
 * `X001` states the strength and leaves it there. That is the same restraint `CRC001` shows: it says a
 * checksum is not an integrity check without pretending the person wanted a MAC.
 */
export const RULES: readonly LintRule<ClassicalSpec>[] = [
  {
    /**
     * What this cipher is worth, said once and plainly.
     *
     * `insecure` rather than `error`: it computes exactly as specified, and the whole point of the tool
     * is to produce that output. No fix, because there is nothing to fix -- a different shift is not
     * stronger, and a different cipher is a different tool. The detail gives the number, because "weak"
     * is vague and "26 keys" is not.
     */
    code: "X001",
    check(spec) {
      if (requireClassicalTool(spec.variant).kind !== "caesar") return [];
      return [
        {
          code: "X001",
          level: "insecure",
          message: "A Caesar cipher has 26 keys and is broken by reading the table below.",
          detail:
            "This is not a weakness in the implementation; it is the cipher. Every shift is on screen under the result, so a ciphertext is broken by looking at 26 lines and picking the one that is English -- no computer required. It is here to read cryptograms, check textbook exercises and solve puzzles, all of which it does correctly. It is not here to keep anything secret.",
          optionIds: [OPTION_SHIFT],
        },
      ];
    },
  },
  {
    /**
     * A shift of zero is the identity, and the output looking like the input is otherwise puzzling.
     *
     * `warning` with a fix, because it is almost never what was meant -- and the one case where it *is*
     * meant, walking the shifts by hand from zero, is not harmed by a line in a panel. The fix goes to
     * 3 rather than 1: it is the classical shift and this tool's own default, so the fix lands
     * somewhere recognisable rather than merely somewhere non-zero.
     */
    code: "X002",
    check(spec) {
      if (requireClassicalTool(spec.variant).kind !== "caesar") return [];
      if (readShift(spec.options) !== 0) return [];
      return [
        {
          code: "X002",
          level: "warning",
          message: "A shift of 0 leaves the text unchanged.",
          detail:
            "The cipher is the identity at this shift: E(x) = (x + 0) mod 26 is x. If the output looks like the input, this is why. A shift of 26 would do the same thing, which is why the control stops at 25.",
          optionIds: [OPTION_SHIFT],
          fix: {
            label: `Use a shift of ${DEFAULT_SHIFT}`,
            apply: (current) => ({
              ...current,
              options: withShift(current.options, DEFAULT_SHIFT),
            }),
          },
        },
      ];
    },
  },
  {
    /**
     * ROT13 is its own inverse, which is a fact worth having rather than a mistake to correct.
     *
     * `info` and no fix. Somebody on 13 has almost certainly chosen it deliberately -- it is the shift
     * with its own name -- and the useful thing to tell them is that the Direction control makes no
     * difference here, because that is the one surprising consequence.
     */
    code: "X003",
    check(spec) {
      if (requireClassicalTool(spec.variant).kind !== "caesar") return [];
      if (readShift(spec.options) !== 13) return [];
      const direction = readDirection(spec.options);
      return [
        {
          code: "X003",
          level: "info",
          message: "A shift of 13 is ROT13, which is its own inverse.",
          detail: `Half of 26, so shifting forward 13 and back 13 land on the same letter -- Direction is currently ${direction} and switching it would change nothing. Applying ROT13 twice returns the original text, which is why it is used to hide spoilers rather than secrets.`,
          optionIds: [OPTION_SHIFT],
        },
      ];
    },
  },
];
