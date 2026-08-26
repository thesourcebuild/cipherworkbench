import { CAESAR_ALPHABET, caesarAllShifts, caesarShift, normaliseShift } from "@ocs/algos";
import { optBool } from "@ocs/contracts/pure";
import type { ToolResult, ToolResultField } from "@ocs/engine";
import { requireClassicalTool } from "./catalogue/tool-meta";
import {
  OPTION_SHOW_ALL,
  readDirection,
  readLetterCase,
  readShift,
} from "./pure";
import type { ClassicalSpec } from "./spec";

const text = (bytes: Uint8Array): string => new TextDecoder().decode(bytes);

/**
 * How much of each line the brute-force table shows.
 *
 * The table is always 26 rows, so the row count needs no cap -- but a paragraph of input would make
 * each row wider than the panel and the table unreadable, which defeats the point of it. Truncated
 * rather than wrapped, because the value of this table is that 26 lines are scannable in one glance
 * and wrapping destroys exactly that. The tool says when it has truncated, on the rule that "the
 * first 64 characters of 400" is information and a silent cut is not.
 */
const PREVIEW_LIMIT = 64;

export async function computeClassical(
  spec: ClassicalSpec,
  input: Uint8Array,
): Promise<ToolResult> {
  const tool = requireClassicalTool(spec.variant);
  try {
    switch (tool.kind) {
      case "caesar":
        return caesarResult(spec, text(input));
    }
  } catch (thrown) {
    // A refusal renders as a result rather than throwing out of the workbench -- the same wrapper the
    // cipher, format and parity families use, for the same reason: a half-typed input is a normal
    // state of a text box.
    return { error: thrown instanceof Error ? thrown.message : String(thrown) };
  }
}

function caesarResult(spec: ClassicalSpec, message: string): ToolResult {
  const direction = readDirection(spec.options);
  const typed = readShift(spec.options);
  const letterCase = readLetterCase(spec.options);
  /**
   * Decryption is the same shift negated, which is the whole of `D(x) = (x - k) mod 26`.
   *
   * Reduced through `normaliseShift` rather than by `%`, because JavaScript's remainder keeps the sign
   * of the dividend: `-3 % 26` is `-3`, and using it as an offset indexes off the front of the
   * alphabet. That reduction lives in the algorithm; this line only decides the sign.
   */
  const applied = normaliseShift(direction === "encrypt" ? typed : -typed);
  const result = caesarShift(message, { shift: applied, letterCase });

  const fields: ToolResultField[] = [
    {
      label: "Shift applied",
      value:
        direction === "encrypt"
          ? `+${typed}`
          : `-${typed} (that is +${applied} mod ${CAESAR_ALPHABET})`,
      hint:
        direction === "encrypt"
          ? "E(x) = (x + k) mod 26."
          : "D(x) = (x - k) mod 26, which is the same as adding 26 - k.",
    },
    {
      label: "Letters moved",
      value: `${result.shifted} of ${result.shifted + result.passed}`,
      hint:
        result.passed === 0
          ? "Every character was a letter."
          : `${result.passed} passed through unchanged: digits, punctuation, spaces and any letter outside A-Z.`,
    },
  ];

  /**
   * ROT13 is its own inverse, and saying so beside the result is worth a line.
   *
   * `X003` says it in the Checks panel too, and the duplication is deliberate rather than sloppy: the
   * panel is where someone goes to find out whether they have made a mistake, and this is where they
   * are already looking. It is a property of the shift, so it is true before anything is typed -- but
   * it belongs here rather than in `info` because it explains *this* result.
   */
  if (typed === CAESAR_ALPHABET / 2) {
    fields.push({
      label: "Note",
      value: "A shift of 13 is ROT13, which is its own inverse",
      hint: "Encrypt and decrypt produce the same output at this shift. Applying it twice returns the input.",
    });
  }

  const showAll = optBool(spec.options, OPTION_SHOW_ALL);
  return {
    text: result.text,
    fields,
    ...(showAll ? { working: bruteForceTable(message, letterCase, applied) } : {}),
  };
}

/**
 * Every shift, with the one in use marked.
 *
 * This is the table that makes the tool useful rather than merely correct: given a ciphertext, the
 * plaintext is one of these 26 lines, and finding it is the entire attack. The marker is on the row
 * the current settings produce -- so for a decryption at shift 3 the marked row is shift 23, which is
 * the same statement as `-3 mod 26` and is worth having on screen next to it.
 *
 * Laid out here rather than in `@ocs/algos`, which holds no opinion about tables. The columns are
 * padded to a fixed width rather than through a general aligner: there are exactly two, the first is
 * always four characters, and the second is the only one that varies.
 */
function bruteForceTable(
  message: string,
  letterCase: Parameters<typeof caesarAllShifts>[1],
  applied: number,
): string {
  const all = caesarAllShifts(message, letterCase);
  const truncated = message.length > PREVIEW_LIMIT;
  const rows = all.map((line, shift) => {
    const shown = truncated ? `${line.slice(0, PREVIEW_LIMIT)}...` : line;
    // The marker sits in its own column so the text still starts at the same place on every row.
    const marker = shift === applied ? ">" : " ";
    return `${marker} ${String(shift).padStart(2)}  ${shown}`;
  });
  const head = `  ${"k".padStart(2)}  Result`;
  const note = truncated
    ? `\n\nShowing the first ${PREVIEW_LIMIT} characters of ${message.length}.`
    : "";
  return `${head}\n${rows.join("\n")}${note}`;
}

/**
 * What these settings *are*, true before anything is typed.
 *
 * The formula belongs here rather than in a field for exactly that reason -- it does not depend on the
 * input -- and it is worth stating because it is the thing someone checking this tool against a
 * textbook wants to see. The alphabet line is here because it is the question this cipher attracts
 * most: whether it applies to digits, to bytes, or to hex.
 */
export function classicalInfo(spec: ClassicalSpec): ToolResultField[] {
  const direction = readDirection(spec.options);
  const shift = readShift(spec.options);
  return [
    {
      label: "Formula",
      value: direction === "encrypt" ? "E(x) = (x + k) mod 26" : "D(x) = (x - k) mod 26",
      hint: `With k = ${shift}. x is a letter's position in the alphabet, A being 0.`,
    },
    {
      label: "Alphabet",
      value: "A-Z and a-z, 26 letters",
      hint: "Everything else passes through: digits, punctuation, spaces, and letters outside these 26. A shift over bytes or hex digits would be a different cipher, not this one.",
    },
    {
      label: "Keyspace",
      value: `${CAESAR_ALPHABET} shifts, of which ${CAESAR_ALPHABET - 1} change anything`,
      hint: "Small enough to read rather than search, which is what the table under the result is for.",
    },
  ];
}

/** Re-exported for the tests, which check the table's shape rather than trusting it. */
export const __testing = { bruteForceTable, PREVIEW_LIMIT };
