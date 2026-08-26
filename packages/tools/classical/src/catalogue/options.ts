import { createOptionCatalogue, type OptionCatalogue, type OptionDef } from "@ocs/engine";
import {
  DEFAULT_SHIFT,
  LETTER_CASES,
  OPTION_DIRECTION,
  OPTION_LETTER_CASE,
  OPTION_SHIFT,
  OPTION_SHOW_ALL,
  type LetterCase,
} from "../pure";
import type { ClassicalToolMeta } from "./tool-meta";
import type { ClassicalOptionGroup } from "./groups";

type Def = OptionDef<ClassicalOptionGroup>;

const DIRECTION: Def = {
  id: OPTION_DIRECTION,
  label: "Direction",
  group: "cipher",
  kind: "enum",
  choices: [
    { value: "encrypt", label: "Encrypt", summary: "Move each letter forward" },
    { value: "decrypt", label: "Decrypt", summary: "Move each letter back" },
  ],
  summary: "Forward, or back.",
  detail:
    "Encryption is E(x) = (x + k) mod 26 and decryption is D(x) = (x - k) mod 26 -- the same shift applied in the other direction, which is why one control covers both. At a shift of 13 the two are identical: ROT13 is its own inverse, and the Checks panel says so when you select it.",
  order: 10,
};

const SHIFT: Def = {
  id: OPTION_SHIFT,
  label: "Shift",
  group: "cipher",
  kind: "number",
  arg: { placeholder: String(DEFAULT_SHIFT), min: 0, max: 25 },
  summary: "Places to move, 0 to 25.",
  detail:
    "The cipher's whole key, which is why it is breakable by hand: 26 shifts is a keyspace you read rather than search, and the working below the result prints all of them. Values outside 0 to 25 are the same as one inside it -- a shift of 29 is a shift of 3 -- so the control stops there rather than accepting a number it would silently reduce.",
  order: 20,
};

const LETTER_CASE_LABEL: Readonly<Record<LetterCase, string>> = {
  preserve: "Preserve",
  upper: "UPPER CASE",
  lower: "lower case",
};

const LETTER_CASE_SUMMARY: Readonly<Record<LetterCase, string>> = {
  preserve: "Keep each letter's own case",
  upper: "The classical presentation",
  lower: "All lower",
};

const LETTER_CASE: Def = {
  id: OPTION_LETTER_CASE,
  label: "Letter case",
  group: "output",
  kind: "enum",
  // Derived from the enum with label maps, so adding a case is a compile error until it is named.
  choices: LETTER_CASES.map((value) => ({
    value,
    label: LETTER_CASE_LABEL[value],
    summary: LETTER_CASE_SUMMARY[value],
  })),
  summary: "Case of the letters that moved.",
  detail:
    "Preserving it is what nearly every implementation does and it keeps the transformation reversible on the exact input you gave. Upper case is how the classical examples print -- HELLO to KHOOR -- and is here because that is the form somebody comparing against a textbook is holding. Either way, only letters are touched: digits, punctuation and spaces pass through as they are.",
  order: 10,
};

const SHOW_ALL: Def = {
  id: OPTION_SHOW_ALL,
  label: "Show all 26 shifts",
  group: "output",
  kind: "boolean",
  summary: "The brute-force table.",
  detail:
    "Prints the input under every shift, with the selected one marked, which is how a Caesar ciphertext is actually broken: the plaintext is one of 26 lines and the eye finds it immediately. Off if the table is in the way -- it says nothing the Shift control cannot be walked through by hand.",
  order: 20,
};

/**
 * A throwing `Record`, not a chain ending in a default.
 *
 * The sixth time this repo has used this shape, and for the reason the earlier five record: a tool
 * added to the metadata without an entry here should fail by name at build time rather than silently
 * inherit whichever option happened to be last.
 */
const BY_ID: Record<string, Def> = {
  [OPTION_DIRECTION]: DIRECTION,
  [OPTION_SHIFT]: SHIFT,
  [OPTION_LETTER_CASE]: LETTER_CASE,
  [OPTION_SHOW_ALL]: SHOW_ALL,
};

const CACHE = new Map<string, OptionCatalogue<ClassicalOptionGroup>>();

/** Memoised per tool: `ToolDefinition.catalogue` is resolved once, and this never changes. */
export function classicalCatalogueFor(
  meta: ClassicalToolMeta,
): OptionCatalogue<ClassicalOptionGroup> {
  let catalogue = CACHE.get(meta.id);
  if (!catalogue) {
    const options: Def[] = [];
    for (const id of meta.exposes) {
      const option = BY_ID[id];
      if (!option) throw new Error(`${meta.id} exposes unknown classical option: ${id}`);
      options.push(option);
    }
    catalogue = createOptionCatalogue<ClassicalOptionGroup>(options);
    CACHE.set(meta.id, catalogue);
  }
  return catalogue;
}

export const ALL_CLASSICAL_OPTIONS: readonly Def[] = Object.values(BY_ID);
