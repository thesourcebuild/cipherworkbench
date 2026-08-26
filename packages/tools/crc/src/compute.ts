import { CRC_CATALOGUE, createCrc, crcLookupTable, type CrcModel } from "@ocs/algos";
import type {
  ToolResult,
  ToolResultField,
  ToolStream,
  ToolTable,
  ToolVariantTable,
} from "@ocs/engine";
import { formatHexParam } from "./pure";
import { requireCrcTool } from "./catalogue/tool-meta";
import { matchingCatalogueEntry, resolveModel } from "./resolve";
import type { CrcSpec } from "./spec";

/**
 * Reports the parameters that were actually used.
 *
 * This is the field set that makes the tool trustworthy rather than merely correct. Two programs
 * that both claim "CRC-16" disagree about a third of the time, because there are thirty-one of them
 * -- so a checksum with no statement of which variant produced it is not a reproducible result.
 * Showing the seven parameters means whoever receives the value can get the same one.
 *
 * Reached through `ToolDefinition.info` rather than returned from `compute`, because none of it
 * depends on the input: pick MODBUS and its polynomial is decided, whether or not anything has been
 * typed yet. The workbench renders it under the options, where the choice that produced it is.
 */
function modelFields(model: CrcModel, custom: boolean): ToolResultField[] {
  const fields: ToolResultField[] = [
    { label: "Model", value: model.name },
    ...(model.aliases?.length
      ? [
          {
            /**
             * The alias list, and this row is why the Model dropdown can afford to show bare names.
             *
             * "ISO-HDLC" means nothing to anyone; "CRC-32, crc32, gzip, PNG, Ethernet" is how a
             * reader recognises the variant they came for. That belonged in the dropdown until it
             * turned out an `<option>` cannot wrap and cannot grow past the window edge, so five
             * aliases clipped every other name in the list. Here it wraps, it is visible without a
             * hover, and it stays on screen while you compare it against whatever sent you looking.
             */
            /**
             * Two lines: the word people scan for, then what it means.
             *
             * "Also known as" alone reads as prose in a column of nouns -- Model, Width, Polynomial,
             * Init -- and "Alias" alone is a term some readers will not connect to the list of
             * familiar names beside it. The newline is honoured by `FieldTable`'s label cell, which
             * uses `whitespace-pre` for exactly this.
             */
            label: "Alias\n(Also known as)",
            value: model.aliases.join(", "),
          },
        ]
      : []),
    { label: "Width", value: `${model.width} bits` },
    { label: "Polynomial", value: formatHexParam(model.poly, model.width) },
    { label: "Init", value: formatHexParam(model.init, model.width) },
    { label: "Reflect in / out", value: `${model.refIn} / ${model.refOut}` },
    { label: "Final xor", value: formatHexParam(model.xorOut, model.width) },
  ];

  if (custom) {
    const known = matchingCatalogueEntry(model);
    if (known) {
      // Someone hand-entering parameters to identify an unknown checksum has usually
      // just rediscovered a standard one. Saying so ends their search.
      fields.push({
        label: "Matches",
        value: known.name,
        hint: `These parameters are exactly ${known.name}${
          known.aliases?.length ? ` (also known as ${known.aliases.join(", ")})` : ""
        }. Selecting it from the Model list gives the same result.`,
      });
    }
  } else {
    fields.push({
      label: "Check value",
      value: formatHexParam(model.check, model.width),
      hint: 'The published CRC of "123456789" for this model — enter that as the input to confirm this tool agrees with the catalogue.',
    });
    if (model.residue !== undefined) {
      /**
       * The other half of how a CRC is used, and the half a calculator usually omits.
       *
       * A sender appends the CRC; a receiver runs the CRC over message-and-CRC together and compares
       * the result against this, rather than recomputing and comparing the check field. It is zero
       * for most models, which is why the ones where it is not are worth stating rather than
       * assuming -- and why someone debugging a receiver that checks against zero needs to see it.
       *
       * Absent for a custom model: there is no published residue for parameters someone just typed,
       * and computing one would put a number on screen with nothing behind it.
       */
      fields.push({
        label: "Residue",
        value: formatHexParam(model.residue, model.width),
        hint: "What a correct message with its own CRC appended produces. A receiver can compare against this instead of recomputing the check field.",
      });
    }
  }

  return fields;
}

/**
 * The parameter table for one spec, for `ToolDefinition.info`.
 *
 * Empty when the settings do not resolve. The half-filled state of a custom polynomial is already
 * reported by `CRC002`, and a table of blanks beside that diagnostic would say nothing twice.
 */
export function crcInfo(spec: CrcSpec): ToolResultField[] {
  const resolved = resolveModel(spec);
  if (!resolved.ok) return [];
  return modelFields(resolved.model, resolved.custom);
}

/**
 * Shown on the reflected entry only, and nowhere else.
 *
 * The question it answers is asked at one moment: you switch the orientation away from the default
 * and wonder whether you have just changed your CRC. Normal is where the panel opens, so there is
 * nothing to reassure anyone about yet -- and a line of text under a heading that says the same
 * thing whatever you pick is a line nobody reads by the third time.
 *
 * It replaced a sentence spelling out the indexing arithmetic per width, which read badly at the
 * ends of the range -- "a 8-bit register", and `(crc >> 0)` at width 8, both of which are what you
 * get from templating a description that assumed a wide register. The label already says MSB-first
 * or LSB-first; anything past that belongs in a reference, not in a one-line panel description.
 */
const DISPLAY_ONLY =
  "This option does not affect the CRC calculation, only the displayed lookup table";

/**
 * Shown on both orientations, at widths 3 to 7, because skipping it gives a wrong answer silently.
 *
 * The table for a narrow CRC is over the polynomial shifted up into a byte -- the only way a
 * byte-indexed table exists at all below 8 bits. Someone copying the grid into their own loop gets a
 * plausible byte out and no indication that five of its bits are padding, which is exactly the shape
 * of bug this whole panel is meant to prevent.
 *
 * Unlike `DISPLAY_ONLY` this is not about a choice the reader has made, so it is not confined to the
 * entry they switched to.
 */
const leftJustified = (width: number): string =>
  `Entries are ${width}-bit values shifted up ${8 - width} bits, which is what makes a byte-indexed table possible below 8 bits -- shift the finished register back down ${8 - width} to read the CRC`;

/**
 * The lookup table these parameters imply, in both bit orders.
 *
 * Both, because both appear in real source and someone copying one out needs the orientation their
 * loop expects: zlib's CRC-32 table is reflected, the Ethernet and MPEG references are normal. The
 * `normal` one is the very table the engine runs on -- `crcLookupTable` returns `buildTable`'s own
 * output, not a re-derivation -- so the panel cannot show a table the tool does not use.
 *
 * Padded to the model's hex width rather than trimmed, because a table is read in columns and
 * ragged cells make it unreadable. No `0x`: the panel puts one on if you ask.
 */
export function crcTables(spec: CrcSpec): ToolTable[] {
  const resolved = resolveModel(spec);
  if (!resolved.ok) return [];

  /**
   * The register's width, not the model's, at every width from 3 to 82.
   *
   * Below 8 they differ: the entries are byte-wide, so they take two hex digits and a C array of
   * them is `uint8_t`. This used to return nothing for those five tools on the reasoning that a
   * byte-indexed table cannot exist when the register is narrower than the index -- true of an
   * unjustified table, and the reason the panel now carries `leftJustified` rather than staying
   * hidden. What the sibling project does here is different again and wrong: it fills the grid with
   * "the CRC of the single byte i", a quantity that disagrees with its own calculator.
   */
  const narrow = resolved.model.width < 8;
  const bitWidth = narrow ? 8 : resolved.model.width;
  const note = narrow ? leftJustified(resolved.model.width) : undefined;

  const digits = Math.ceil(bitWidth / 4);
  const format = (values: readonly bigint[]): string[] =>
    values.map((v) => v.toString(16).toUpperCase().padStart(digits, "0"));

  return [
    {
      id: "normal",
      label: "Normal (MSB-first)",
      // No `DISPLAY_ONLY`: this is where the panel opens, so there is nothing to explain about a
      // choice nobody has made yet. The justification note is not a choice and does appear.
      summary: note,
      columns: 16,
      bitWidth,
      name: "crc_table",
      values: format(crcLookupTable(resolved.model, "normal")),
    },
    {
      id: "reflected",
      label: "Reflected (LSB-first)",
      summary: note === undefined ? DISPLAY_ONLY : `${DISPLAY_ONLY}. ${note}`,
      columns: 16,
      bitWidth,
      name: "crc_table",
      values: format(crcLookupTable(resolved.model, "reflected")),
    },
  ];
}

/**
 * Every model of this tool's width, over the same input.
 *
 * The thing crccalc.com is actually used for: you have a checksum from a device or a file format,
 * you know it is eight bits, and you do not know which of the twenty CRC-8 models produced it. So
 * you compute all twenty and look for the row that matches. Nothing else in this app answers that,
 * and no amount of reading the parameters in the Info table does either.
 *
 * Width, not family: `crc8` covers exactly the models whose width is 8, which is the axis the tool
 * is already divided on. Custom mode still selects the width, so the list is the same twenty and the
 * hand-entered parameters simply are not among them -- `matchingCatalogueEntry` is the thing that
 * answers "is my custom model actually a standard one", and it already has its own row in Info.
 *
 * Ordered as the catalogue is, which is how the Model dropdown is ordered too. Sorting by value
 * would put the row you are looking for somewhere new on every keystroke.
 */
/**
 * A single-use stream over one model. The same three lines `createCrcStream` uses for the selected
 * model, without the resolver in front of it -- here the model is already known.
 */
function streamFor(model: CrcModel): ToolStream {
  const engine = createCrc(model);
  let finished = false;
  return {
    update(chunk) {
      if (finished) throw new Error("Cannot update a CRC stream after finish().");
      engine.update(chunk);
    },
    finish() {
      if (finished) throw new Error("finish() called twice on the same CRC stream.");
      finished = true;
      return { bytes: engine.digestBytes() };
    },
  };
}

export function crcVariants(spec: CrcSpec): ToolVariantTable {
  const tool = requireCrcTool(spec.variant);
  if (tool.width === undefined) return { columns: [], rows: [] };

  const resolved = resolveModel(spec);
  // Only a *named* model marks a row. In custom mode nothing here is selected, which is honest:
  // the parameters in the form are not one of these twenty until they happen to coincide.
  const selected = resolved.ok && !resolved.custom ? resolved.model.name : undefined;
  const width = tool.width;

  return {
    /**
     * The six parameters that define a CRC, beside the value each one produced.
     *
     * This is the difference between a list of answers and something you can act on. You have a
     * checksum, you find the row that matches -- and the next thing you need is the parameters, so
     * that whatever you are writing can reproduce it. Sending someone back to the Model dropdown to
     * select it and then read the Info table is two steps for information that fits on the row.
     *
     * `Check` sits next to `Result` on purpose: they are equal exactly when the input is the check
     * string, so the two columns agreeing is a one-glance confirmation that this tool and the
     * catalogue agree about all twenty models.
     */
    noun: "model",
    columns: ["Check", "Poly", "Init", "RefIn", "RefOut", "XorOut"],
    rows: CRC_CATALOGUE.filter((model) => model.width === width).map((model) => ({
      id: model.name,
      label: model.name,
      aliases: model.aliases,
      // A factory, so listing twenty models costs twenty objects rather than twenty lookup tables.
      stream: () => streamFor(model),
      selected: model.name === selected,
      cells: [
        model.check === undefined ? "—" : formatHexParam(model.check, width),
        formatHexParam(model.poly, width),
        formatHexParam(model.init, width),
        String(model.refIn),
        String(model.refOut),
        formatHexParam(model.xorOut, width),
      ],
    })),
  };
}

export async function computeCrc(spec: CrcSpec, input: Uint8Array): Promise<ToolResult> {
  const resolved = resolveModel(spec);
  // A missing or oversized polynomial is a normal state of a half-filled form, so it
  // comes back as a result the panel renders rather than as an exception.
  if (!resolved.ok) return { error: resolved.problem };

  const engine = createCrc(resolved.model);
  engine.update(input);
  return { bytes: engine.digestBytes() };
}

export function createCrcStream(spec: CrcSpec): ToolStream {
  const resolved = resolveModel(spec);
  if (!resolved.ok) {
    // Still a valid stream — it consumes the file and reports the problem — so the
    // caller does not need a second code path for "settings are incomplete".
    return {
      update: () => {},
      finish: () => ({ error: resolved.problem }),
    };
  }

  const engine = createCrc(resolved.model);
  let finished = false;

  return {
    update(chunk) {
      if (finished) throw new Error("Cannot update a CRC stream after finish().");
      engine.update(chunk);
    },
    finish() {
      if (finished) throw new Error("finish() called twice on the same CRC stream.");
      finished = true;
      return { bytes: engine.digestBytes() };
    },
  };
}
