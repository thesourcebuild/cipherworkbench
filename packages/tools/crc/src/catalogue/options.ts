import { CRC_CATALOGUE, type CrcModel } from "@ocs/algos";
import {
  createOptionCatalogue,
  type OptionCatalogue,
  type OptionDef,
  type OptionEnumChoice,
} from "@ocs/engine";
import {
  CUSTOM_MODEL,
  OPTION_INIT,
  OPTION_MODEL,
  OPTION_POLY,
  OPTION_REF_IN,
  OPTION_REF_OUT,
  OPTION_XOR_OUT,
  TAG_CUSTOM,
} from "../pure";
import type { CrcOptionGroup } from "./groups";

/**
 * The catalogue is built per width rather than shared, because the `model` dropdown's
 * choices are exactly the variants of that width. That is the one thing that differs
 * between the CRC tools; everything else below is identical for all of them.
 */

/** `CRC-32/ISO-HDLC` reads as `ISO-HDLC` once you are already inside the CRC-32 tool. */
function shortName(model: CrcModel): string {
  return model.name.replace(/^CRC-\d+\//, "");
}

function modelChoices(width: number): OptionEnumChoice[] {
  const choices: OptionEnumChoice[] = CRC_CATALOGUE.filter((m) => m.width === width).map(
    (m) => ({
      value: m.name,
      label: shortName(m),
      group: "Standard Models",
      // The aliases are the whole reason this list is readable: "ISO-HDLC" means nothing,
      // "CRC-32, crc32, gzip, PNG, Ethernet" means everything. The options form shows as much of
      // this beside the name as one line of a dropdown can hold, and all of it under the select.
      ...(m.aliases?.length ? { summary: m.aliases.join(", ") } : {}),
    }),
  );

  choices.push({
    value: CUSTOM_MODEL,
    label: "Custom",
    summary: "Enter the polynomial and the rest by hand",
    // Its own group, so a native select draws a break above it. Picking Custom does something
    // categorically different from picking a model -- it reveals six parameter fields beside the
    // input -- and it sat flush against WCDMA with nothing to say so.
    group: "Customize Model",
  });

  return choices;
}

function options(width: number): readonly OptionDef<CrcOptionGroup>[] {
  const widthHex = Math.ceil(width / 4);
  const example = "0".repeat(widthHex);

  return [
    {
      id: OPTION_MODEL,
      label: "Model",
      group: "model",
      kind: "enum",
      choices: modelChoices(width),
      summary: "The named variant, or Custom to enter parameters yourself.",
      detail:
        'Every named CRC is the same shift-and-xor loop with different constants — a polynomial, an initial value, whether the input and output are bit-reflected, and a final xor. That is why one implementation covers all of them, and why two tools that both say "CRC-16" can disagree completely: there are thirty-one of those. The parameters actually used are shown with the result.',
      order: 10,
    },
    {
      id: OPTION_POLY,
      label: "Polynomial",
      group: "parameters",
      kind: "text",
      arg: { placeholder: `0x${example}` },
      availableOn: [TAG_CUSTOM],
      summary: `The generator polynomial, ${width} bits, top bit implicit.`,
      detail:
        "Written in the catalogue's normal (msb-first) form, with the implicit x^width term omitted — so CRC-32's polynomial is 0x04C11DB7, not 0x104C11DB7. If you have a reversed (lsb-first) constant such as 0xEDB88320, it is the bit-reflection of this form; enter the msb-first value and set the reflection flags instead.",
      order: 10,
    },
    {
      id: OPTION_INIT,
      label: "Initial value",
      group: "parameters",
      kind: "text",
      arg: { placeholder: `0x${example}` },
      availableOn: [TAG_CUSTOM],
      summary: "What the register holds before the first byte.",
      detail:
        "Usually all zeros or all ones. A non-zero init is what makes a CRC notice leading zero bytes — with init 0, any number of leading zeros gives the same register state, so a message that gained or lost some would check out.",
      order: 20,
    },
    {
      id: OPTION_REF_IN,
      label: "Reflect input",
      group: "parameters",
      kind: "boolean",
      availableOn: [TAG_CUSTOM],
      summary: "Feed each byte in least-significant-bit first.",
      detail:
        "Reflects every input byte before it enters the register. This is not an aesthetic choice — it reflects how the bits arrived on the wire in whichever hardware the variant was designed for. Getting it wrong produces a valid-looking checksum that matches nothing.",
      order: 30,
    },
    {
      id: OPTION_REF_OUT,
      label: "Reflect output",
      group: "parameters",
      kind: "boolean",
      availableOn: [TAG_CUSTOM],
      summary: "Reflect the whole register before the final xor.",
      detail:
        "Applied once, at the end, to the full register rather than byte by byte. Most variants set this together with Reflect input, but not all of them — MCRF4XX and the DNP variant differ from their siblings in exactly this pair of flags.",
      order: 40,
    },
    {
      id: OPTION_XOR_OUT,
      label: "Final xor",
      group: "parameters",
      kind: "text",
      arg: { placeholder: `0x${example}` },
      availableOn: [TAG_CUSTOM],
      summary: "Xored into the register at the very end.",
      detail:
        "Usually all zeros or all ones. Together with the initial value it is what distinguishes, for example, MODBUS from USB — same polynomial, same reflection, different init and xor.",
      order: 50,
    },
  ];
}

const CACHE = new Map<number, OptionCatalogue<CrcOptionGroup>>();

/** Memoised: the choice list is derived from the catalogue and never changes at runtime. */
export function crcCatalogueFor(width: number): OptionCatalogue<CrcOptionGroup> {
  let catalogue = CACHE.get(width);
  if (!catalogue) {
    catalogue = createOptionCatalogue<CrcOptionGroup>(options(width));
    CACHE.set(width, catalogue);
  }
  return catalogue;
}

export function crcOptionsFor(width: number): readonly OptionDef<CrcOptionGroup>[] {
  return crcCatalogueFor(width).options;
}
