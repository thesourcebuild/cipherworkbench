import { createOptionCatalogue, type OptionCatalogue, type OptionDef } from "@ocs/engine";
import {
  OPTION_BCC_MODE,
  OPTION_BYTE_ORDER,
  OPTION_RESULT,
  OPTION_WIDTH,
  OPTION_WORD_SIZE,
  TAG_WORDS,
} from "../pure";
import type { ChecksumOptionGroup } from "./groups";

/**
 * Every option any tool in this family can expose, in one list.
 *
 * A tool's catalogue is this list filtered by its `exposes` array, so six of the nine tools get an
 * empty catalogue and `OptionsForm` renders "no settings" for them. That is the honest shape: an
 * LRC has nothing to configure, and giving it an inert width selector to look consistent would
 * invite someone to change it and wonder why Modbus stopped agreeing.
 */
const ALL: readonly OptionDef<ChecksumOptionGroup>[] = [
  {
    id: OPTION_WIDTH,
    label: "Result width",
    group: "arithmetic",
    kind: "enum",
    choices: [
      { value: "8", label: "8 bits", summary: "One byte — the usual embedded case" },
      { value: "16", label: "16 bits", summary: "Two bytes" },
      { value: "32", label: "32 bits", summary: "Four bytes" },
    ],
    summary: "How many low bits of the running total to keep.",
    detail:
      "The sum is taken over the full input and then truncated, which is the same thing as adding modulo 2^width. This is independent of how the input is grouped: you can sum 16-bit words and report only the low byte, and some protocols do exactly that.",
    order: 10,
  },
  {
    id: OPTION_RESULT,
    label: "Report",
    group: "arithmetic",
    kind: "enum",
    choices: [
      {
        value: "complement",
        label: "Complement (Internet checksum)",
        summary: "What goes in an IP, TCP, UDP or ICMP header",
      },
      {
        value: "sum",
        label: "Raw sum",
        summary: "The folded sum before complementing — RFC 1071's worked example",
      },
    ],
    summary: "Whether to complement the folded sum at the end.",
    detail:
      "IPv4, TCP, UDP and ICMP all transmit the complement, which is what makes the receiver's check elegant: summing the whole header including the checksum field yields 0xFFFF. RFC 1071's own section 3 example stops at the raw sum, so both are worth being able to see — a value that looks wrong by exactly a complement is this setting, not a bug.",
    order: 20,
  },
  {
    id: OPTION_BCC_MODE,
    label: "Mode",
    group: "arithmetic",
    kind: "enum",
    choices: [
      { value: "xor", label: "XOR (ISO 1155)", summary: "The standard definition" },
      {
        value: "sum",
        label: "Additive sum",
        summary: "What some vendors ship under the same name",
      },
    ],
    summary: "Which computation this device's BCC means.",
    detail:
      "ISO 1155 defines the Block Check Character as an XOR of the block. Plenty of industrial equipment computes an additive sum and calls it a BCC anyway. There is nothing in the name to tell them apart, which is why this is a selector rather than a fixed algorithm: if one does not match your device, try the other.",
    order: 30,
  },
  {
    id: OPTION_WORD_SIZE,
    label: "Word size",
    group: "grouping",
    kind: "enum",
    choices: [
      { value: "8", label: "8 bits", summary: "Sum the bytes one at a time" },
      { value: "16", label: "16 bits", summary: "Sum 16-bit words" },
      { value: "32", label: "32 bits", summary: "Sum 32-bit words" },
    ],
    summary: "How the input is grouped before adding.",
    detail:
      "Changes the answer, and it is the setting most often left unstated in a protocol document. Summing 0x01 0x02 as bytes gives 3; as one big-endian 16-bit word it gives 0x0102. A trailing partial word is zero-padded, so appending a 0x00 to an odd-length input does not change a 16-bit word sum.",
    order: 10,
  },
  {
    id: OPTION_BYTE_ORDER,
    label: "Byte order",
    group: "grouping",
    kind: "enum",
    choices: [
      { value: "big", label: "Big-endian", summary: "First byte is the most significant" },
      {
        value: "little",
        label: "Little-endian",
        summary: "First byte is the least significant",
      },
    ],
    // Gated on the word size rather than always shown: with 8-bit words there is no order to
    // choose, and a control that provably cannot affect the result is worse than no control.
    availableOn: [TAG_WORDS],
    summary: "Which end of each word the first byte lands on.",
    detail:
      "Only applies once words are wider than a byte. Endianness here is a property of the protocol, not of the machine running this tool — a little-endian device sending 16-bit words on the wire will have summed them in its own order, and that is the order to pick.",
    order: 20,
  },
];

const BY_ID = new Map(ALL.map((o) => [o.id, o]));

const CACHE = new Map<string, OptionCatalogue<ChecksumOptionGroup>>();

/**
 * Memoised per tool id. `ToolDefinition.catalogue` is resolved once per tool, and the filtered
 * list never changes at runtime.
 */
export function checksumCatalogueFor(
  toolId: string,
  exposes: readonly string[],
): OptionCatalogue<ChecksumOptionGroup> {
  let catalogue = CACHE.get(toolId);
  if (!catalogue) {
    catalogue = createOptionCatalogue<ChecksumOptionGroup>(
      exposes.map((id) => {
        const def = BY_ID.get(id);
        if (!def) throw new Error(`${toolId} exposes unknown checksum option: ${id}`);
        return def;
      }),
    );
    CACHE.set(toolId, catalogue);
  }
  return catalogue;
}

export function checksumOptionsFor(
  toolId: string,
  exposes: readonly string[],
): readonly OptionDef<ChecksumOptionGroup>[] {
  return checksumCatalogueFor(toolId, exposes).options;
}

/** Every option definition in the family, for `validateCatalogue`. */
export const ALL_CHECKSUM_OPTIONS = ALL;
