import {
  createOptionCatalogue,
  type OptionCatalogue,
  type OptionDef,
} from "@ocs/engine";
import {
  OPTION_BAUD,
  OPTION_BIT_ORDER,
  OPTION_DATA_BITS,
  OPTION_DIRECTION,
  OPTION_BCH_PROFILE,
  OPTION_HAMMING_CODE,
  OPTION_RS_ECC,
  OPTION_RS_PROFILE,
  DEFAULT_RS_ECC,
  OPTION_INVERTED,
  OPTION_PARITY,
  OPTION_PLACEMENT,
  OPTION_SCOPE,
  OPTION_SPACED,
  OPTION_STOP_BITS,
  OPTION_HADAMARD_ORDER,
  TAG_APPLY,
  TAG_FRAMED,
  TAG_PER_BYTE,
} from "../pure";
import type { ParityToolMeta } from "./tool-meta";
import type { ParityOptionGroup } from "./groups";

type Def = OptionDef<ParityOptionGroup>;

/**
 * Two direction controls, because the two tools mean different things by it.
 *
 * "Apply / Check" is right for a parity bit: you either add one or test one, and the data is the same
 * either way. "Encode / Decode" is right for the frame and the code, where one direction produces
 * something that is not data at all -- a picture of a wire, a codeword -- and the other reads it back.
 * Sharing one pair of labels would mean being vague about one of them, and both write the same option
 * id, so a share link carries either equally.
 */
const DIRECTION_APPLY: Def = {
  id: OPTION_DIRECTION,
  label: "Direction",
  group: "direction",
  kind: "enum",
  choices: [
    { value: "apply", label: "Apply", summary: "Compute the parity for this data" },
    { value: "check", label: "Check", summary: "Verify the parity already in it" },
  ],
  summary: "Add the bit, or test it.",
  detail:
    "Applying computes the parity of each unit and puts it where the placement setting says. Checking reads a bit that is already there and reports which units disagree -- which is the direction you want when a device is sending you bytes with parity in the top bit and something is wrong.",
  order: 10,
};

const DIRECTION_CODE: Def = {
  id: OPTION_DIRECTION,
  label: "Direction",
  group: "direction",
  kind: "enum",
  choices: [
    { value: "apply", label: "Encode", summary: "Data in, framed bits out" },
    { value: "check", label: "Decode", summary: "Bits in, data out" },
  ],
  summary: "Which way through the frame.",
  detail:
    "Encoding takes bytes and shows the bits that go on the wire. Decoding takes those bits back -- paste a run of ones and zeros out of a logic analyser and it recovers the bytes, reporting any frame whose parity or stop bit was wrong. Anything that is not a 0 or a 1 is ignored, so spaces, underscores and 0b prefixes can be left in.",
  order: 10,
};

/**
 * A third pair, for the three codes.
 *
 * "Encode / Decode" is right for all three, but the *explanation* is not the UART one: a codeword is
 * not a picture of a wire, and decoding it can repair damage rather than merely reading it back. That
 * difference -- decoding *changes* the data when it corrects -- is the thing worth saying, and it is
 * why this is a third definition rather than a shared one with vaguer prose.
 */
const DIRECTION_ECC: Def = {
  id: OPTION_DIRECTION,
  label: "Direction",
  group: "direction",
  kind: "enum",
  choices: [
    { value: "apply", label: "Encode", summary: "Data in, codewords out" },
    { value: "check", label: "Decode", summary: "Codewords in, data out and damage repaired" },
  ],
  summary: "Add the check symbols, or read them back and repair.",
  detail:
    "Encoding appends or interleaves the check symbols and hands back something longer than it was given. Decoding is the direction that does the work: it locates whatever has been damaged, repairs it if the code can, and says what it changed. Where the damage is beyond the code's reach it refuses rather than guessing -- a decoder that returned the nearest valid codeword regardless would hand back data that is silently not what was sent, which is worse than no answer.",
  order: 10,
};

const PARITY_BIT: Def = {
  id: OPTION_PARITY,
  label: "Parity",
  group: "frame",
  kind: "enum",
  choices: [
    { value: "even", label: "Even", summary: "The bit makes the count of ones even" },
    { value: "odd", label: "Odd", summary: "The bit makes the count of ones odd" },
    { value: "mark", label: "Mark", summary: "Always 1 — detects nothing", insecure: true },
    { value: "space", label: "Space", summary: "Always 0 — detects nothing", insecure: true },
  ],
  summary: "Which convention.",
  detail:
    "Even and odd are the two that are actually parity: the bit is chosen so the total number of ones in the unit, including the bit itself, comes out even or odd. Mark and space are constants -- always 1 and always 0 -- so they carry no information about the data and detect nothing at all. They exist because some equipment uses that slot as a ninth data bit or as an address/data flag, and a tool that could not reproduce a mark-parity byte could not talk to it.",
  order: 10,
};

const FRAME_PARITY: Def = {
  ...PARITY_BIT,
  choices: [
    { value: "none", label: "None", summary: "No parity bit in the frame — 8N1" },
    ...PARITY_BIT.choices!,
  ],
  detail: `${PARITY_BIT.detail} A frame can also have no parity bit at all, which is what the N in 8N1 means and what almost everything uses today: a CRC over the whole message catches far more than one bit per byte ever could.`,
  order: 20,
};

const SCOPE: Def = {
  id: OPTION_SCOPE,
  label: "Scope",
  group: "frame",
  kind: "enum",
  choices: [
    { value: "byte", label: "Each byte", summary: "One parity bit per byte, as a UART sends" },
    { value: "message", label: "Whole message", summary: "One parity bit for everything" },
  ],
  summary: "One bit per byte, or one bit in total.",
  detail:
    "Per byte is the serial case and the useful one. Whole-message parity is one bit over every bit of the input -- the parity of the XOR of all the bytes -- which is what a parity-protected memory word or a very old tape format carries. It is the weakest check that exists: any two flipped bits cancel, and so does any byte appearing twice.",
  order: 5,
};

const DATA_BITS_PARITY: Def = {
  id: OPTION_DATA_BITS,
  label: "Data bits",
  group: "frame",
  kind: "number",
  arg: { placeholder: "8", min: 5, max: 8 },
  // Only per-byte parity has a data width; a whole-message bit covers every bit there is.
  availableOn: [TAG_PER_BYTE],
  summary: "How many low bits of each byte count.",
  detail:
    "Seven is the setting to know about. A device sending 7-bit ASCII with parity in the top bit produces bytes that look exactly like 8-bit data, so computing 8-bit parity over them folds the parity bit back into its own input and gives an answer that is always even. If a capture disagrees with this tool by exactly the parity bit, this is why.",
  order: 20,
};

const DATA_BITS_UART: Def = {
  ...DATA_BITS_PARITY,
  arg: { placeholder: "8", min: 5, max: 9 },
  availableOn: undefined,
  detail: `${DATA_BITS_PARITY.detail} Nine is the multidrop case: the ninth bit flags whether the frame is an address or data, and it is carried instead of a parity bit rather than as well as one.`,
  order: 10,
};

const PLACEMENT: Def = {
  id: OPTION_PLACEMENT,
  label: "Result layout",
  group: "output",
  kind: "enum",
  choices: [
    {
      value: "byte-each",
      label: "One byte each",
      summary: "00 or 01 per input byte — unambiguous as bytes",
    },
    {
      value: "packed",
      label: "Packed bits",
      summary: "One bit per input byte, eight to a byte",
    },
    {
      value: "high-bit",
      label: "In the top bit of the data",
      summary: "The 7-bit-plus-parity byte itself",
    },
  ],
  // Whole-message parity is one bit: there is nothing to lay out, and the other two choices would
  // describe a result that does not exist.
  availableOn: [TAG_PER_BYTE, TAG_APPLY],
  summary: "Where the computed bits go.",
  detail:
    "This decides the shape of the *bytes* the tool hands back, not how the answer reads -- the Parity bits row beside the result always spells the bits out in order, whichever layout and whichever output encoding are chosen. One byte each spends eight bits saying one and is the unambiguous choice when something downstream expects one byte per input byte. Packed is the bit string -- one bit per input byte, most significant first -- which is what you want when the parity bits travel separately, as a parity plane or a column of a memory array; it is the compact one, and the padding at the end is stated with the result because nothing in the bytes themselves distinguishes it from data. In the top bit gives the byte a 7E1 device actually transmits, so it is the one to compare against a capture; it needs seven data bits or fewer, because eight data bits plus a parity bit is nine bits and does not fit in a byte.",
  order: 10,
};

const STOP_BITS_OPTION: Def = {
  id: OPTION_STOP_BITS,
  label: "Stop bits",
  group: "frame",
  kind: "enum",
  choices: [
    { value: "1", label: "1" },
    { value: "1.5", label: "1.5", summary: "Only ever seen with 5 data bits" },
    { value: "2", label: "2" },
  ],
  summary: "How long the line idles between frames.",
  detail:
    "A stop bit is the line returning to idle, so its value is always 1 and only its duration varies. One and a half is a duration rather than a bit -- the receiver waits an extra half bit time and the line does not change -- which is why the frame shown for 1.5 looks the same as for 1 while the transmission time differs by 5%. It exists for the mechanical teleprinters that needed the extra moment, which is also why it is only ever paired with five data bits.",
  order: 30,
};

const BIT_ORDER: Def = {
  id: OPTION_BIT_ORDER,
  label: "Bit order",
  group: "frame",
  kind: "enum",
  choices: [
    { value: "lsb", label: "LSB first", summary: "What every real UART does" },
    { value: "msb", label: "MSB first", summary: "For comparing against a misread capture" },
  ],
  summary: "Which end of the byte goes first.",
  detail:
    "A UART transmits the least significant bit first, always, which is why a byte on the wire reads backwards from the byte in memory: 'A' is 0x41, or 0100_0001, and it goes out as 1000_0010. MSB first is offered because reading a capture the wrong way round is the most common mistake made with one of these, and seeing both is how you discover that is what happened. Note that 0x55 and 0xff are symmetrical, so they cannot tell you which way round you are reading.",
  order: 40,
};

const INVERTED: Def = {
  id: OPTION_INVERTED,
  label: "Inverted levels",
  group: "frame",
  kind: "boolean",
  summary: "Idle low, start bit high — what an RS-232 driver does.",
  detail:
    "At TTL levels the line idles high and the start bit pulls it low. On the RS-232 side of a level shifter every level is inverted, so the same frame captured there reads as the exact complement -- which looks like a completely broken UART until you know. Turning this on shows that view, and decoding with it on reads such a capture correctly.",
  order: 50,
};

const BAUD: Def = {
  id: OPTION_BAUD,
  label: "Baud",
  group: "frame",
  kind: "number",
  arg: { placeholder: "9600", min: 50, max: 20_000_000, unit: "bits/s" },
  summary: "For the timing figures, not for the bits.",
  detail:
    "The bit pattern does not depend on the line rate, but the two questions people ask next do: how long one frame takes, and how many bytes per second that works out to. Note the second is not the first divided by eight -- a byte at 8N1 costs ten bit times, so 9600 baud carries 960 bytes per second, and adding parity and a second stop bit drops it to 800.",
  order: 60,
};

const SPACED: Def = {
  id: OPTION_SPACED,
  label: "Separate the fields",
  group: "output",
  kind: "boolean",
  summary: "A space between start, data, parity and stop.",
  detail:
    "On by default, because the whole reason to look at a frame is to see which bit is which, and ten undivided ones and zeros is what you already had in the capture. Turn it off to get a continuous bit string you can paste somewhere else -- or back into this tool's Decode direction, which ignores the spaces either way.",
  order: 20,
};

const HAMMING_CODE: Def = {
  id: OPTION_HAMMING_CODE,
  label: "Code",
  group: "frame",
  kind: "enum",
  choices: [
    { value: "8-4", label: "Hamming(8,4) — SECDED", summary: "4 data bits, corrects one, detects two" },
    { value: "7-4", label: "Hamming(7,4)", summary: "4 data bits, corrects one, miscorrects two" },
    { value: "16-11", label: "Hamming(16,11) — SECDED", summary: "11 data bits, corrects one, detects two" },
    { value: "15-11", label: "Hamming(15,11)", summary: "11 data bits, corrects one, miscorrects two" },
  ],
  summary: "How many data bits per codeword, and whether two errors are detected.",
  detail:
    "Two independent choices in one control. The *width* decides the overhead: four data bits in eight is 100% expansion, eleven in sixteen is 45%, and the wider code is cheaper for the same guarantee -- one corrected error per codeword, over a longer codeword. The *extension* decides what happens with two errors, and it matters more than it sounds: an unextended Hamming code has no way to notice, so it 'corrects' a double error into a third, wrong value and reports success. The extra parity bit over the whole codeword is enough to tell 'one error, here' from 'two errors, somewhere', so it refuses instead of lying. Both extended forms are also byte-aligned, which is why (8,4) is the default.",
  order: 10,
};


const RS_PROFILE: Def = {
  id: OPTION_RS_PROFILE,
  label: "Field",
  group: "frame",
  kind: "enum",
  choices: [
    { value: "qr", label: "QR Code", summary: "0x11d, generator base 0" },
    { value: "datamatrix", label: "Data Matrix / Aztec", summary: "0x12d, generator base 1" },
  ],
  summary: "Which standard's arithmetic to use.",
  detail:
    "Not a preference: the two are different codes. QR Code builds GF(256) from x^8 + x^4 + x^3 + x^2 + 1 and puts the generator's first root at alpha^0; Data Matrix uses x^8 + x^5 + x^3 + x^2 + 1 and starts at alpha^1. A codeword valid under one is meaningless under the other, and there is nothing in the parity symbols to say which produced them -- so reproducing a value means matching whichever standard made it. The polynomial is a select rather than a number field for that reason: a free choice would invite a field nothing else in the world uses.",
  order: 10,
};

const RS_ECC: Def = {
  id: OPTION_RS_ECC,
  label: "ECC symbols",
  group: "frame",
  kind: "number",
  arg: { placeholder: String(DEFAULT_RS_ECC), unit: "bytes", min: 1, max: 254, step: 1 },
  summary: "How many parity bytes to append.",
  detail:
    "Each pair of parity symbols buys one corrected byte, so ten symbols repair five damaged bytes anywhere in the block -- and a damaged byte is a damaged byte whether one bit flipped or all eight, which is the whole reason to reach for a symbol code. The block holds 255 symbols in total, data and parity together, so the message length plus this cannot exceed that. QR uses between 7 and 30 depending on the error-correction level; Data Matrix between 5 and 68.",
  order: 20,
};

const BCH_PROFILE: Def = {
  id: OPTION_BCH_PROFILE,
  label: "Code",
  group: "frame",
  kind: "enum",
  choices: [
    { value: "qr-format", label: "BCH(15,5) — QR format info", summary: "5 data bits, masked" },
    { value: "qr-version", label: "BCH(18,6) — QR version info", summary: "6 data bits, unmasked" },
  ],
  summary: "Which of QR's two metadata codes.",
  detail:
    "Both are cyclic codes over GF(2) and both correct three bit errors. The format code protects the five bits naming the error-correction level and the mask pattern, and it XORs a fixed 0x5412 afterwards -- which exists so that a blank or destroyed region does not read as a valid format. The version code protects the six bits naming the symbol version and needs no mask, because version 0 is not a version. Decoding here compares against every codeword rather than solving algebraically, which finds the nearest one whatever the distance; the two codes have only 32 and 64 codewords, so that is affordable and is a stronger guarantee than an algebraic decoder gives.",
  order: 10,
};

const HADAMARD_ORDER_OPTION: Def = {
  id: OPTION_HADAMARD_ORDER,
  label: "Order",
  group: "frame",
  kind: "enum",
  choices: [
    { value: "16", label: "Order 16 — [16, 5, 8]", summary: "5 data bits, 16 codeword bits, corrects 3" },
    { value: "32", label: "Order 32 — [32, 6, 16] (Mariner 9)", summary: "6 data bits, 32 codeword bits, corrects 7" },
    { value: "64", label: "Order 64 — [64, 7, 32]", summary: "7 data bits, 64 codeword bits, corrects 15" },
  ],
  summary: "The Hadamard matrix dimension (codeword length in bits).",
  detail:
    "Walsh-Hadamard codes have parameters [2^m, m+1, 2^(m-1)]. Order 16 carries 5 data bits in 16 bits; order 32 (used by Mariner 9 in 1971) carries 6 data bits in 32 bits.",
  order: 20,
};

/**
 * One `Record`, and a miss throws.
 *
 * The sixth time this repo has used this shape rather than a chain ending in a default, and for the
 * reason the earlier five record -- one of them shipped, giving the Salsa tools RC4's key rules with
 * every test still green. A tool added to the metadata without an entry here fails by name.
 */
const BY_TOOL: Record<string, readonly Def[]> = {
  parity: [DIRECTION_APPLY, PARITY_BIT, SCOPE, DATA_BITS_PARITY, PLACEMENT],
  uart: [
    DIRECTION_CODE,
    DATA_BITS_UART,
    FRAME_PARITY,
    STOP_BITS_OPTION,
    BIT_ORDER,
    INVERTED,
    BAUD,
    SPACED,
  ],
  hamming: [DIRECTION_ECC, HAMMING_CODE],
  reedsolomon: [DIRECTION_ECC, RS_PROFILE, RS_ECC],
  bch: [DIRECTION_ECC, BCH_PROFILE],
  golay: [DIRECTION_ECC],
  hadamard: [DIRECTION_ECC, HADAMARD_ORDER_OPTION],
};

const CACHE = new Map<string, OptionCatalogue<ParityOptionGroup>>();

/** Memoised per tool: `ToolDefinition.catalogue` is resolved once, and this never changes. */
export function parityCatalogueFor(meta: ParityToolMeta): OptionCatalogue<ParityOptionGroup> {
  let catalogue = CACHE.get(meta.id);
  if (!catalogue) {
    const options = BY_TOOL[meta.id];
    if (!options) throw new Error(`No parity option catalogue for tool: ${meta.id}`);
    // The metadata's `exposes` is what the tests read and what documents the tool; this is what the
    // form renders. They have to agree, and a test asserts it rather than one being derived from the
    // other -- a derivation would make the disagreement impossible to see.
    catalogue = createOptionCatalogue<ParityOptionGroup>([...options]);
    CACHE.set(meta.id, catalogue);
  }
  return catalogue;
}

/** Every option definition in the family, deduplicated by id, for the family-wide tests. */
export const ALL_PARITY_OPTIONS: readonly Def[] = Object.values(BY_TOOL).flat();

export { TAG_FRAMED };
