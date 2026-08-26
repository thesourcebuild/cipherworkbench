/**
 * The three computations, and one convention worth stating before any of them.
 *
 * A parity bit is one bit, and this app's contract is bytes in, bytes out. So every result here has
 * to decide how a bit becomes something you can read, and the answer is *never implicit*: the
 * `parity` tool has a Result layout control with three named choices, and the `uart` tool returns
 * text because a frame is a diagram rather than a value. Silently packing bits into bytes and letting
 * the output-encoding menu spell them would be a third convention nobody chose, and a reader could
 * not tell padding from data.
 */
import {
  BCH_PROFILES,
  bchDecode,
  bchEncode,
  hammingEncode,
  hammingDecode,
  messageParity,
  RS_PROFILES,
  rsDecode,
  rsEncode,
  packBits,
  parityBit,
  parseBitString,
  uartDecode,
  uartFrame,
  uartFrameBits,
  type ParityMode,
  type UartConfig,
} from "@ocs/algos";
import type { ToolResult, ToolResultField } from "@ocs/engine";
import { requireParityTool } from "./catalogue/tool-meta";
import {
  readBaud,
  readBitOrder,
  readDataBits,
  readDirection,
  readFrameParity,
  readHammingCode,
  readInverted,
  readParityMode,
  readPlacement,
  readScope,
  readBchProfile,
  readRsEcc,
  readRsProfile,
  readSpaced,
  readStopBits,
} from "./pure";
import type { ParitySpec } from "./spec";

const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

export async function computeParity(spec: ParitySpec, input: Uint8Array): Promise<ToolResult> {
  const tool = requireParityTool(spec.variant);
  try {
    switch (tool.kind) {
      case "parity":
        return parityResult(spec, input);
      case "uart":
        return uartResult(spec, input);
      case "hamming":
        return hammingResult(spec, input);
      case "reedsolomon":
        return reedSolomonResult(spec, input);
      case "bch":
        return bchResult(spec, input);
    }
  } catch (thrown) {
    // A refusal the resolver cannot see -- an impossible placement, a bit string that is not one --
    // renders as a result rather than throwing out of the workbench. Same wrapper as the cipher and
    // format families, and for the same reason: a half-typed input is a normal state of a text box.
    return { error: thrown instanceof Error ? thrown.message : String(thrown) };
  }
}

/**
 * A monospace table: headings, rows, every column padded to the wider of the two.
 *
 * Shared by the UART frame diagram and the parity working, which is the second caller that made it
 * worth extracting. Both learned the same lesson from the same report -- a header whose labels are
 * wider than the fields they name lines up with nothing, and an unlabelled column is worse than no
 * column -- so the padding lives in one place rather than being got right twice.
 */
function alignTable(headings: readonly string[], rows: readonly (readonly string[])[]): string {
  const widths = headings.map((heading, column) =>
    Math.max(heading.length, ...rows.map((row) => row[column]!.length)),
  );
  const line = (cells: readonly string[]): string =>
    cells
      .map((cell, column) => cell.padEnd(widths[column]!))
      .join("  ")
      .trimEnd();
  return [line(headings), ...rows.map(line)].join("\n");
}

/**
 * The thirty-three ASCII names, because on a serial link they are the interesting bytes.
 *
 * The first version of this printed a dot for everything outside 0x21..0x7e, which is 161 of the 256
 * possible bytes rendered identically -- and the ones it hid are precisely the ones a serial capture is
 * full of. A protocol framed `STX ... ETX` is recognisable at a glance and unreadable as
 * `. ... .`; DC1 and DC3 are XON and XOFF, so a stalled link is visible in this column; and CR against
 * LF against CR LF is the difference between three line endings.
 *
 * `SP` for the space is the same idea one step further: a space rendered as itself is an empty cell,
 * which is the ambiguity these tables exist to remove.
 */
const ASCII_NAMES: readonly string[] = [
  "NUL", "SOH", "STX", "ETX", "EOT", "ENQ", "ACK", "BEL",
  "BS", "HT", "LF", "VT", "FF", "CR", "SO", "SI",
  "DLE", "DC1", "DC2", "DC3", "DC4", "NAK", "SYN", "ETB",
  "CAN", "EM", "SUB", "ESC", "FS", "GS", "RS", "US",
];

/**
 * What a byte is called: a control name, `SP`, the character itself, `DEL`, or a dot.
 *
 * Every byte from 0x00 to 0x7f is named. Above that nothing can be, and the dot is the honest answer
 * rather than a gap: 0x80..0xff has no character without knowing which code page is in force, the byte
 * column beside this one already carries the value, and guessing Latin-1 would put a glyph on screen
 * that the far end may never have meant. Note also that in a 7-bit format those bytes are usually
 * 7-bit ASCII with a parity bit set -- which is what the Bits column shows, since it is masked to the
 * data width.
 */
function charOf(byte: number): string {
  if (byte < 0x20) return ASCII_NAMES[byte]!;
  if (byte === 0x20) return "SP";
  if (byte < 0x7f) return String.fromCharCode(byte);
  if (byte === 0x7f) return "DEL";
  return ".";
}


/** Bits, most significant first, grouped in fours -- which is what makes eight of them countable. */
function bitsOf(value: number, width: number): string {
  const bits = value
    .toString(2)
    .padStart(width, "0")
    .split("")
    .reverse();
  const groups: string[] = [];
  for (let i = 0; i < bits.length; i += 4) groups.push(bits.slice(i, i + 4).reverse().join(""));
  return groups.reverse().join(" ");
}

/** How many bits are set, which is the number the parity bit is decided by. */
function onesIn(value: number): number {
  let count = 0;
  for (let x = value; x !== 0; x >>= 1) count += x & 1;
  return count;
}

/** Rows are capped and the cap is stated: "the first 256 of 4 million" is information. */
const WORKING_ROWS = 256;

function workingNote(total: number): string {
  return total > WORKING_ROWS
    ? `\n\n... and ${total - WORKING_ROWS} more. A working is for reading, so it stops at ${WORKING_ROWS}.`
    : "";
}

// ─────────────────────────────────────────────────────────────── The parity bit

function parityResult(spec: ParitySpec, input: Uint8Array): ToolResult {
  const mode = readParityMode(spec.options) as ParityMode;
  const scope = readScope(spec.options);
  const direction = readDirection(spec.options);

  if (scope === "message") {
    if (input.length === 0) return { error: "Nothing to take the parity of — the input is empty." };
    const bit = messageParity(input, mode);
    return {
      bytes: new Uint8Array([bit]),
      fields: [
        { label: "Parity bit", value: String(bit) },
        {
          label: "Covers",
          value: `${input.length} byte${input.length === 1 ? "" : "s"}, ${input.length * 8} bits`,
        },
        {
          label: "What it catches",
          value:
            "Any odd number of flipped bits anywhere in the message, and no even number. Two flips cancel, and so does a byte repeated twice.",
        },
      ],
    };
  }

  if (input.length === 0) {
    // Every other tool in the app says this rather than returning zero bytes. An empty Result panel
    // with no explanation reads as the tool being broken, which is the one thing worse than an error.
    return { error: "Nothing to compute parity over — the input is empty." };
  }

  const dataBits = readDataBits(spec.options, 8, 8);
  if (direction === "check") return checkParity(spec, input, mode, dataBits);

  const placement = readPlacement(spec.options);
  if (placement === "high-bit" && dataBits > 7) {
    /**
     * Refused rather than clamped, because there is no answer to give.
     *
     * Eight data bits plus a parity bit is nine bits on the wire, which is exactly why 8E1 frames are
     * eleven bits long and why a UART with 8E1 cannot hand you a byte with the parity in it. This is
     * the "refuse only what the thing genuinely cannot do" case, alongside AES's key sizes -- the
     * message names the two ways out rather than only saying no.
     */
    return {
      error: `Eight data bits leave no room for a parity bit in the same byte: 8${mode[0]!.toUpperCase()}1 is nine bits on the wire. Drop to 7 data bits, or choose a different result layout.`,
    };
  }

  const bits = [...input].map((byte) => parityBit(byte, mode, dataBits));
  const ones = bits.filter((bit) => bit === 1).length;

  const bytes =
    placement === "packed"
      ? packBits(bits)
      : placement === "byte-each"
        ? new Uint8Array(bits)
        : Uint8Array.from(input, (byte, i) => (byte & ((1 << dataBits) - 1)) | (bits[i]! << 7));

  /**
   * The bits themselves, and this field is the answer to "what is this".
   *
   * It exists because of a real report. The default layout is one byte per input byte and the default
   * output encoding for this family is binary, so ten input bytes rendered as
   * `00000000 00000001 00000001 ...` -- eighty characters carrying ten bits, with no way to read the
   * answer off it. The primary value's job is to be *usable* (copied, saved, fed to something that
   * expects bytes), and it cannot also be the legible form under every layout and every encoding.
   *
   * So the bits are stated once, in order, independent of both. Grouped in eights because that is what
   * `encodeBinary` does and the familiar convention, and the count is given because a grouped string is
   * exactly the thing somebody miscounts.
   */
  const LIMIT = 512;
  const grouped = bits
    .slice(0, LIMIT)
    .join("")
    .replace(/(.{8})/g, "$1 ")
    .trim();
  const fields: ToolResultField[] = [
    {
      label: "Parity bits",
      value:
        bits.length > LIMIT
          ? `${grouped} ... and ${bits.length - LIMIT} more`
          : grouped,
    },
    { label: "Bits set", value: `${ones} of ${bits.length}` },
  ];
  if (placement === "packed") {
    // The one layout where the reader cannot tell data from padding, so the padding is stated.
    const padding = bytes.length * 8 - bits.length;
    fields.push({
      label: "Padding",
      value:
        padding === 0
          ? "None — the bit count is a multiple of eight"
          : `${padding} zero bit${padding === 1 ? "" : "s"} at the end of the last byte`,
    });
  }
  if (placement === "high-bit") {
    fields.push({
      label: "Layout",
      value: `Bit 7 is the parity bit; bits 0 to ${dataBits - 1} are the data. This is the byte a ${dataBits}${mode[0]!.toUpperCase()}1 device transmits.`,
    });
  }

  /**
   * The working: one row per input byte, showing how its bit was decided.
   *
   * Asked for directly, and it is the right thing to ask for -- the result is one bit per byte and
   * every step behind it is short: the byte, the bits that were counted, how many are set, and what
   * that makes the parity bit. Nothing in the answer is then something a reader has to take on trust.
   *
   * The Bits column shows *what was counted*, not the whole byte, and says so in its heading whenever
   * the data width is under eight. That is the setting most likely to be misread -- a 7-bit ASCII byte
   * with parity already in bit 7 looks exactly like 8-bit data -- so showing eight bits of context for
   * a seven-bit count would be the wrong kind of helpful.
   */
  const counted = (1 << dataBits) - 1;
  const label = `${mode[0]!.toUpperCase()}${mode.slice(1)}`;
  const working = alignTable(
    [
      "Char",
      "Byte",
      dataBits === 8 ? "Bits" : `Bits (low ${dataBits})`,
      "Ones",
      // Mark and space do not depend on the count, so calling their column a "parity bit" would be
      // the overclaim `P002` exists to avoid.
      mode === "even" || mode === "odd" ? `${label} parity bit` : `${label} bit`,
    ],
    [...input].slice(0, WORKING_ROWS).map((byte, index) => [
      charOf(byte),
      `0x${byte.toString(16).padStart(2, "0")}`,
      bitsOf(byte & counted, dataBits),
      String(onesIn(byte & counted)),
      String(bits[index]!),
    ]),
  );

  return { bytes, fields, working: working + workingNote(input.length) };
}

/**
 * Check: read the bit that is already in the top of each byte and say which bytes disagree.
 *
 * Reported as a list of offsets rather than a count, because the count answers "is something wrong"
 * and the offsets answer "what". Capped, because a wrong parity *setting* makes every byte fail and a
 * list of forty thousand offsets is not a diagnosis -- the cap is stated rather than silently applied.
 */
function checkParity(
  spec: ParitySpec,
  input: Uint8Array,
  mode: ParityMode,
  dataBits: number,
): ToolResult {
  if (input.length === 0) return { error: "Nothing to check — the input is empty." };
  if (dataBits > 7) {
    return {
      error: `Checking reads the parity bit out of bit 7, so the data can be at most 7 bits wide. At 8 data bits the parity bit is not in the byte at all.`,
    };
  }

  const bad: number[] = [];
  const mask = (1 << dataBits) - 1;
  for (let i = 0; i < input.length; i++) {
    const carried = (input[i]! >> 7) & 1;
    if (carried !== parityBit(input[i]! & mask, mode, dataBits)) bad.push(i);
  }

  const LIMIT = 32;
  const shown = bad.slice(0, LIMIT);
  const fields: ToolResultField[] = [
    { label: "Checked", value: `${input.length} byte${input.length === 1 ? "" : "s"}` },
    { label: "Failed", value: String(bad.length) },
  ];
  if (bad.length > 0) {
    fields.push({
      label: "At offsets",
      value:
        shown.join(", ") + (bad.length > LIMIT ? `, and ${bad.length - LIMIT} more` : ""),
    });
  }
  if (bad.length === input.length && input.length > 1) {
    // Every byte failing is almost never every byte being corrupt.
    fields.push({
      label: "Note",
      value:
        "Every byte failed, which usually means the setting is wrong rather than the data. Try the other parity mode, or a different data width.",
    });
  }

  /**
   * The working, in the direction where it matters most.
   *
   * Checking answers "which bytes are wrong", and a list of offsets says *where* without saying why.
   * These columns say why: the bit that arrived, the bit the data implies, and whether they agree. The
   * side-by-side comparison is also what makes a wrong *setting* obvious -- every row failing, with
   * Sent and Wanted differing the same way each time, is odd parity being read as even rather than
   * corrupt data.
   */
  const working = alignTable(
    ["Char", "Byte", `Bits (low ${dataBits})`, "Ones", "Sent", "Wanted", ""],
    [...input].slice(0, WORKING_ROWS).map((byte) => {
      const data = byte & mask;
      const carried = (byte >> 7) & 1;
      const wanted = parityBit(data, mode, dataBits);
      return [
        charOf(data),
        `0x${byte.toString(16).padStart(2, "0")}`,
        bitsOf(data, dataBits),
        String(onesIn(data)),
        String(carried),
        String(wanted),
        carried === wanted ? "ok" : "FAIL",
      ];
    }),
  );

  // The data with the parity bit stripped, which is what you actually wanted out of a 7E1 stream.
  return {
    bytes: Uint8Array.from(input, (byte) => byte & mask),
    fields,
    working: working + workingNote(input.length),
  };
}

// ─────────────────────────────────────────────────────────────── The UART frame

function configFor(spec: ParitySpec): UartConfig {
  return {
    dataBits: readDataBits(spec.options, 8, 9),
    parity: readFrameParity(spec.options),
    stopBits: readStopBits(spec.options),
    lsbFirst: readBitOrder(spec.options) === "lsb",
    inverted: readInverted(spec.options),
  };
}

function uartResult(spec: ParitySpec, input: Uint8Array): ToolResult {
  const config = configFor(spec);
  if (config.dataBits === 9 && config.parity !== "none") {
    return {
      error:
        "Nine data bits and a parity bit do not coexist: the ninth bit occupies the parity slot, which is what makes it an address/data flag. Set parity to None, or drop to 8 data bits.",
    };
  }
  return readDirection(spec.options) === "check"
    ? decodeFrames(spec, input, config)
    : encodeFrames(spec, input, config);
}

/**
 * One row per byte, as a table with every column labelled.
 *
 * The first version printed `30 0  0 00001100 1` under a header of `start data(8) stop`, and three
 * separate things were wrong with it. The leading hex and character columns had no headings at all, so
 * for the input "0" the digit appeared three times with nothing to say which was which. The header
 * labels were wider than the fields they named -- five characters of "start" over a one-bit field --
 * so nothing lined up past the first column. And the data column did not say it was *reversed*: 0x30
 * is 0011_0000 and the frame shows 0000_1100, which reads as a bug until you know a UART sends the
 * least significant bit first.
 *
 * So: every column is named, every column is padded to the wider of its heading and its values, and
 * the data heading states the bit order. That is what makes the table answer "which bit is which",
 * which is the only reason to look at a frame at all.
 */
function encodeFrames(spec: ParitySpec, input: Uint8Array, config: UartConfig): ToolResult {
  if (input.length === 0) return { error: "Nothing to frame — the input is empty." };
  const spaced = readSpaced(spec.options);
  const baud = readBaud(spec.options);
  const frameBits = uartFrameBits(config);

  const LIMIT = 256;
  const shown = [...input].slice(0, LIMIT);

  const headings = ["Byte", "Char"];
  if (spaced) {
    for (const field of uartFrame(shown[0]!, config)) {
      headings.push(
        field.name === "start"
          ? "Start"
          : field.name === "parity"
            ? "Parity"
            : field.name === "stop"
              ? "Stop"
              : // The one heading that carries information rather than a name.
                `Data (${config.dataBits} bits, ${config.lsbFirst ? "LSB" : "MSB"} first)`,
      );
    }
  } else {
    headings.push(`Bits (${frameBits} on the wire, ${config.lsbFirst ? "LSB" : "MSB"} first)`);
  }

  const rows = shown.map((byte) => {
    const fields = uartFrame(byte, config);
    const bits = spaced
      ? fields.map((field) => field.bits.join(""))
      : [fields.flatMap((field) => field.bits).join("")];
    return [`0x${byte.toString(16).padStart(2, "0")}`, charOf(byte), ...bits];
  });

  const body = alignTable(headings, rows);
  const truncated =
    input.length > LIMIT
      ? `\n\n... ${input.length - LIMIT} more bytes not shown. A frame diagram is for reading, so it stops at ${LIMIT}.`
      : "";

  return {
    text: body + truncated,
    fields: [
      { label: "Format", value: describeFormat(config) },
      { label: "Bits per frame", value: `${frameBits} (${config.dataBits} of them data)` },
      {
        label: "Bit order",
        value: config.lsbFirst
          ? `Least significant first, which is what every UART does — so 0x41 goes out as 1000 0010 rather than 0100 0001.`
          : `Most significant first. No real UART does this; it is here so a capture read the wrong way round can be recognised.`,
      },
      {
        label: "Efficiency",
        value: `${((config.dataBits / frameBits) * 100).toFixed(1)}% — ${frameBits - config.dataBits} bits of every ${frameBits} are overhead`,
      },
      { label: "One frame takes", value: formatDuration(frameBits / baud) },
      {
        label: "Throughput",
        value: `${(baud / frameBits).toFixed(1)} bytes/s at ${baud.toLocaleString()} baud`,
      },
      {
        label: "Idle level",
        value: config.inverted
          ? "Low. The start bit is high, as on the RS-232 side of a level shifter."
          : "High. The start bit pulls the line low, as at TTL levels.",
      },
    ],
  };
}

function decodeFrames(spec: ParitySpec, input: Uint8Array, config: UartConfig): ToolResult {
  const bits = parseBitString(text(input));
  if (bits.length === 0) {
    return {
      error:
        "No bits found. Paste a run of ones and zeros — spaces, underscores and 0b prefixes are ignored, but nothing else here is a bit.",
    };
  }

  const { frames, trailingBits } = uartDecode(bits, config);
  if (frames.length === 0) {
    return {
      error: `Found ${bits.length} bit${bits.length === 1 ? "" : "s"} but no complete frame. At ${describeFormat(config)} a frame is ${uartFrameBits(config)} bits, and the line idles at ${config.inverted ? "0" : "1"} between them — if the capture is inverted, try the Inverted levels switch.`,
    };
  }

  const parityErrors = frames.filter((f) => f.parityError).map((f) => f.offset);
  const framingErrors = frames.filter((f) => f.framingError).map((f) => f.offset);

  const fields: ToolResultField[] = [
    { label: "Format", value: describeFormat(config) },
    { label: "Frames read", value: `${frames.length} from ${bits.length} bits` },
  ];
  if (parityErrors.length > 0) {
    fields.push({
      label: "Parity errors",
      value: `${parityErrors.length}, at bit offset${parityErrors.length === 1 ? "" : "s"} ${parityErrors.slice(0, 16).join(", ")}`,
    });
  }
  if (framingErrors.length > 0) {
    /**
     * Named separately from parity, because the two point at different faults.
     *
     * A parity error says a bit flipped. A bad stop bit almost always says the *baud rate* is wrong --
     * the receiver is sampling in the middle of somebody else's bit -- so telling a reader "invalid"
     * would throw away the half of the message that says where to look.
     */
    fields.push({
      label: "Framing errors",
      value: `${framingErrors.length}, at bit offset${framingErrors.length === 1 ? "" : "s"} ${framingErrors.slice(0, 16).join(", ")} — a stop bit that is not idle usually means the baud rate or the frame format is wrong, not that the data is corrupt`,
    });
  }
  if (trailingBits > 0) {
    fields.push({
      label: "Trailing bits",
      value: `${trailingBits} left over — the capture stops part-way through a frame`,
    });
  }
  if (parityErrors.length === 0 && framingErrors.length === 0 && trailingBits === 0) {
    fields.push({ label: "Errors", value: "None. Every frame parsed and every parity bit agreed." });
  }

  return { bytes: Uint8Array.from(frames, (frame) => frame.value & 0xff), fields };
}

/** "8N1", "7E2" -- the shorthand every datasheet uses, built from the settings rather than typed. */
function describeFormat(config: UartConfig): string {
  const letter =
    config.parity === "none"
      ? "N"
      : config.parity === "even"
        ? "E"
        : config.parity === "odd"
          ? "O"
          : config.parity === "mark"
            ? "M"
            : "S";
  return `${config.dataBits}${letter}${config.stopBits}`;
}

/**
 * Seconds, in the unit a reader would have used.
 *
 * A frame at 9600 baud is 0.00104 seconds, which nobody says out loud. Scaling to milliseconds and
 * microseconds is the difference between a figure and a number.
 */
function formatDuration(seconds: number): string {
  if (seconds >= 1) return `${seconds.toFixed(3)} s`;
  if (seconds >= 1e-3) return `${(seconds * 1e3).toFixed(3)} ms`;
  return `${(seconds * 1e6).toFixed(2)} µs`;
}

// ────────────────────────────────────────────────────────────── Hamming codes

/**
 * Two widths and two forms, and the packing differs between them for a reason.
 *
 * A 4-bit code carries one nibble, so a byte is two codewords and each gets a byte of its own -- which
 * costs one bit in eight for the unextended form and buys a result whose hex reads a codeword at a
 * time. An 11-bit code does not divide a byte at all, so it has to read the input as a **bit stream**,
 * eleven bits at a time, most significant first. That is the only honest option: any byte-aligned
 * variant would be a different code.
 *
 * The consequence is that the 11-bit forms pad. A message whose bit count is not a multiple of eleven
 * gets zeros in the last codeword, and the count of padding bits is stated rather than left for the
 * reader to work out -- because on the way back those bits are indistinguishable from data.
 */
function hammingResult(spec: ParitySpec, input: Uint8Array): ToolResult {
  const [codeBitsText, dataBitsText] = readHammingCode(spec.options).split("-");
  const dataBits = Number(dataBitsText);
  const codeBits = Number(codeBitsText);
  /**
   * The extended form is the even width, and that is not a coincidence.
   *
   * An unextended Hamming codeword is `2^r - 1` bits -- always odd -- and the extended form adds one
   * overall parity bit to make it `2^r`. So the parity of the codeword length says which form this is,
   * and there is no third possibility to confuse it with.
   */
  const extended = codeBits % 2 === 0;
  const label = `Hamming(${codeBits},${dataBits})${extended ? ", SECDED" : ""}`;
  // Bytes per codeword: one for the 4-bit codes, two for the 11-bit ones.
  const width = codeBits <= 8 ? 1 : 2;

  if (input.length === 0) return { error: "Nothing to encode — the input is empty." };

  if (readDirection(spec.options) === "apply") {
    const totalBits = input.length * 8;
    const count = Math.ceil(totalBits / dataBits);
    const padding = count * dataBits - totalBits;
    const out = new Uint8Array(count * width);
    for (let i = 0; i < count; i++) {
      // Read `dataBits` bits starting at bit `i * dataBits`, most significant first, zero past the end.
      let value = 0;
      for (let b = 0; b < dataBits; b++) {
        const bitIndex = i * dataBits + b;
        const byte = bitIndex >> 3;
        const bit = byte < input.length ? (input[byte]! >> (7 - (bitIndex & 7))) & 1 : 0;
        value = (value << 1) | bit;
      }
      const codeword = hammingEncode(dataBits, value, extended);
      for (let b = 0; b < width; b++) out[i * width + b] = (codeword >>> (8 * (width - 1 - b))) & 0xff;
    }
    return {
      bytes: out,
      fields: [
        { label: "Code", value: label },
        {
          label: "Codewords",
          value:
            width === 1
              ? `${count} — two per input byte, high nibble first`
              : `${count} — one per ${dataBits} bits of input, ${width} bytes each`,
        },
        {
          label: "Overhead",
          value:
            `${dataBits} data bits in ${width * 8}, so ${Math.round((width * 800) / dataBits - 100)}% larger` +
            (extended
              ? "."
              : `, with the top ${width * 8 - codeBits} bit${width * 8 - codeBits === 1 ? "" : "s"} of each codeword left zero as padding.`),
        },
        {
          label: "Guarantee",
          value: extended
            ? "Any one flipped bit is corrected; any two are detected and refused."
            : "Any one flipped bit is corrected. Two are silently miscorrected — see the Checks panel.",
        },
        ...(padding === 0
          ? []
          : [
              {
                label: "Padding",
                value:
                  `${padding} zero bit${padding === 1 ? "" : "s"} in the last codeword. ` +
                  `Decoding cannot tell those from data, so the recovered byte count is stated there too.`,
              },
            ]),
      ],
    };
  }

  if (input.length % width !== 0) {
    return {
      error:
        `${label} reads ${width} byte${width === 1 ? "" : "s"} per codeword, so the input has to be a ` +
        `multiple of ${width}. This one is ${input.length}.`,
    };
  }
  const count = input.length / width;
  const values: number[] = [];
  const corrected: number[] = [];
  const doubles: number[] = [];
  for (let i = 0; i < count; i++) {
    let received = 0;
    for (let b = 0; b < width; b++) received = (received << 8) | input[i * width + b]!;
    // The unextended forms leave the top bit of their byte unused; mask it rather than decoding it.
    const decoded = hammingDecode(dataBits, received & ((1 << codeBits) - 1), extended);
    if (decoded.doubleError) doubles.push(i);
    else if (decoded.correctedPosition !== 0) corrected.push(i);
    values.push(decoded.value);
  }

  // The data bits, concatenated back into a bit stream and then into bytes.
  const totalBits = count * dataBits;
  const out = new Uint8Array(Math.floor(totalBits / 8));
  for (let i = 0; i < count; i++) {
    for (let b = 0; b < dataBits; b++) {
      const bitIndex = i * dataBits + b;
      const byte = bitIndex >> 3;
      if (byte >= out.length) break;
      const bit = (values[i]! >> (dataBits - 1 - b)) & 1;
      if (bit) out[byte] = out[byte]! | (1 << (7 - (bitIndex & 7)));
    }
  }
  const leftover = totalBits - out.length * 8;

  const fields: ToolResultField[] = [
    { label: "Code", value: label },
    { label: "Codewords read", value: String(count) },
    {
      label: "Corrected",
      value:
        corrected.length === 0
          ? "None — every codeword was already clean"
          : `${corrected.length}, at codeword ${corrected.slice(0, 16).join(", ")}`,
    },
  ];
  /**
   * Always present, and empty when there are none.
   *
   * An unextended code cannot report this at all -- at minimum distance 3 a double error is
   * indistinguishable from a different single one, so it miscorrects and says nothing. Rendering the
   * row empty rather than omitting it is what makes the two forms comparable on screen: the same
   * field, blank under (7,4) and populated under (8,4), is the argument for choosing the extended one.
   */
  fields.push({
    label: "Uncorrectable",
    value:
      doubles.length === 0
        ? ""
        : `${doubles.length} codeword${doubles.length === 1 ? " had" : "s had"} two errors, ` +
          `at ${doubles.slice(0, 16).join(", ")} — the data there is not recoverable`,
  });

  /**
   * What the trailing bits were, in whichever way this width leaves them.
   *
   * A 4-bit code packs two codewords per byte, so an odd count leaves half a byte; an 11-bit code
   * leaves whatever the encoder padded. Both are the same fact -- the recovered bit count is not a
   * multiple of eight -- and stating it beats emitting a partial byte, which a reader cannot tell from
   * data.
   */
  if (leftover !== 0) {
    fields.push({
      label: "Note",
      value:
        width === 1
          ? `An odd number of codewords: ${count} is not a whole number of bytes, so the last ` +
            `${dataBits} bits are reported here rather than padded into one.`
          : `${leftover} trailing bit${leftover === 1 ? "" : "s"}, which is what the encoder padded. ` +
            `They are dropped rather than emitted as a partial byte.`,
    });
  }
  return { bytes: out, fields };
}


// ──────────────────────────────────────────────── Reed-Solomon and BCH

/**
 * Reed-Solomon: the data unchanged, followed by the parity symbols.
 *
 * Systematic encoding is what every standard that uses this does, and it is the reason the tool is
 * useful for debugging: the first `n` bytes of the output are the bytes that went in, so a mismatch is
 * localised to the parity immediately.
 */
function reedSolomonResult(spec: ParitySpec, input: Uint8Array): ToolResult {
  const profile = readRsProfile(spec.options);
  const ecc = readRsEcc(spec.options);
  const field = RS_PROFILES[profile];
  const label = profile === "qr" ? "QR Code" : "Data Matrix / Aztec";

  if (input.length === 0) return { error: "Nothing to encode — the input is empty." };

  if (readDirection(spec.options) === "apply") {
    if (input.length + ecc > 255) {
      return {
        error:
          `A Reed-Solomon block over GF(256) holds 255 symbols in total. ` +
          `${input.length} data bytes plus ${ecc} ECC symbols is ${input.length + ecc}; ` +
          `reduce the ECC count or split the message into blocks.`,
      };
    }
    const parity = rsEncode(field, input, ecc);
    const out = new Uint8Array(input.length + ecc);
    out.set(input);
    out.set(parity, input.length);
    return {
      bytes: out,
      fields: [
        { label: "Field", value: label },
        { label: "Block", value: `${input.length} data + ${ecc} ECC = ${out.length} symbols` },
        {
          label: "Guarantee",
          value:
            `Any ${Math.floor(ecc / 2)} damaged bytes anywhere in the block are located and repaired. ` +
            `A damaged byte counts once whether one bit flipped or all eight, which is what a symbol code buys.`,
        },
        { label: "Parity", value: encodeHexSpaced(parity) },
      ],
    };
  }

  if (input.length <= ecc) {
    return {
      error:
        `A codeword needs more than ${ecc} symbols — ${input.length} is all parity and no data. ` +
        `Either this is not a codeword or the ECC count does not match the one that produced it.`,
    };
  }
  const decoded = rsDecode(field, input, ecc);
  if (!decoded) {
    return {
      error:
        `More damage than this code can locate. With ${ecc} ECC symbols it repairs up to ` +
        `${Math.floor(ecc / 2)} damaged bytes; beyond that it refuses rather than returning a valid ` +
        `codeword that is not the one sent.`,
    };
  }
  const data = decoded.codeword.slice(0, input.length - ecc);
  return {
    bytes: data,
    fields: [
      { label: "Field", value: label },
      { label: "Block", value: `${input.length} symbols = ${data.length} data + ${ecc} ECC` },
      {
        label: "Repaired",
        value:
          decoded.corrected.length === 0
            ? "Nothing — every symbol was already correct"
            : `${decoded.corrected.length} byte${decoded.corrected.length === 1 ? "" : "s"}, ` +
              `at position ${decoded.corrected.join(", ")}`,
      },
      {
        label: "Headroom",
        value: `${Math.floor(ecc / 2) - decoded.corrected.length} more damaged bytes would still have been repairable.`,
      },
    ],
  };
}

/**
 * BCH, one codeword per input byte.
 *
 * The data is five or six bits, so one byte in gives one codeword out and the rest of the byte is
 * refused rather than silently masked -- a value that does not fit is a different intention from a
 * value that does, and QR's five-bit format field is exactly where somebody would paste a whole byte
 * by mistake.
 */
function bchResult(spec: ParitySpec, input: Uint8Array): ToolResult {
  const profile = readBchProfile(spec.options);
  const meta = BCH_PROFILES[profile];
  const label = profile === "qr-format" ? "BCH(15,5), QR format information" : "BCH(18,6), QR version information";
  // 15 or 18 bits, so two or three bytes per codeword.
  const width = meta.n <= 16 ? 2 : 3;

  if (input.length === 0) return { error: "Nothing to encode — the input is empty." };

  if (readDirection(spec.options) === "apply") {
    const out = new Uint8Array(input.length * width);
    const rows: string[][] = [];
    for (let i = 0; i < input.length; i++) {
      const value = input[i]!;
      if (value >= 1 << meta.k) {
        return {
          error:
            `${label} carries ${meta.k} bits, so each input byte must be 0 to ${(1 << meta.k) - 1}. ` +
            `Byte ${i} is ${value}.`,
        };
      }
      const codeword = bchEncode(profile, value);
      for (let b = 0; b < width; b++) out[i * width + b] = (codeword >>> (8 * (width - 1 - b))) & 0xff;
      if (rows.length < WORKING_ROWS) {
        rows.push([
          String(i),
          value.toString(2).padStart(meta.k, "0"),
          codeword.toString(2).padStart(meta.n, "0"),
        ]);
      }
    }
    return {
      bytes: out,
      fields: [
        { label: "Code", value: label },
        { label: "Codewords", value: `${input.length} — one per input byte, ${width} bytes each` },
        {
          label: "Guarantee",
          value:
            `Minimum distance ${meta.distance}, so any ${Math.floor((meta.distance - 1) / 2)} flipped ` +
            `bits are corrected. Decoding here compares against every codeword, so it also finds the ` +
            `nearest one beyond that.`,
        },
        ...(meta.mask === 0
          ? []
          : [
              {
                label: "Mask",
                value:
                  `0x${meta.mask.toString(16)} is XORed in after encoding, so an all-zero field is not ` +
                  `a valid codeword — which is what stops a blank region reading as a legitimate format.`,
              },
            ]),
      ],
      working: alignTable(["#", "Data", "Codeword"], rows) + workingNote(input.length),
    };
  }

  if (input.length % width !== 0) {
    return {
      error:
        `${label} is ${meta.n} bits, read as ${width} bytes per codeword — so the input has to be a ` +
        `multiple of ${width} bytes. This one is ${input.length}.`,
    };
  }
  const count = input.length / width;
  const out = new Uint8Array(count);
  const rows: string[][] = [];
  let repaired = 0;
  let ambiguous = 0;
  for (let i = 0; i < count; i++) {
    let received = 0;
    for (let b = 0; b < width; b++) received = (received << 8) | input[i * width + b]!;
    const decoded = bchDecode(profile, received);
    if (!decoded) {
      ambiguous += 1;
      if (rows.length < WORKING_ROWS) rows.push([String(i), received.toString(2).padStart(meta.n, "0"), "—", "ambiguous"]);
      continue;
    }
    out[i] = decoded.data;
    if (decoded.distance > 0) repaired += 1;
    if (rows.length < WORKING_ROWS) {
      rows.push([
        String(i),
        received.toString(2).padStart(meta.n, "0"),
        decoded.data.toString(2).padStart(meta.k, "0"),
        String(decoded.distance),
      ]);
    }
  }
  return {
    bytes: out,
    fields: [
      { label: "Code", value: label },
      { label: "Codewords read", value: String(count) },
      {
        label: "Repaired",
        value:
          repaired === 0
            ? "None — every codeword was already valid"
            : `${repaired} of ${count} had at least one flipped bit`,
      },
      ...(ambiguous === 0
        ? []
        : [
            {
              label: "Ambiguous",
              value:
                `${ambiguous} codeword${ambiguous === 1 ? " was" : "s were"} equidistant from two ` +
                `codewords, so any answer would be a guess. Those bytes are left zero.`,
            },
          ]),
    ],
    working: alignTable(["#", "Received", "Data", "Bits fixed"], rows) + workingNote(count),
  };
}

/** Hex with a space between bytes, which is how a parity block is read. */
function encodeHexSpaced(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join(" ");
}

/**
 * What these settings *are*, for the Info section under the options.
 *
 * The division from `ToolResult.fields` is the one `ToolDefinition.info` states: would this still be
 * true with an empty input. A code's guarantee, its overhead and a UART frame's bit count all follow
 * from the controls the moment they are set, so they belong here and are on screen before anything is
 * typed. What a computation *found* -- which codewords were repaired, how many bits were padding --
 * stays in `fields`.
 */
export function parityInfo(spec: ParitySpec): ToolResultField[] {
  const tool = requireParityTool(spec.variant);
  const direction = readDirection(spec.options);

  switch (tool.kind) {
    case "parity": {
      const mode = readParityMode(spec.options);
      const scope = readScope(spec.options);
      const fields: ToolResultField[] = [
        { label: "Mode", value: `${mode[0]!.toUpperCase()}${mode.slice(1)}` },
        {
          label: "Scope",
          value: scope === "message" ? "The whole message, as one bit" : "Each byte separately",
        },
      ];
      if (scope !== "message") {
        fields.push({ label: "Data bits", value: String(readDataBits(spec.options, 8, 8)) });
        if (direction === "apply") {
          const placement = readPlacement(spec.options);
          fields.push({
            label: "Layout",
            value:
              placement === "high-bit"
                ? "In bit 7 of each byte, as a 7E1-style byte"
                : placement === "packed"
                  ? "One packed bit string, padded to a byte boundary"
                  : "One byte per input byte, holding just the bit",
          });
        }
      }
      fields.push({
        label: "Detects",
        value:
          mode === "even" || mode === "odd"
            ? "Any odd number of flipped bits in a unit. An even number is invisible."
            : "Nothing — this mode is a constant, so it carries no information about the data.",
      });
      return fields;
    }
    case "uart": {
      const config = configFor(spec);
      const baud = readBaud(spec.options);
      const bits = uartFrameBits(config);
      return [
        { label: "Format", value: describeFormat(config) },
        { label: "Bit order", value: config.lsbFirst ? "Least significant first" : "Most significant first" },
        { label: "Levels", value: config.inverted ? "Inverted" : "Idle high, start bit low" },
        {
          label: "Frame",
          value: `${bits} bit times per byte`,
          hint:
            "A half stop bit is a duration rather than a value, so this can be fractional -- 8N1.5 is 10.5 bit times even though the diagram shows one stop bit.",
        },
        {
          label: "Throughput",
          value: `${baud} baud carries ${Math.floor(baud / bits)} bytes/s`,
          hint: "The framing overhead is real: 8N1 spends ten bit times per byte, not eight.",
        },
      ];
    }
    case "hamming": {
      const [codeBitsText, dataBitsText] = readHammingCode(spec.options).split("-");
      const codeBits = Number(codeBitsText);
      const dataBits = Number(dataBitsText);
      const extended = codeBits % 2 === 0;
      const width = codeBits <= 8 ? 1 : 2;
      return [
        { label: "Code", value: `Hamming(${codeBits},${dataBits})${extended ? ", SECDED" : ""}` },
        { label: "Carries", value: `${dataBits} data bits in ${codeBits}, stored in ${width} byte${width === 1 ? "" : "s"}` },
        {
          label: "Minimum distance",
          value: extended ? "4" : "3",
          hint: extended
            ? "Enough to tell one error from two, which is what lets it refuse rather than miscorrect."
            : "Enough to correct one error and no more. Two are indistinguishable from a different single error.",
        },
        {
          label: "Guarantee",
          value: extended
            ? "Corrects any one flipped bit; detects any two and refuses."
            : "Corrects any one flipped bit; silently miscorrects two.",
        },
      ];
    }
    case "reedsolomon": {
      const profile = readRsProfile(spec.options);
      const ecc = readRsEcc(spec.options);
      return [
        {
          label: "Field",
          value: profile === "qr" ? "QR Code — 0x11d, base 0" : "Data Matrix / Aztec — 0x12d, base 1",
          hint: "The two are different codes, not settings of one. A codeword valid under one is meaningless under the other.",
        },
        { label: "ECC symbols", value: `${ecc} bytes appended` },
        {
          label: "Repairs",
          value: `${Math.floor(ecc / 2)} damaged bytes anywhere in the block`,
          hint: "A byte counts once whether one bit flipped or all eight, which is what a symbol code buys over a bit code.",
        },
        { label: "Block limit", value: `${255 - ecc} data bytes, since GF(256) holds 255 symbols in all` },
      ];
    }
    case "bch": {
      const profile = readBchProfile(spec.options);
      const meta = BCH_PROFILES[profile];
      return [
        {
          label: "Code",
          value: profile === "qr-format" ? "BCH(15,5) — QR format information" : "BCH(18,6) — QR version information",
        },
        { label: "Carries", value: `${meta.k} data bits in ${meta.n}` },
        {
          label: "Minimum distance",
          value: String(meta.distance),
          hint: `So any ${Math.floor((meta.distance - 1) / 2)} flipped bits are corrected with certainty.`,
        },
        ...(meta.mask === 0
          ? []
          : [
              {
                label: "Mask",
                value: `0x${meta.mask.toString(16)}, XORed in after encoding`,
                hint: "So that an all-zero field is not a valid codeword, and a destroyed region does not read as a legitimate format.",
              },
            ]),
        {
          label: "Decoding",
          value: "Nearest codeword, over all of them",
          hint: `There are only ${1 << meta.k} codewords, so this is maximum-likelihood decoding rather than bounded-distance: it finds the closest whatever the distance, and reports a tie rather than guessing.`,
        },
      ];
    }
  }
}

/**
 * Internals the tests reach for, and nothing else should.
 *
 * `charOf` is here because the Char column names all 161 otherwise-invisible bytes below 0x80, and a
 * lookup table's failure mode is one wrong entry rather than a wrong shape -- so the test walks all
 * 256. Exporting it beats making the test parse a rendered table.
 */
export const __testing = { charOf, alignTable, bitsOf, onesIn };
