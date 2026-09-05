/**
 * The three tools this family contributes, as eager metadata.
 *
 * They are the same idea at three strengths, which is what makes them one family rather than three
 * strays in `checksum`:
 *
 *  - `parity` computes the bit. It notices an odd number of flipped bits in a unit and nothing else.
 *  - `uart` shows where that bit is transmitted. Nothing here is arithmetic; it is all convention,
 *    and the convention is the part people get wrong.
 *  - `hamming` puts a parity bit over each of several overlapping subsets, so the pattern of failures
 *    names the position that went wrong. One parity bit detects; several overlapping ones locate.
 *  - `reedsolomon` does the same over byte *symbols* in a finite field rather than over bit subsets,
 *    which is what lets it repair a burst that destroys whole bytes.
 *  - `bch` is the step between: parity checks in a finite field over bits, correcting more than one
 *    error. Offered as the two codes QR uses for its own format and version fields.
 *
 * So the family is now genuinely error *correction* rather than parity alone, and the name is the
 * historical one rather than the accurate one. That is a fair criticism and the alternative is worse:
 * splitting these across a `parity` and an `ecc` family would put a boundary where there is none --
 * every one of the five is parity applied over a wider unit than the last.
 *
 * Free of any `@ocs/algos` import, so listing these costs nothing but the strings.
 */
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
  type ParityDefaults,
} from "../pure";

/** Which computation a tool performs. The compute path switches on exactly this. */
export type ParityKind = "parity" | "uart" | "hamming" | "reedsolomon" | "bch" | "golay" | "hadamard";

export interface ParityToolMeta {
  id: string;
  label: string;
  kind: ParityKind;
  /** Sidebar group. */
  category: string;
  /** Catalogue option ids this tool exposes. */
  exposes: readonly string[];
  /**
   * Option values a fresh spec starts with.
   *
   * `OptionValue` rather than `string`, so a number is seeded as a number: `"9600"` is not a seeded
   * baud rate, it is a form showing one value while `optNumber` reads undefined and the resolver
   * falls back. Every `enum` a tool renders must be in here or the control opens on "(not set)".
   */
  defaults: ParityDefaults;
  /** False for a tool whose input is not a byte string. Both of these read one, so both are true. */
  usesInput: boolean;
  /** True where the tool goes both ways, which is what puts `inverse` in the manifest's directions. */
  bidirectional: boolean;
  tags: readonly string[];
  summary: string;
  /**
   * The input `check` is over, as hex, for a tool that cannot take the family's default.
   *
   * BCH is the one that needs it and the reason is structural rather than awkward: its data unit is
   * five bits, so every byte of `123456789` is out of range and the tool correctly refuses them.
   * Masking them down to five bits would make the check value computable and meaningless -- it would
   * be a value for an input nobody supplied. Naming a different input is the honest option.
   */
  checkInput?: string;
  /**
   * What this tool produces for the ASCII input `123456789` in its default configuration, in hex.
   *
   * The same convention the CRC and checksum families use, and it earns its place for the same
   * reason: these are conventions rather than algorithms, so one agreed value over one agreed input
   * is how two implementations confirm they mean the same thing. A test asserts each of these is
   * what the tool actually produces, so the number cannot drift away from the code.
   *
   * Absent for `uart`, whose output is a diagram rather than a value.
   */
  check?: string;
}

export const PARITY_TOOLS: readonly ParityToolMeta[] = [
  {
    id: "parity",
    label: "Parity bit",
    kind: "parity",
    category: "Parity",
    exposes: [
      OPTION_DIRECTION,
      OPTION_PARITY,
      OPTION_SCOPE,
      OPTION_DATA_BITS,
      OPTION_PLACEMENT,
    ],
    defaults: {
      [OPTION_DIRECTION]: "apply",
      [OPTION_PARITY]: "even",
      [OPTION_SCOPE]: "byte",
      [OPTION_DATA_BITS]: 8,
      [OPTION_PLACEMENT]: "byte-each",
    },
    usesInput: true,
    bidirectional: true,
    tags: [
      "parity",
      "parity bit",
      "even parity",
      "odd parity",
      "mark parity",
      "space parity",
      "7e1",
      "8n1",
      "8e1",
      "7o1",
      "serial",
      "uart",
      "rs232",
      "rs485",
      "error detection",
      "popcount",
      "hamming weight",
    ],
    summary: "Even, odd, mark or space parity, per byte or over the whole message.",
    // Even parity of each of 0x31..0x39, one byte per input byte. Derived, and pinned by a test.
    check: "010100010000010100",
  },
  {
    id: "uart",
    label: "UART frame",
    kind: "uart",
    category: "Serial",
    exposes: [
      OPTION_DIRECTION,
      OPTION_DATA_BITS,
      OPTION_PARITY,
      OPTION_STOP_BITS,
      OPTION_BIT_ORDER,
      OPTION_INVERTED,
      OPTION_BAUD,
      OPTION_SPACED,
    ],
    defaults: {
      [OPTION_DIRECTION]: "apply",
      // 8N1 is the default everywhere, so it is the default here: the answer somebody arriving with a
      // capture and no documentation is most likely to be looking at.
      [OPTION_DATA_BITS]: 8,
      [OPTION_PARITY]: "none",
      [OPTION_STOP_BITS]: "1",
      [OPTION_BIT_ORDER]: "lsb",
      [OPTION_BAUD]: 9600,
      [OPTION_SPACED]: true,
    },
    usesInput: true,
    bidirectional: true,
    tags: [
      "uart",
      "serial",
      "rs232",
      "rs422",
      "rs485",
      "ttl",
      "frame",
      "framing",
      "start bit",
      "stop bit",
      "8n1",
      "7e1",
      "baud",
      "bit order",
      "lsb first",
      "logic analyser",
      "logic analyzer",
    ],
    summary: "What a byte looks like on the wire: start bit, data LSB first, parity, stop bits.",
  },
  {
    id: "hamming",
    label: "Hamming code",
    kind: "hamming",
    category: "Error correction",
    exposes: [OPTION_DIRECTION, OPTION_HAMMING_CODE],
    defaults: { [OPTION_DIRECTION]: "apply", [OPTION_HAMMING_CODE]: "8-4" },
    usesInput: true,
    bidirectional: true,
    tags: [
      "hamming",
      "hamming code",
      "hamming(7,4)",
      "hamming(8,4)",
      "hamming(15,11)",
      "hamming(16,11)",
      "secded",
      "ecc",
      "error correction",
      "single error correction",
      "double error detection",
      "syndrome",
      "parity",
    ],
    summary: "Hamming at two widths, each with an extended form that detects two errors as well.",
    // (8,4) of each nibble of 0x31..0x39: two codewords per input byte. Derived, and pinned by a test.
    check: "87d2875587878799874b87cc871e87e18733",
  },
  {
    /**
     * Reed-Solomon over GF(2^8) -- the code in QR, Data Matrix, CDs, DVDs, RAID-6 and Voyager.
     *
     * Two profiles rather than a free choice of field, because the two standards that matter chose
     * different primitive polynomials *and* different generator bases, and a codeword valid under one
     * is meaningless under the other. Offering the polynomial as a number field would invite a value
     * nothing else in the world agrees with.
     */
    id: "reedsolomon",
    label: "Reed-Solomon",
    kind: "reedsolomon",
    category: "Error correction",
    exposes: [OPTION_DIRECTION, OPTION_RS_PROFILE, OPTION_RS_ECC],
    defaults: {
      [OPTION_DIRECTION]: "apply",
      [OPTION_RS_PROFILE]: "qr",
      [OPTION_RS_ECC]: DEFAULT_RS_ECC,
    },
    usesInput: true,
    bidirectional: true,
    tags: [
      "reed-solomon",
      "reed solomon",
      "rs",
      "ecc",
      "error correction",
      "qr code",
      "data matrix",
      "iso 18004",
      "berlekamp-massey",
      "galois field",
      "gf(256)",
      "burst error",
    ],
    summary: "The symbol code behind QR, CDs and RAID-6. Repairs whole bytes, not just bits.",
    // 10 ECC symbols over the ASCII digits, in QR's field. Derived, and pinned by a test.
    check: "3132333435363738398cad8ef131b852feb7fd",
  },
  {
    /**
     * BCH, as the two codes QR uses for its own metadata.
     *
     * A general BCH tool would need the code's parameters as four controls and would offer
     * combinations nothing publishes a value for. These two are what somebody debugging a QR symbol
     * actually needs, and both are published in ISO/IEC 18004 in full.
     */
    id: "bch",
    label: "BCH code",
    kind: "bch",
    category: "Error correction",
    exposes: [OPTION_DIRECTION, OPTION_BCH_PROFILE],
    defaults: { [OPTION_DIRECTION]: "apply", [OPTION_BCH_PROFILE]: "qr-format" },
    usesInput: true,
    bidirectional: true,
    tags: [
      "bch",
      "bose-chaudhuri-hocquenghem",
      "ecc",
      "error correction",
      "qr code",
      "format information",
      "version information",
      "iso 18004",
      "cyclic code",
      "bch(15,5)",
      "bch(18,6)",
    ],
    summary: "QR's own format and version codes: BCH(15,5) and BCH(18,6), corrected by nearest word.",
    /**
     * Nine bytes 0x00..0x08 rather than the family's `123456789`, because five data bits cannot hold
     * an ASCII digit. Nine of them, so the shape still matches every other tool's check value.
     */
    checkInput: "000102030405060708",
    check: "541251255e7c5b4b45f940ce4f974aa077c4",
  },
  {
    id: "golay",
    label: "Golay G_24",
    kind: "golay",
    category: "Error correction",
    exposes: [OPTION_DIRECTION],
    defaults: { [OPTION_DIRECTION]: "apply" },
    usesInput: true,
    bidirectional: true,
    tags: [
      "golay",
      "golay g24",
      "extended binary golay",
      "ecc",
      "error correction",
      "voyager",
      "rate 1/2",
      "finite geometry",
      "mathieu group",
    ],
    summary: "NASA Voyager deep space [24,12,8] code: corrects up to 3 bit errors per 24-bit word.",
    check: "31383f233fef343ea55366e6373a49839107",
  },
  {
    id: "hadamard",
    label: "Walsh-Hadamard",
    kind: "hadamard",
    category: "Error correction",
    exposes: [OPTION_DIRECTION, OPTION_HADAMARD_ORDER],
    defaults: { [OPTION_DIRECTION]: "apply", [OPTION_HADAMARD_ORDER]: "16" },
    usesInput: true,
    bidirectional: true,
    tags: [
      "hadamard",
      "walsh-hadamard",
      "mariner 9",
      "fwht",
      "sylvester matrix",
      "ecc",
      "error correction",
      "maximum likelihood",
    ],
    summary: "Mariner 9 deep space code: decoded by Fast Walsh-Hadamard Transform (FWHT).",
    check: "3c3c0f0faa5566663c3c5aa55555a5a53c3cff0099669999ffff3cc300ff",
  },
];

export const PARITY_TOOL_IDS: readonly string[] = PARITY_TOOLS.map((t) => t.id);

export function getParityTool(id: string): ParityToolMeta | undefined {
  return PARITY_TOOLS.find((t) => t.id === id);
}

/** A miss throws by name, rather than falling through to whichever tool happened to be first. */
export function requireParityTool(id: string): ParityToolMeta {
  const tool = getParityTool(id);
  if (!tool) throw new Error(`Unknown parity tool: ${id}`);
  return tool;
}
