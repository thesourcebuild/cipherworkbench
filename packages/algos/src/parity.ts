/**
 * Parity: one bit, several bits, and overlapping bits.
 *
 * Three things live here and they are the same idea at three strengths, which is why they share a
 * file and a family:
 *
 *  - **A parity bit** over a unit says whether the number of ones in it is even or odd. It detects
 *    any *odd* number of flipped bits and misses every even number, so it catches exactly half of
 *    all multi-bit errors -- which is the whole reason CRCs exist.
 *  - **A UART frame** is where that bit is actually transmitted, between the data and the stop bit.
 *    Nothing here is arithmetic; the difficulty is entirely convention, and it is real convention:
 *    a UART sends data **least significant bit first**, so a byte on the wire reads backwards from
 *    the byte in memory, and every field of the frame is configurable.
 *  - **A Hamming code** puts a parity bit over each of several *overlapping* subsets of the bits,
 *    chosen so the pattern of failures names the position that went wrong. One parity bit detects;
 *    several overlapping ones locate, and locating is correcting.
 *
 * None of this has an oracle. There is no parity in `node:crypto`, no library in this tree
 * implements a UART, and Hamming codes are published as *tables* rather than as test vectors. What
 * stands in is different for each, and each is stated in `tests/algos-parity.test.ts` rather than
 * implied: parity is checked against an independent formulation over all 256 bytes (bit tricks
 * against counting the ones in a string, which are the two ways to get it wrong); the UART frames
 * are checked against the fields written out by hand for values whose bit patterns are asymmetric,
 * because a symmetric one passes under a reversed bit order; and Hamming is checked
 * **exhaustively** -- all sixteen codewords, the published `1011 -> 0110011` example, a minimum
 * distance of 3, and every one of the 112 single-bit errors corrected -- which is stronger than any
 * table of vectors would be.
 */

// ───────────────────────────────────────────────────────────── The parity bit

export type ParityMode = "even" | "odd" | "mark" | "space";

/**
 * The number of set bits in a byte, mod 2.
 *
 * The folding trick rather than a loop or a lookup table: `x ^= x >> 4` puts the parity of the high
 * nibble into the low one, and so on down to one bit. It is the standard formulation and it is here
 * rather than inline because three callers want it and a second copy is how the two drift.
 */
export function byteParity(value: number): number {
  let x = value & 0xff;
  x ^= x >> 4;
  x ^= x >> 2;
  x ^= x >> 1;
  return x & 1;
}

/**
 * The parity bit a given mode would transmit for one unit.
 *
 * `mark` and `space` are constants and that is not an oversight in this function -- it is what those
 * two modes *are*. A mark bit is always 1 and a space bit always 0, so neither carries any
 * information about the data and neither detects anything. They exist because some protocols use the
 * slot as a ninth data bit or as an address/data flag, and a UART that must interoperate has to be
 * able to send them. The lint rule says so; this returns them without comment.
 */
export function parityBit(value: number, mode: ParityMode, dataBits = 8): number {
  switch (mode) {
    case "mark":
      return 1;
    case "space":
      return 0;
    case "even":
      // Even parity: the bit that makes the *total* count of ones even, i.e. the parity of the data.
      return byteParity(value & maskFor(dataBits));
    case "odd":
      return byteParity(value & maskFor(dataBits)) ^ 1;
  }
}

/** Low `bits` set. `dataBits` is 5 to 9, so this never overflows a 32-bit int. */
function maskFor(bits: number): number {
  return bits >= 32 ? 0xffffffff : (1 << bits) - 1;
}

/** The parity of an entire byte string, as one bit. RAM parity, and the weakest check there is. */
export function messageParity(data: Uint8Array, mode: ParityMode): number {
  if (mode === "mark") return 1;
  if (mode === "space") return 0;
  let x = 0;
  for (const byte of data) x ^= byte;
  const bit = byteParity(x);
  return mode === "odd" ? bit ^ 1 : bit;
}

/**
 * Pack bits, most significant first, into bytes; the final byte is zero-padded.
 *
 * MSB-first because that is how a bit string is read when it is written down, so the hex of the
 * result lines up with the bits as printed. The padding is stated by the caller rather than guessed
 * at: a reader who does not know how many bits there were cannot tell padding from data, which is
 * the one thing a bit-packed result must not be ambiguous about.
 */
export function packBits(bits: readonly number[]): Uint8Array {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i++) {
    if (bits[i]! & 1) out[i >> 3]! |= 0x80 >> (i & 7);
  }
  return out;
}

// ─────────────────────────────────────────────────────────────── The UART frame

export interface UartConfig {
  /** 5 to 9. Nine is the multidrop case, where the ninth bit is an address/data flag. */
  dataBits: number;
  parity: ParityMode | "none";
  /** 1, 1.5 or 2. A half stop bit is a duration, not a value, which is why this is a number. */
  stopBits: 1 | 1.5 | 2;
  /**
   * True for the ordinary UART, which sends the least significant data bit first.
   *
   * Configurable because reading a capture the wrong way round is the single most common mistake
   * made with one of these, and being able to see both is how you find that out. Every real UART
   * is LSB-first.
   */
  lsbFirst: boolean;
  /**
   * True to invert every level, which is what an RS-232 line driver does.
   *
   * At TTL levels the line idles high and the start bit is low. On the RS-232 side of a MAX232 the
   * same frame is upside down, so a capture taken there reads as the complement -- which looks like
   * a broken UART until you know.
   */
  inverted: boolean;
}

/** One field of a frame, kept separate so the renderer can label them rather than run them together. */
export interface UartField {
  name: "start" | "data" | "parity" | "stop";
  bits: readonly number[];
}

/**
 * The bits one byte becomes on the wire, in transmission order, as labelled fields.
 *
 * Fields rather than one array, because the whole value of looking at this is seeing *which* bit is
 * which -- a flat run of ten ones and zeros is what you already had in the logic analyser. The
 * inversion is applied last and to everything, since it is a property of the line rather than of the
 * protocol.
 *
 * A 1.5-stop-bit setting emits one stop bit here. The half is a duration the line spends idle, and
 * the line is idle at the stop level anyway, so there is no second value to show -- it changes the
 * timing, which `uartFrameBits` reports, and not the bit pattern.
 */
export function uartFrame(value: number, config: UartConfig): UartField[] {
  const data: number[] = [];
  for (let i = 0; i < config.dataBits; i++) {
    const index = config.lsbFirst ? i : config.dataBits - 1 - i;
    data.push((value >> index) & 1);
  }

  const fields: UartField[] = [
    { name: "start", bits: [0] },
    { name: "data", bits: data },
  ];
  if (config.parity !== "none") {
    fields.push({ name: "parity", bits: [parityBit(value, config.parity, config.dataBits)] });
  }
  fields.push({ name: "stop", bits: config.stopBits === 2 ? [1, 1] : [1] });

  if (!config.inverted) return fields;
  return fields.map((field) => ({ name: field.name, bits: field.bits.map((bit) => bit ^ 1) }));
}

/**
 * Bits per frame, counting a half stop bit as a half.
 *
 * Fractional on purpose: at 1.5 stop bits a frame really does occupy 10.5 bit times, and rounding it
 * would make the transmission time this feeds wrong by 5%. Nobody sends half a bit; everybody who
 * configures 1.5 waits for it.
 */
export function uartFrameBits(config: UartConfig): number {
  return 1 + config.dataBits + (config.parity === "none" ? 0 : 1) + config.stopBits;
}

/**
 * Read frames back out of a bit stream, reporting what went wrong per frame.
 *
 * The inverse is worth having and is not symmetrical with the forward direction: what arrives is a
 * string of ones and zeros off a capture, and the interesting output is not just the bytes but *which
 * frames failed and how*. A parity error and a framing error are different faults with different
 * causes -- parity says a bit flipped, a bad stop bit usually says the baud rate is wrong -- so they
 * are reported separately rather than as one "invalid".
 *
 * Resynchronisation is deliberately absent. It scans for the next start bit only from where the
 * previous frame ended, because a decoder that hunts for a plausible alignment after an error will
 * always find one, and inventing bytes out of a bad capture is worse than stopping.
 */
export interface UartDecodedFrame {
  value: number;
  /** Bit offset in the stream where this frame's start bit was. */
  offset: number;
  parityError: boolean;
  framingError: boolean;
}

export interface UartDecodeResult {
  frames: readonly UartDecodedFrame[];
  /** Bits left over that could not make a whole frame. Zero for a clean capture. */
  trailingBits: number;
}

export function uartDecode(stream: readonly number[], config: UartConfig): UartDecodeResult {
  const bits = config.inverted ? stream.map((bit) => bit ^ 1) : stream;
  const frames: UartDecodedFrame[] = [];
  // A whole frame needs its stop bit to be present, so 1.5 rounds up for the purpose of *reading*
  // one -- unlike the timing figure, where the half is real.
  const span = 1 + config.dataBits + (config.parity === "none" ? 0 : 1) + Math.ceil(config.stopBits);

  let at = 0;
  while (at < bits.length) {
    // Idle. The line sits at 1 between frames, so anything before the first 0 is not part of a frame.
    if (bits[at] !== 0) {
      at++;
      continue;
    }
    if (at + span > bits.length) break;

    let value = 0;
    for (let i = 0; i < config.dataBits; i++) {
      const bit = bits[at + 1 + i]! & 1;
      const index = config.lsbFirst ? i : config.dataBits - 1 - i;
      value |= bit << index;
    }

    let cursor = at + 1 + config.dataBits;
    let parityError = false;
    if (config.parity !== "none") {
      parityError = (bits[cursor]! & 1) !== parityBit(value, config.parity, config.dataBits);
      cursor++;
    }
    // Only the first stop bit is checked. The second is the same level, so a fault in it is the same
    // fault, and requiring both would report one error twice.
    const framingError = bits[cursor] !== 1;

    frames.push({ value, offset: at, parityError, framingError });
    at += span;
  }

  return { frames, trailingBits: bits.length - at };
}

/** "0100000101" to bits, ignoring anything that is not a zero or a one. */
export function parseBitString(text: string): number[] {
  const bits: number[] = [];
  for (const ch of text) {
    if (ch === "0") bits.push(0);
    else if (ch === "1") bits.push(1);
  }
  return bits;
}

// ────────────────────────────────────────────────────────────── Hamming codes

/**
 * Hamming(7,4) and its extended (8,4) form, over one nibble.
 *
 * The layout is the original and the one every table is printed in: bit positions are numbered from
 * 1, the parity bits sit at the powers of two, and each covers the positions whose index has that
 * bit set. So p1 covers 1,3,5,7; p2 covers 2,3,6,7; p3 covers 4,5,6,7 -- and the consequence is the
 * whole trick: if exactly one position is wrong, the parity bits that fail are exactly the ones
 * whose numbers add up to it. The failing set *is* the position, in binary.
 *
 * `1011` encodes to `0110011`, which is the example the textbooks and Wikipedia use, and the test
 * pins it. Everything else is checked exhaustively rather than against a table, because sixteen
 * codewords is small enough to check completely: distinct, minimum distance 3, and every one of the
 * 112 single-bit errors corrected to the right nibble.
 */

/** Position 1..7 of the codeword, as a bit index into the returned byte (bit 6 is position 1). */
const HAMMING74_BITS = 7;

/**
 * One nibble to a 7-bit codeword, right-aligned in a byte with position 1 as the most significant.
 *
 * Right-aligned rather than packed contiguously across nibbles: a byte per codeword makes the hex
 * readable and makes the tool's output the same length whichever variant is chosen, and the padding
 * bit is always zero, which the tool says. Contiguous packing would save one bit in eight and cost
 * every reader the ability to see a codeword.
 */
export function hamming74Encode(nibble: number): number {
  const d1 = (nibble >> 3) & 1;
  const d2 = (nibble >> 2) & 1;
  const d3 = (nibble >> 1) & 1;
  const d4 = nibble & 1;

  const p1 = d1 ^ d2 ^ d4;
  const p2 = d1 ^ d3 ^ d4;
  const p3 = d2 ^ d3 ^ d4;

  // Positions 1..7: p1 p2 d1 p3 d2 d3 d4, most significant first.
  return (
    (p1 << 6) | (p2 << 5) | (d1 << 4) | (p3 << 3) | (d2 << 2) | (d3 << 1) | d4
  );
}

/** The (8,4) SECDED form: the seven bits plus one more over all of them, in the low bit. */
export function hamming84Encode(nibble: number): number {
  const seven = hamming74Encode(nibble);
  return (seven << 1) | byteParity(seven);
}

export interface HammingDecoded {
  nibble: number;
  /** 1..7 if a bit was corrected, 0 if the codeword was already clean. */
  correctedPosition: number;
  /**
   * Only the extended form can say this, and it is the reason to choose it.
   *
   * Plain (7,4) has minimum distance 3: it corrects one error and, handed two, *miscorrects* -- it
   * produces a different valid codeword and reports success. The eighth bit raises the distance to
   * 4, which is enough to tell "one error, here" from "two errors, somewhere", and this is that
   * verdict. `nibble` is meaningless when it is true.
   */
  doubleError: boolean;
}

export function hamming74Decode(codeword: number): HammingDecoded {
  const bit = (position: number) => (codeword >> (HAMMING74_BITS - position)) & 1;

  // Each syndrome bit is the parity of the positions that parity bit covers, including itself.
  const s1 = bit(1) ^ bit(3) ^ bit(5) ^ bit(7);
  const s2 = bit(2) ^ bit(3) ^ bit(6) ^ bit(7);
  const s3 = bit(4) ^ bit(5) ^ bit(6) ^ bit(7);
  // The failing parity bits, read as a binary number, name the position. That is the whole design.
  const position = s1 | (s2 << 1) | (s3 << 2);

  const fixed = position === 0 ? codeword : codeword ^ (1 << (HAMMING74_BITS - position));
  const at = (p: number) => (fixed >> (HAMMING74_BITS - p)) & 1;
  const nibble = (at(3) << 3) | (at(5) << 2) | (at(6) << 1) | at(7);
  return { nibble, correctedPosition: position, doubleError: false };
}

export function hamming84Decode(byte: number): HammingDecoded {
  const seven = (byte >> 1) & 0x7f;
  const overall = byte & 1;
  const inner = hamming74Decode(seven);
  const overallFails = byteParity(seven) !== overall;

  /**
   * The two-error verdict, and it is exactly this pair of conditions.
   *
   * The inner syndrome fires on any odd number of errors and on some even numbers; the overall bit
   * fires on any odd number. So a non-zero syndrome with the overall bit *agreeing* means an even
   * number of errors went wrong somewhere the inner code cannot place -- two, in practice. A
   * syndrome of zero with the overall bit failing is the eighth bit itself having flipped, which is
   * correctable and leaves the data alone.
   */
  if (inner.correctedPosition !== 0 && !overallFails) {
    return { nibble: inner.nibble, correctedPosition: 0, doubleError: true };
  }
  if (inner.correctedPosition === 0 && overallFails) {
    // Position 8: the overall parity bit. Reported so the caller can say a bit was fixed.
    return { nibble: inner.nibble, correctedPosition: 8, doubleError: false };
  }
  return inner;
}

/**
 * The general Hamming code, at any parity-bit count from 3 to 4.
 *
 * (7,4) and (8,4) above are written out longhand because they came first and because their published
 * vector -- `1011 -> 0110011` -- is what pins the convention everything here follows. This is the same
 * code generalised: `r` parity bits give a codeword of `2^r - 1` bits carrying `2^r - 1 - r` data bits,
 * with parity bit `i` at position `2^i` covering every position whose index has bit `i` set. The
 * extended form appends one more bit over the whole codeword, which raises the minimum distance from
 * three to four and is what turns "correct one" into "correct one, detect two".
 *
 * Two things worth stating.
 *
 * **The syndrome *is* the position, which is the whole design.** Reading the failing parity checks as
 * a binary number names the bit that flipped, because that is exactly which checks a position
 * participates in. That is why the parity bits sit at powers of two rather than being appended --
 * appending them would work as a code and destroy the property.
 *
 * **Data bits fill the non-power-of-two positions in order, most significant first.** Position 1 and 2
 * are parity, 3 is the first data bit, 4 is parity, 5, 6, 7 are data, 8 is parity, and so on. A
 * different filling order is a different code that is equally correct and matches nothing.
 *
 * `HAMMING_CODES` is the registry: the sizes this repo offers, each with the width of the unit it
 * carries. There is no (31,26) or beyond, and that is a judgement rather than a limit -- 26 data bits
 * per codeword is past the point where anyone reads the result, and nothing standardises it.
 */
export interface HammingCodeMeta {
  /** Parity bits. The codeword is `2^r - 1` bits, or `2^r` extended. */
  readonly parityBits: number;
  /** Data bits carried: `2^r - 1 - r`. */
  readonly dataBits: number;
  /** Total codeword bits, excluding the extended overall parity bit. */
  readonly codeBits: number;
}

export const HAMMING_SIZES: Readonly<Record<string, HammingCodeMeta>> = {
  "4": { parityBits: 3, dataBits: 4, codeBits: 7 },
  "11": { parityBits: 4, dataBits: 11, codeBits: 15 },
};

/** True when `position` is a power of two, and therefore a parity bit rather than a data bit. */
const isParityPosition = (position: number): boolean => (position & (position - 1)) === 0;

/**
 * One data unit to a codeword, right-aligned so position 1 is the most significant bit.
 *
 * `extended` appends the overall parity bit in the low bit, exactly as `hamming84Encode` does -- so
 * the (8,4) and (16,11) layouts are the same idea at two widths.
 */
export function hammingEncode(dataBits: number, value: number, extended: boolean): number {
  const meta = HAMMING_SIZES[String(dataBits)];
  if (!meta) throw new Error(`No Hamming code carrying ${dataBits} data bits.`);
  const { codeBits } = meta;

  // Place the data bits in the non-power-of-two positions, most significant first.
  let code = 0;
  let taken = 0;
  for (let position = 1; position <= codeBits; position++) {
    if (isParityPosition(position)) continue;
    const bit = (value >> (dataBits - 1 - taken)) & 1;
    taken += 1;
    if (bit) code |= 1 << (codeBits - position);
  }

  // Each parity bit is the parity of every position whose index has its bit set.
  for (let p = 0; p < meta.parityBits; p++) {
    const parityPosition = 1 << p;
    let sum = 0;
    for (let position = 1; position <= codeBits; position++) {
      if ((position & parityPosition) === 0) continue;
      sum ^= (code >> (codeBits - position)) & 1;
    }
    if (sum) code |= 1 << (codeBits - parityPosition);
  }

  if (!extended) return code;
  let overall = 0;
  for (let position = 1; position <= codeBits; position++) overall ^= (code >> (codeBits - position)) & 1;
  return (code << 1) | overall;
}

/** What a decode found. `correctedPosition` is 1-based, or 0 for a clean codeword. */
export interface HammingResult {
  readonly value: number;
  readonly correctedPosition: number;
  readonly doubleError: boolean;
}

export function hammingDecode(dataBits: number, codeword: number, extended: boolean): HammingResult {
  const meta = HAMMING_SIZES[String(dataBits)];
  if (!meta) throw new Error(`No Hamming code carrying ${dataBits} data bits.`);
  const { codeBits, parityBits } = meta;

  const inner = extended ? codeword >>> 1 : codeword;
  const overallBit = extended ? codeword & 1 : 0;

  // The syndrome, read as a binary number, names the position that flipped.
  let syndrome = 0;
  for (let p = 0; p < parityBits; p++) {
    const parityPosition = 1 << p;
    let sum = 0;
    for (let position = 1; position <= codeBits; position++) {
      if ((position & parityPosition) === 0) continue;
      sum ^= (inner >> (codeBits - position)) & 1;
    }
    if (sum) syndrome |= parityPosition;
  }

  let overallFails = false;
  if (extended) {
    let sum = 0;
    for (let position = 1; position <= codeBits; position++) sum ^= (inner >> (codeBits - position)) & 1;
    overallFails = sum !== overallBit;
  }

  /**
   * The extended form's two-error verdict, and it is the same pair of conditions `hamming84Decode`
   * uses: the inner syndrome fires on any odd number of errors and on some even ones, while the
   * overall bit fires only on an odd number. A non-zero syndrome with the overall bit *agreeing*
   * therefore means an even number of errors the inner code cannot place -- two, in practice.
   */
  if (extended && syndrome !== 0 && !overallFails) {
    return { value: extract(dataBits, inner), correctedPosition: 0, doubleError: true };
  }
  if (extended && syndrome === 0 && overallFails) {
    // The overall bit itself flipped. Correctable, and it leaves the data alone.
    return { value: extract(dataBits, inner), correctedPosition: codeBits + 1, doubleError: false };
  }

  const fixed = syndrome === 0 ? inner : inner ^ (1 << (codeBits - syndrome));
  return { value: extract(dataBits, fixed), correctedPosition: syndrome, doubleError: false };
}

/** Pull the data bits back out of the non-power-of-two positions. */
function extract(dataBits: number, code: number): number {
  const { codeBits } = HAMMING_SIZES[String(dataBits)]!;
  let value = 0;
  for (let position = 1; position <= codeBits; position++) {
    if (isParityPosition(position)) continue;
    value = (value << 1) | ((code >> (codeBits - position)) & 1);
  }
  return value;
}
