import { describe, expect, it } from "vitest";
import {
  byteParity,
  hamming74Decode,
  hamming74Encode,
  hamming84Decode,
  hamming84Encode,
  messageParity,
  packBits,
  parityBit,
  parseBitString,
  uartDecode,
  uartFrame,
  uartFrameBits,
  type UartConfig,
} from "@ocs/algos";

/**
 * Parity, UART framing and Hamming codes -- none of which has an oracle in this tree.
 *
 * `node:crypto` has no parity, no library here implements a UART, and Hamming codes are published as
 * tables rather than as vectors. So what stands in is different for each, and saying which is the
 * point of this comment rather than leaving a reader to assume all three are equally well covered:
 *
 *  - **Parity** is checked against an independent formulation over all 256 bytes. The folding trick
 *    in the implementation and counting the ones in a binary string are the two ways to write this,
 *    and they fail differently, so agreement over the whole domain is a real check rather than a
 *    restatement.
 *  - **UART frames** are written out by hand, field by field, for values whose bit patterns are
 *    *asymmetric*. That matters more than the number of cases: 0x55 and 0xff read the same forwards
 *    and backwards, so a reversed bit order passes on them and fails on 'A'.
 *  - **Hamming** is checked exhaustively -- all sixteen codewords, the published example, the minimum
 *    distance, and every single-bit error in every codeword. That is stronger than a table.
 */

/** The other way to write it: count the ones in the binary expansion. */
const parityByCounting = (value: number) => popcount(value & 0xff) % 2;

/** Hamming weight, written the obvious way: this is a test, so it shares nothing with the source. */
function popcount(value: number): number {
  return value
    .toString(2)
    .split("")
    .filter((c) => c === "1").length;
}

describe("the parity bit", () => {
  it("agrees with counting the ones, for all 256 bytes", () => {
    for (let byte = 0; byte < 256; byte++) {
      expect(byteParity(byte), byte.toString(16)).toBe(parityByCounting(byte));
    }
  });

  /**
   * Even parity makes the total count of ones even, which means the bit *is* the parity of the data.
   * Odd is its complement. Stated as a property over the whole domain rather than as examples,
   * because the two are one inversion apart and an inverted mode is the entire failure mode.
   */
  it("makes the total even for even parity and odd for odd parity", () => {
    for (let byte = 0; byte < 256; byte++) {
      const even = parityBit(byte, "even");
      const odd = parityBit(byte, "odd");
      expect(parityByCounting(byte) ^ even, `even ${byte}`).toBe(0);
      expect(parityByCounting(byte) ^ odd, `odd ${byte}`).toBe(1);
      expect(even ^ odd).toBe(1);
    }
  });

  /** Mark and space are constants, which is what makes them detect nothing. Asserted, not assumed. */
  it("returns a constant for mark and space, whatever the data", () => {
    for (let byte = 0; byte < 256; byte++) {
      expect(parityBit(byte, "mark")).toBe(1);
      expect(parityBit(byte, "space")).toBe(0);
    }
  });

  /**
   * Seven data bits ignore bit 7, so 0x41 and 0xc1 must give the same parity bit.
   *
   * This is 7E1 versus 8E1, and it is the setting most likely to be got wrong: a device sending
   * 7-bit ASCII with parity in the top bit produces bytes that look exactly like 8-bit data.
   */
  it("masks to the data width", () => {
    expect(parityBit(0x41, "even", 7)).toBe(parityBit(0xc1, "even", 7));
    expect(parityBit(0x41, "even", 8)).not.toBe(parityBit(0xc1, "even", 8));
    for (const bits of [5, 6, 7, 8]) {
      for (let byte = 0; byte < 256; byte++) {
        const masked = byte & ((1 << bits) - 1);
        expect(parityBit(byte, "even", bits), `${byte}/${bits}`).toBe(parityByCounting(masked));
      }
    }
  });

  it("takes the parity of a whole message as the parity of its XOR", () => {
    // 0x31 ^ 0x32 ^ 0x33 = 0x30, which has two ones.
    expect(messageParity(new Uint8Array([0x31, 0x32, 0x33]), "even")).toBe(0);
    expect(messageParity(new Uint8Array([0x31, 0x32, 0x33]), "odd")).toBe(1);
    // A byte appearing twice cancels, which is the property that makes this the weakest check there is.
    expect(messageParity(new Uint8Array([0x41, 0x41]), "even")).toBe(0);
    expect(messageParity(new Uint8Array(), "even")).toBe(0);
  });

  it("packs bits most significant first, zero-padding the last byte", () => {
    expect([...packBits([1, 0, 1, 0, 0, 0, 0, 0])]).toEqual([0xa0]);
    expect([...packBits([1])]).toEqual([0x80]);
    expect([...packBits([1, 1, 1, 1, 1, 1, 1, 1, 1])]).toEqual([0xff, 0x80]);
    expect([...packBits([])]).toEqual([]);
  });
});

describe("UART framing", () => {
  const config = (over: Partial<UartConfig> = {}): UartConfig => ({
    dataBits: 8,
    parity: "none",
    stopBits: 1,
    lsbFirst: true,
    inverted: false,
    ...over,
  });

  const flat = (value: number, over: Partial<UartConfig> = {}) =>
    uartFrame(value, config(over))
      .flatMap((field) => field.bits)
      .join("");

  /**
   * 'A' is 0x41, so its bits are 0100_0001 and least significant first they are 1000_0010.
   *
   * Written out rather than computed, and chosen because it is asymmetric: 0x55 and 0xff read the
   * same in both directions, so they cannot tell a correct implementation from one sending the byte
   * MSB-first -- which is the mistake anybody writing this makes once.
   */
  it("sends the data least significant bit first, between a start and a stop bit", () => {
    expect(flat(0x41)).toBe("0" + "10000010" + "1");
    expect(flat(0x41, { lsbFirst: false })).toBe("0" + "01000001" + "1");
    expect(flat(0x01)).toBe("0" + "10000000" + "1");
    expect(flat(0x80)).toBe("0" + "00000001" + "1");
  });

  it("puts the parity bit after the data and before the stop bit", () => {
    // 0x41 has two ones: even parity 0, odd parity 1.
    expect(flat(0x41, { parity: "even" })).toBe("0" + "10000010" + "0" + "1");
    expect(flat(0x41, { parity: "odd" })).toBe("0" + "10000010" + "1" + "1");
    expect(flat(0x41, { parity: "mark" })).toBe("0" + "10000010" + "1" + "1");
    expect(flat(0x41, { parity: "space" })).toBe("0" + "10000010" + "0" + "1");
  });

  it("names each field, so a reader can see which bit is which", () => {
    const fields = uartFrame(0x41, config({ parity: "even", stopBits: 2 }));
    expect(fields.map((f) => f.name)).toEqual(["start", "data", "parity", "stop"]);
    expect(fields.find((f) => f.name === "stop")!.bits).toEqual([1, 1]);
    expect(uartFrame(0x41, config()).map((f) => f.name)).toEqual(["start", "data", "stop"]);
  });

  it("sends only the data bits configured", () => {
    expect(flat(0x41, { dataBits: 7 })).toBe("0" + "1000001" + "1");
    expect(flat(0x1ff, { dataBits: 9 })).toBe("0" + "111111111" + "1");
    // Seven data bits drop bit 7 entirely, which is how 7-bit ASCII with a parity bit is sent.
    expect(flat(0xc1, { dataBits: 7 })).toBe(flat(0x41, { dataBits: 7 }));
  });

  it("inverts every level for a line-driver capture", () => {
    expect(flat(0x41, { inverted: true })).toBe("1" + "01111101" + "0");
    const normal = flat(0x41);
    const upside = flat(0x41, { inverted: true });
    expect([...normal].map((b) => (b === "0" ? "1" : "0")).join("")).toBe(upside);
  });

  /**
   * A half stop bit is a duration, not a value.
   *
   * 10.5 bit times at 8N1.5 is real -- it is what the receiver waits for -- so the count is
   * fractional while the bit pattern has one stop bit in it. Rounding the count would make any
   * transmission time computed from it wrong by five per cent.
   */
  it("counts a half stop bit as a half, without emitting half a bit", () => {
    expect(uartFrameBits(config())).toBe(10);
    expect(uartFrameBits(config({ parity: "even" }))).toBe(11);
    expect(uartFrameBits(config({ stopBits: 1.5 }))).toBe(10.5);
    expect(uartFrameBits(config({ stopBits: 2, parity: "odd", dataBits: 7 }))).toBe(11);
    expect(flat(0x41, { stopBits: 1.5 })).toBe(flat(0x41, { stopBits: 1 }));
  });

  it("reads its own frames back, for every byte and every configuration", () => {
    const values = [0, 1, 2, 0x41, 0x55, 0xaa, 0x1f];
    for (const dataBits of [5, 6, 7, 8]) {
      for (const parity of ["none", "even", "odd", "mark", "space"] as const) {
        for (const inverted of [false, true]) {
          const settings = config({ dataBits, parity, inverted });
          const masked = values.map((v) => v & ((1 << dataBits) - 1));
          const bits = masked.flatMap((v) => uartFrame(v, settings).flatMap((f) => f.bits));
          const decoded = uartDecode(bits, settings);
          const label = `${dataBits}/${parity}/${inverted}`;
          expect(
            decoded.frames.map((f) => f.value),
            label,
          ).toEqual(masked);
          expect(
            decoded.frames.some((f) => f.parityError || f.framingError),
            label,
          ).toBe(false);
        }
      }
    }
  });

  /**
   * A parity error and a framing error are different faults and are reported separately.
   *
   * Flipping a data bit under even parity trips parity alone; corrupting the stop bit trips framing
   * alone. Collapsing the two into "invalid" would throw away the useful half -- a framing error
   * usually means the baud rate is wrong, where a parity error means a bit flipped.
   */
  it("tells a parity error from a framing error", () => {
    const settings = config({ parity: "even" });
    const clean = uartFrame(0x41, settings).flatMap((f) => f.bits);

    const flipped = [...clean];
    flipped[1] = flipped[1]! ^ 1;
    const p = uartDecode(flipped, settings).frames[0]!;
    expect(p.parityError).toBe(true);
    expect(p.framingError).toBe(false);

    const broken = [...clean];
    broken[broken.length - 1] = 0;
    const f = uartDecode(broken, settings).frames[0]!;
    expect(f.parityError).toBe(false);
    expect(f.framingError).toBe(true);
  });

  /**
   * Idle bits are not leftovers, and a truncated frame is.
   *
   * The line sits high between frames, so trailing ones are the line doing its job -- reporting them
   * as "2 bits left over" would put a number on screen that means nothing and invite someone to go
   * looking for the missing eight. What the count is *for* is a capture that stops mid-frame, which
   * is what a too-short capture window looks like and is worth being told about.
   */
  it("treats trailing idle bits as idle and a truncated frame as leftover", () => {
    const settings = config();
    const frame = uartFrame(0x41, settings).flatMap((f) => f.bits);

    const padded = uartDecode([1, 1, 1, ...frame, 1, 1], settings);
    expect(padded.frames.map((f) => f.value)).toEqual([0x41]);
    expect(padded.frames[0]!.offset).toBe(3);
    expect(padded.trailingBits).toBe(0);

    const cut = uartDecode([...frame, ...frame.slice(0, 4)], settings);
    expect(cut.frames.map((f) => f.value)).toEqual([0x41]);
    expect(cut.trailingBits).toBe(4);

    // Nothing at all is not an error, and half a frame is not a frame.
    expect(uartDecode([], settings).frames).toEqual([]);
    expect(uartDecode([0, 1, 0], settings).frames).toEqual([]);
    expect(uartDecode([0, 1, 0], settings).trailingBits).toBe(3);
  });

  it("reads a bit string, ignoring the separators people write in", () => {
    expect(parseBitString("0 1000 0010 1")).toEqual([0, 1, 0, 0, 0, 0, 0, 1, 0, 1]);
    expect(parseBitString("0b1010_1010")).toEqual([0, 1, 0, 1, 0, 1, 0, 1, 0]);
    expect(parseBitString("no bits here")).toEqual([]);
  });
});

describe("Hamming(7,4)", () => {
  /** The example every table prints, and the one value here that is published rather than derived. */
  it("encodes 1011 as 0110011", () => {
    expect(hamming74Encode(0b1011).toString(2).padStart(7, "0")).toBe("0110011");
  });

  it("produces sixteen distinct codewords with a minimum distance of 3", () => {
    const words = Array.from({ length: 16 }, (_, n) => hamming74Encode(n));
    expect(new Set(words).size).toBe(16);
    let minimum = 7;
    for (let a = 0; a < 16; a++) {
      for (let b = a + 1; b < 16; b++) minimum = Math.min(minimum, popcount(words[a]! ^ words[b]!));
    }
    // Distance 3 is exactly what buys single-error correction, and no more.
    expect(minimum).toBe(3);
  });

  /**
   * Every single-bit error in every codeword: 16 x 7 = 112 cases, all corrected to the right nibble
   * and all naming the position that was flipped.
   *
   * Exhaustive rather than sampled, because the syndrome is a *positional* code -- an error in the
   * mapping from failing parity bits to position is wrong for one position and right for the other
   * six, which sampling would miss six times out of seven.
   */
  it("corrects every single-bit error and names its position", () => {
    for (let nibble = 0; nibble < 16; nibble++) {
      const clean = hamming74Encode(nibble);
      expect(hamming74Decode(clean)).toEqual({
        nibble,
        correctedPosition: 0,
        doubleError: false,
      });
      for (let position = 1; position <= 7; position++) {
        const decoded = hamming74Decode(clean ^ (1 << (7 - position)));
        const label = `nibble ${nibble} position ${position}`;
        expect(decoded.nibble, label).toBe(nibble);
        expect(decoded.correctedPosition, label).toBe(position);
      }
    }
  });

  /**
   * Two errors are *miscorrected* by the plain code, and that is worth pinning rather than hiding.
   *
   * With distance 3 there is nowhere for a double error to be recognised: it lands within one bit of
   * some other valid codeword, so decoding reports success and returns the wrong nibble. This is why
   * the extended form exists, and why a lint rule says so.
   */
  it("silently returns the wrong nibble for some double errors", () => {
    const clean = hamming74Encode(0b1011);
    const decoded = hamming74Decode(clean ^ 0b1000001);
    expect(decoded.doubleError).toBe(false);
    expect(decoded.nibble).not.toBe(0b1011);
  });
});

describe("Hamming(8,4) SECDED", () => {
  it("adds one bit over the whole codeword", () => {
    for (let nibble = 0; nibble < 16; nibble++) {
      const eight = hamming84Encode(nibble);
      expect(eight >> 1).toBe(hamming74Encode(nibble));
      expect(popcount(eight) % 2).toBe(0);
    }
  });

  it("still corrects every single-bit error, including one in the eighth bit", () => {
    for (let nibble = 0; nibble < 16; nibble++) {
      const clean = hamming84Encode(nibble);
      expect(hamming84Decode(clean)).toEqual({
        nibble,
        correctedPosition: 0,
        doubleError: false,
      });
      for (let bit = 0; bit < 8; bit++) {
        const decoded = hamming84Decode(clean ^ (1 << bit));
        const label = `nibble ${nibble} bit ${bit}`;
        expect(decoded.doubleError, label).toBe(false);
        expect(decoded.nibble, label).toBe(nibble);
        expect(decoded.correctedPosition, label).toBeGreaterThan(0);
      }
    }
  });

  /** The whole reason for the eighth bit: all 28 two-bit patterns, in all 16 codewords, detected. */
  it("detects every double error rather than miscorrecting it", () => {
    for (let nibble = 0; nibble < 16; nibble++) {
      const clean = hamming84Encode(nibble);
      for (let a = 0; a < 8; a++) {
        for (let b = a + 1; b < 8; b++) {
          const decoded = hamming84Decode(clean ^ (1 << a) ^ (1 << b));
          expect(decoded.doubleError, `nibble ${nibble} bits ${a},${b}`).toBe(true);
        }
      }
    }
  });
});
