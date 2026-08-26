import type { ToolSample } from "@ocs/engine";

/**
 * One sample, and only for `uart`.
 *
 * The check string is a fine input for a parity bit and for a Hamming encoder -- they take arbitrary
 * bytes, which is what the generic samples are for. The UART tool's *decode* direction does not: it
 * reads a run of ones and zeros, and `123456789` contains four of them in the wrong places. So there
 * is one sample here, a real 8N1 capture, and nothing else.
 *
 * It is the frame for the three bytes `Hi!` at 8N1, with the idle line either side, written out rather
 * than generated: a sample derived from the implementation it is meant to demonstrate would agree with
 * a broken one. `tests/parity-tool.test.ts` decodes it and requires those three bytes back, so the
 * string cannot drift away from what it claims to be.
 */
const HI_AT_8N1 = [
  "11",
  // 'H' is 0x48 = 0100_1000, LSB first 0001_0010
  "0 00010010 1",
  // 'i' is 0x69 = 0110_1001, LSB first 1001_0110
  "0 10010110 1",
  // '!' is 0x21 = 0010_0001, LSB first 1000_0100
  "0 10000100 1",
  "11",
].join(" ");

const BY_TOOL: Record<string, readonly ToolSample[]> = {
  uart: [
    {
      id: "capture",
      label: "An 8N1 capture of three bytes",
      note: "For the Decode direction: idle, three frames, idle. The spaces are ignored, so it can be pasted as copied. Switch to Encode and the same bytes come back as this diagram.",
      text: HI_AT_8N1,
    },
  ],
};

export function samplesFor(toolId: string): readonly ToolSample[] | undefined {
  return BY_TOOL[toolId];
}

/** Exposed for the test that decodes it. */
export const UART_CAPTURE_SAMPLE = HI_AT_8N1;
