import type { LintRule } from "@ocs/contracts/diagnostic";
import { setOption } from "@ocs/contracts/pure";
import { requireParityTool } from "../catalogue/tool-meta";
import {
  OPTION_BIT_ORDER,
  OPTION_HAMMING_CODE,
  OPTION_PARITY,
  readBitOrder,
  readDataBits,
  readDirection,
  readFrameParity,
  readHammingCode,
  readParityMode,
  readScope,
} from "../pure";
import type { ParitySpec } from "../spec";

export const RULE_CODES = ["P001", "P002", "P003", "P004", "P005"] as const;

/**
 * One rule per real footgun, with a fix where a fix exists.
 *
 * The bar this repo holds is "would this change what someone does", and it is worth saying what is
 * *absent* under that bar. There is no rule saying a parity bit is weak in general -- `P001` says it
 * once, at `info`, because that is the fact the tool exists to teach and it is not a mistake anybody
 * made. There is no rule about the bit order, because LSB-first is the default and choosing MSB is a
 * deliberate act of comparison. And there is nothing about mark parity being unusual, only about it
 * detecting nothing, which is the part that changes a decision.
 */
export const RULES: readonly LintRule<ParitySpec>[] = [
  {
    /**
     * What a parity bit actually buys, said once and at `info`.
     *
     * The sibling of `CRC001`, and deliberately weaker in tone than it: a CRC gets a warning because
     * people use one *as* an integrity check, where nobody believes a parity bit is security. What
     * they do get wrong is the arithmetic -- one bit sounds like "catches single errors" and is really
     * "catches every odd number and no even number", which is half of all multi-bit errors missed.
     */
    code: "P001",
    check(spec) {
      const tool = requireParityTool(spec.variant);
      if (tool.kind !== "parity") return [];
      const scope = readScope(spec.options);
      const mode = readParityMode(spec.options);
      // Mark and space detect nothing at all, so `P002` is the accurate thing to say instead.
      if (mode === "mark" || mode === "space") return [];
      const unit =
        scope === "message"
          ? "the whole message"
          : `each ${readDataBits(spec.options, 8, 8)}-bit unit`;
      return [
        {
          code: "P001",
          level: "info",
          message: `A parity bit over ${unit} misses every even number of flipped bits.`,
          detail:
            scope === "message"
              ? "One bit over the whole input is the weakest check that exists: two flipped bits anywhere cancel, a byte repeated twice cancels, and any reordering of the bytes gives the same answer. It is what a parity-protected memory word carries, and it is there to catch a single stuck bit rather than to say a message arrived intact. Use a CRC for that."
              : "It catches one flipped bit, and three, and five. It catches no even number at all, so it misses about half of every multi-bit error -- and a burst of noise on a serial line flips bits in pairs as often as singly. That gap is the entire reason CRCs exist: CRC-8 costs the same one byte per frame and catches every burst shorter than eight bits.",
        },
      ];
    },
  },
  {
    /**
     * Mark and space are constants, so they detect nothing.
     *
     * A `warning` rather than `info`, because this is a real mistake with a plausible cause: the four
     * modes sit in one dropdown and two of them are not parity schemes at all. No fix, because
     * choosing mark parity is usually *correct* -- it is what the equipment does -- and switching it
     * to even would break the link. The rule says what the setting is, not what to do about it.
     */
    code: "P002",
    check(spec) {
      const tool = requireParityTool(spec.variant);
      const mode =
        tool.kind === "uart" ? readFrameParity(spec.options) : readParityMode(spec.options);
      if (mode !== "mark" && mode !== "space") return [];
      return [
        {
          code: "P002",
          level: "warning",
          message: `${mode === "mark" ? "Mark" : "Space"} parity is a constant bit and detects nothing.`,
          detail: `The bit is always ${mode === "mark" ? "1" : "0"} whatever the data, so it carries no information about it: no flipped bit anywhere in the frame will ever change it. That is not a defect in this tool -- it is what the mode is. Equipment uses the slot as a ninth data bit or as an address/data flag, and if that is what you are talking to then this is the right setting. If you wanted error detection, even or odd is the choice.`,
          optionIds: [OPTION_PARITY],
        },
      ];
    },
  },
  {
    /**
     * Eight data bits with per-byte parity: the parity bit is not in the byte.
     *
     * `info` while applying -- the resolver already refuses the one combination that is impossible,
     * and the rest is worth explaining rather than blocking. This is the single most common way to get
     * a different answer from a device: computing 8-bit parity over bytes that already carry parity in
     * bit 7 folds the parity bit into its own input, and the answer comes out even every time.
     */
    code: "P003",
    check(spec) {
      const tool = requireParityTool(spec.variant);
      if (tool.kind !== "parity") return [];
      if (readScope(spec.options) !== "byte") return [];
      if (readDataBits(spec.options, 8, 8) !== 8) return [];
      return [
        {
          code: "P003",
          level: "info",
          message: "At 8 data bits the parity bit has to travel outside the byte.",
          detail:
            "8E1 is eleven bits on the wire: a start bit, eight data bits, a parity bit and a stop bit. There is nowhere in the byte for the parity bit to go, so the only layouts that make sense are the packed bit string and one byte each. If you are working with a device that sends 7-bit ASCII with parity in the top bit, set this to 7 -- otherwise the parity bit is being counted as part of its own data and the answer will always come out even.",
          optionIds: ["dataBits"],
        },
      ];
    },
  },
  {
    /**
     * Hamming(7,4) miscorrects two errors, and the fix is one dropdown away.
     *
     * `warning`, and this one earns it: the failure is *silent*. Handed a codeword with two flipped
     * bits, (7,4) has no way to notice -- it lands within one bit of a different valid codeword, so it
     * "corrects" to a third wrong value and reports success. That is worse than refusing, and the
     * extended code costs one bit per nibble to fix.
     */
    code: "P004",
    check(spec) {
      const tool = requireParityTool(spec.variant);
      if (tool.kind !== "hamming") return [];
      if (readHammingCode(spec.options) !== "7-4") return [];
      return [
        {
          code: "P004",
          level: "warning",
          message: "Hamming(7,4) silently miscorrects a double error.",
          detail:
            "Its minimum distance is 3, which is exactly enough to correct one error and not enough to notice two: a codeword with two flipped bits sits one bit away from some other valid codeword, so decoding 'corrects' it to a third value and reports success. The extended (8,4) adds one parity bit over the whole codeword, raising the distance to 4 -- enough to tell 'one error, here' from 'two errors, somewhere' and refuse rather than lie. It is also byte-aligned, so it costs nothing in this tool's output.",
          optionIds: [OPTION_HAMMING_CODE],
          fix: {
            label: "Use the extended (8,4) code",
            // A pure function of the spec it is handed, as `applyAllFixes` requires: nothing is read
            // from the closure, so this composes with any other fix landing in the same pass.
            apply: (s) => ({ ...s, options: setOption(s.options, OPTION_HAMMING_CODE, "8-4") }),
          },
        },
      ];
    },
  },
  {
    /**
     * MSB-first is not a UART, and the reason to say so is that it is *offered*.
     *
     * The control exists because reading a capture backwards is the commonest mistake made with a
     * serial link, and being able to see both views is how you find that out. But a frame diagram with
     * this set does not describe any real device, so leaving it silent would let someone screenshot a
     * wrong answer. `info` with a fix, since the fix is what they want nine times in ten.
     */
    code: "P005",
    check(spec) {
      const tool = requireParityTool(spec.variant);
      if (tool.kind !== "uart") return [];
      if (readBitOrder(spec.options) === "lsb") return [];
      const direction = readDirection(spec.options);
      return [
        {
          code: "P005",
          level: "info",
          message: "No real UART sends the most significant bit first.",
          detail:
            direction === "check"
              ? "Every UART transmits the least significant data bit first, so a capture read MSB-first gives each byte's bits in reverse. This setting is here so you can see that reading and recognise it -- if the bytes look like plausible data this way round, the capture is fine and something else reversed it."
              : "Every UART transmits the least significant data bit first, so this diagram does not describe any real device. The setting is here for comparison: if a capture matches this and not the LSB-first frame, whatever produced the capture reversed the bits.",
          optionIds: [OPTION_BIT_ORDER],
          fix: {
            label: "Send the least significant bit first",
            apply: (s) => ({ ...s, options: setOption(s.options, OPTION_BIT_ORDER, "lsb") }),
          },
        },
      ];
    },
  },
];
