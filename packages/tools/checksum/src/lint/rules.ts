import type { LintRule } from "@ocs/contracts/diagnostic";
import { requireChecksumTool, type ChecksumKind } from "../catalogue/tool-meta";
import {
  OPTION_RESULT,
  OPTION_WIDTH,
  OPTION_WORD_SIZE,
  readResult,
  readWidth,
  readWordSize,
} from "../pure";
import type { ChecksumSpec } from "../spec";

export const RULE_CODES = ["S001", "S002", "S003", "S004", "S005", "S006"] as const;

/** The kinds whose value is unchanged by reordering the input. Everything except the two-sum ones. */
const ORDER_BLIND: readonly ChecksumKind[] = ["sum", "twos", "xor", "lrc", "bcc", "ones"];

/** The two tools that expose a width, and so are the two where raising it is a one-click fix. */
const WIDTH_IS_AN_OPTION: readonly ChecksumKind[] = ["sum", "twos"];

export const RULES: readonly LintRule<ChecksumSpec>[] = [
  {
    /**
     * The family-wide note, and `info` for the same reason `CRC001` is: nothing is wrong with
     * computing a checksum, and crying wolf on a tool's own core function trains people to ignore
     * the panel. But the misuse — reading a matching checksum as evidence nothing was altered — is
     * the most common cryptographic mistake there is, so it says so every time.
     */
    code: "S001",
    check(spec) {
      const tool = requireChecksumTool(spec.variant);
      return [
        {
          code: "S001",
          level: "info",
          message: `${tool.label} detects accidental corruption, not tampering.`,
          detail:
            "Producing different data with the same checksum is not a search here, it is one line of arithmetic — with a sum you can absorb any change into a single spare byte. Use these to catch a noisy cable, a truncated transfer or a flipped bit in RAM. If the question is whether a file is the file someone published, that needs SHA-256 and a signature.",
        },
      ];
    },
  },
  {
    code: "S002",
    check(spec) {
      const tool = requireChecksumTool(spec.variant);
      if (!ORDER_BLIND.includes(tool.kind)) return [];
      const wordSize = tool.kind === "ones" ? 16 : readWordSize(spec.options);
      const unit = wordSize === 8 ? "two bytes" : `two ${wordSize}-bit words`;
      return [
        {
          code: "S002",
          level: "warning",
          message: `Reordering the input does not change this value.`,
          detail: `${
            tool.kind === "xor" || tool.kind === "bcc" ? "XOR" : "Addition"
          } is commutative, so swapping ${unit} anywhere in the input produces an identical checksum${
            tool.kind === "xor" || tool.kind === "bcc"
              ? " — and so does duplicating any two bytes that happen to be equal, since they cancel"
              : ""
          }. If the data has a meaningful order, and most data does, Fletcher-16 or a CRC costs about the same and notices.`,
        },
      ];
    },
  },
  {
    code: "S003",
    check(spec) {
      const tool = requireChecksumTool(spec.variant);
      if (!WIDTH_IS_AN_OPTION.includes(tool.kind)) return [];
      if (readWidth(spec.options, String(tool.width) as "8" | "16" | "32") !== 8) return [];
      return [
        {
          code: "S003",
          level: "info",
          message: "An eight-bit checksum misses about one corruption in 256.",
          detail:
            "That is the whole error-detection budget: 255 of every 256 random corruptions change the value, and the rest do not. Sixteen bits costs one extra byte and takes the miss rate to one in 65,536. Fires only on the tools where the width is yours to choose — an LRC or a BCC is eight bits because the protocol says so.",
          optionIds: [OPTION_WIDTH],
          fix: {
            label: "Use 16 bits",
            apply: (s) => ({ ...s, options: { ...s.options, [OPTION_WIDTH]: "16" } }),
          },
        },
      ];
    },
  },
  {
    code: "S004",
    check(spec) {
      const tool = requireChecksumTool(spec.variant);
      if (tool.kind !== "lrc") return [];
      return [
        {
          code: "S004",
          level: "info",
          message: '"LRC" does not always mean this computation.',
          detail:
            "Modbus ASCII's LRC is the two's complement of the byte sum, which is what this tool computes. Several other protocols use the same three letters for an XOR of the bytes — the name refers to the idea of a longitudinal check, not to one algorithm. If a device disagrees with this value, try the XOR checksum tool before looking for a bug.",
        },
      ];
    },
  },
  {
    code: "S005",
    check(spec) {
      const tool = requireChecksumTool(spec.variant);
      if (tool.kind !== "ones" || readResult(spec.options) !== "sum") return [];
      return [
        {
          code: "S005",
          level: "info",
          message: "This is the folded sum, not the value a header carries.",
          detail:
            "IPv4, TCP, UDP and ICMP all transmit the complement of this number. The raw sum is worth having — RFC 1071's own worked example stops here — but a value being out by exactly a complement from what a packet capture shows is this setting rather than a fault.",
          optionIds: [OPTION_RESULT],
          fix: {
            label: "Report the complement",
            apply: (s) => ({ ...s, options: { ...s.options, [OPTION_RESULT]: "complement" } }),
          },
        },
      ];
    },
  },
  {
    code: "S006",
    check(spec) {
      const tool = requireChecksumTool(spec.variant);
      // Fletcher-32 groups into 16-bit words unconditionally; the two sum tools do it only when
      // asked. The one's-complement sum is left out on purpose: an IP header is a whole number of
      // words by construction, so the padding case does not arise where that tool is used.
      const wordSize =
        tool.kind === "fletcher32"
          ? 16
          : WIDTH_IS_AN_OPTION.includes(tool.kind)
            ? readWordSize(spec.options)
            : 8;
      if (wordSize === 8) return [];
      return [
        {
          code: "S006",
          level: "info",
          message: `Trailing bytes are zero-padded to a ${wordSize}-bit word.`,
          detail: `An input whose length is not a multiple of ${
            wordSize / 8
          } bytes is padded with zeros to fill the last word, which means it has the same checksum as itself with those zero bytes actually appended. Every implementation does this; it is a property of the algorithm rather than a choice made here. It matters if you are checksumming records whose length is part of the data.`,
          ...(WIDTH_IS_AN_OPTION.includes(tool.kind) ? { optionIds: [OPTION_WORD_SIZE] } : {}),
        },
      ];
    },
  },
];
