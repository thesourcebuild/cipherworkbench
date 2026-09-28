import { requireChecksumTool } from "../catalogue/tool-meta";
import {
  declaredByteOrder,
  readBccMode,
  readByteOrder,
  readResult,
  readWidth,
  readWordSize,
} from "../pure";
import type { ChecksumSpec } from "../spec";

/**
 * One sentence, shown under the tool header — what these exact settings will do.
 *
 * States the grouping and the width rather than just the name, for the same reason the CRC family
 * states the polynomial: "a 16-bit checksum" is not a reproducible description, and the two things
 * that make it one are how the bytes were grouped and what happened to the total at the end.
 */
export function describeSpec(spec: ChecksumSpec): string {
  const tool = requireChecksumTool(spec.variant);
  const width = readWidth(spec.options, String(tool.width) as "8" | "16" | "32");
  const bytes = width / 8;
  const size = `${bytes} byte${bytes === 1 ? "" : "s"}`;

  switch (tool.kind) {
    case "sum":
    case "twos": {
      const wordSize = readWordSize(spec.options);
      const grouping =
        wordSize === 8
          ? "one byte at a time"
          : `${wordSize}-bit ${readByteOrder(
              spec.options,
              declaredByteOrder(tool.defaults),
            )}-endian words`;
      return tool.kind === "sum"
        ? `Adds the input ${grouping} and keeps the low ${width} bits — ${size}.`
        : `Adds the input ${grouping}, negates the total and keeps the low ${width} bits — ${size}, so data plus checksum comes to zero.`;
    }
    case "ones":
      return readResult(spec.options) === "complement"
        ? "Sums 16-bit big-endian words with an end-around carry and complements the result — 2 bytes, the Internet checksum of RFC 1071."
        : "Sums 16-bit big-endian words with an end-around carry, reporting the folded sum without complementing it — 2 bytes.";
    case "xor":
      return "Xors every byte of the input together — 1 byte.";
    case "lrc":
      return "Adds every byte, negates the total and keeps eight bits — 1 byte, Modbus ASCII's LRC.";
    case "bcc":
      return readBccMode(spec.options) === "xor"
        ? "Xors every byte of the input together — 1 byte, the Block Check Character of ISO 1155."
        : "Adds every byte and keeps eight bits — 1 byte, the additive Block Check Character some equipment uses.";
    case "fletcher16":
      return "Runs two 8-bit sums modulo 255, the second accumulating the first — 2 bytes, positional sum first.";
    case "fletcher32":
      return `Runs two 16-bit sums modulo 65535 over ${readByteOrder(
        spec.options,
      )}-endian 16-bit words — 4 bytes, positional sum first.`;
    case "adler32":
      return "Runs two 16-bit sums modulo 65521, starting from a = 1 — 4 bytes, RFC 1950's Adler-32.";
  }
}
