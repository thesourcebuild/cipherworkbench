import { requireParityTool } from "../catalogue/tool-meta";
import {
  readBitOrder,
  readDataBits,
  readDirection,
  readFrameParity,
  readBchProfile,
  readHammingCode,
  readRsEcc,
  readRsProfile,
  readInverted,
  readParityMode,
  readPlacement,
  readScope,
  readStopBits,
} from "../pure";
import type { ParitySpec } from "../spec";

/**
 * The header line: what this tool is about to do, in the settings actually chosen.
 *
 * Reads the spec and nothing else, so it is on screen before anything is typed. It names the frame
 * shorthand -- 8N1, 7E2 -- because that is the string somebody arrives holding, and seeing it in the
 * header is how they confirm the controls say what they meant.
 */
export function describeSpec(spec: ParitySpec): string {
  const tool = requireParityTool(spec.variant);
  const direction = readDirection(spec.options);

  switch (tool.kind) {
    case "parity": {
      const mode = readParityMode(spec.options);
      if (readScope(spec.options) === "message") {
        return `Takes the ${mode} parity of the whole message, as one bit.`;
      }
      const bits = readDataBits(spec.options, 8, 8);
      if (direction === "check") {
        return `Checks ${mode} parity in bit 7 of each byte against its low ${bits} bits.`;
      }
      const layout =
        readPlacement(spec.options) === "high-bit"
          ? "into bit 7 of each byte"
          : readPlacement(spec.options) === "packed"
            ? "as a packed bit string"
            : "as one byte each";
      return `Computes ${mode} parity over ${bits} bits per byte, ${layout}.`;
    }
    case "uart": {
      const parity = readFrameParity(spec.options);
      const letter = parity === "none" ? "N" : parity[0]!.toUpperCase();
      const format = `${readDataBits(spec.options, 8, 9)}${letter}${readStopBits(spec.options)}`;
      const order = readBitOrder(spec.options) === "lsb" ? "" : ", most significant bit first";
      const levels = readInverted(spec.options) ? ", inverted" : "";
      return direction === "check"
        ? `Reads ${format} frames out of a bit string${order}${levels}.`
        : `Shows each byte as a ${format} frame${order}${levels}.`;
    }
    case "hamming": {
      // The option id is `<codeword>-<data>` bits, which is also how the code is named.
      const [codeBits, dataBits] = readHammingCode(spec.options).split("-");
      const code = `Hamming(${codeBits},${dataBits})`;
      const unit = dataBits === "4" ? "nibble" : `${dataBits} bits`;
      return direction === "check"
        ? `Decodes ${code} codewords, correcting any single-bit error.`
        : `Encodes each ${unit} as a ${code} codeword.`;
    }
    case "reedsolomon": {
      const field = readRsProfile(spec.options) === "qr" ? "QR Code's" : "Data Matrix's";
      const ecc = readRsEcc(spec.options);
      return direction === "check"
        ? `Decodes a Reed-Solomon block in ${field} field, repairing up to ${Math.floor(ecc / 2)} damaged bytes.`
        : `Appends ${ecc} Reed-Solomon parity symbols in ${field} field.`;
    }
    case "bch": {
      const code = readBchProfile(spec.options) === "qr-format" ? "BCH(15,5)" : "BCH(18,6)";
      return direction === "check"
        ? `Decodes ${code} codewords by nearest match, repairing up to three flipped bits.`
        : `Encodes each byte as a ${code} codeword.`;
    }
  }
}
