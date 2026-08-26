import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { PARITY_TOOLS, type ParityToolMeta } from "./catalogue/tool-meta";

/**
 * **Binary first**, which is the one place this family differs from every other in the app.
 *
 * `outputEncodings[0]` is what a tool opens on, and everywhere else that is `hex`, correctly: a digest
 * is compared as hex and nobody reads 256 bits of it in binary. Here the result *is* bits -- a parity
 * bit, a packed bit string, a seven-bit codeword -- and `01` says what `0x01` makes you decode. Hex is
 * second because a 7E1 byte is compared as hex, and `decimal` is offered on the same reasoning as the
 * CRC family's: these are small integers and people quote them as such.
 */
const BIT_ENCODINGS: readonly OutputEncoding[] = [
  "binary",
  "hex",
  "hex-upper",
  "decimal",
  "octal",
  "base64",
];

/**
 * `uart` returns text and therefore offers one encoding, which hides the selector.
 *
 * A frame is a diagram: a labelled run of ones and zeros, one line per byte. Offering to spell that
 * as Base64 would be a control that either does nothing or does something nobody asked for -- the
 * same call the format family makes for the same reason. Note that *decoding* a frame returns bytes,
 * so this list is not the whole story, and that asymmetry is deliberate: the encoding menu is chosen
 * per tool rather than per direction, and the direction that needs it least is the one with a diagram.
 */
const TEXT_ONLY: readonly OutputEncoding[] = ["utf-8"];

function toManifest(meta: ParityToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "parity",
    category: meta.category,
    tags: [...meta.tags],
    summary: meta.summary,
    directions: meta.bidirectional ? ["forward", "inverse"] : ["forward"],
    /**
     * `not-a-mac`, the same posture the CRC and checksum families carry, and for the same reason.
     *
     * These do exactly what they were designed to do; the judgement is about the gap between that and
     * what error-detection codes get used for. A parity bit is the weakest member of that group and
     * the badge cannot say so in one word -- which is what `P001` is for, since a lint rule is handed
     * the spec and can be right about the configuration actually chosen.
     */
    security: "not-a-mac",
    outputEncodings: meta.kind === "uart" ? TEXT_ONLY : BIT_ENCODINGS,
    readsInput: meta.usesInput,
    /**
     * Two of the three. The parity bits and a Hamming codeword are deterministic byte outputs somebody
     * can hold a copy of; the UART tool's is a labelled diagram of a wire, and there is no expected
     * value for a diagram. Its decode direction does return bytes, but those are recovered *data*
     * rather than a published value anybody has in advance.
     */
    supportsVerify: meta.kind !== "uart",
    supportsFile: meta.usesInput,
    /**
     * No streaming, and it is a property of the results rather than a shortcut.
     *
     * Per-byte parity genuinely is incremental, but its *result* is one bit per input byte -- so a
     * stream would have to emit a growing bit string rather than a fixed-width digest, which is not
     * what `ToolStream` is. Whole-message parity, frame decoding and Hamming decoding all need to
     * report per-unit diagnostics that only make sense over the whole input. File input still works
     * and reads into memory, which the Input panel says.
     */
    streaming: false,
  };
}

export const PARITY_MANIFESTS: readonly ToolManifest[] = PARITY_TOOLS.map(toManifest);
