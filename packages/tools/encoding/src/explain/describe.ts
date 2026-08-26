import { requireEncodingTool, VARIANT_LABEL } from "../catalogue/tool-meta";
import {
  readCase,
  readDirection,
  readKeyOrder,
  readPadding,
  readSeparator,
  readVariant,
} from "../pure";
import type { EncodingSpec } from "../spec";

/** One sentence under the tool header — what these exact settings will do, in which direction. */
export function describeSpec(spec: EncodingSpec): string {
  const tool = requireEncodingTool(spec.variant);
  const decoding = readDirection(spec.options) === "decode";
  const variant = readVariant(spec.options, tool.variants[0] ?? "standard");
  const named =
    tool.variants.length > 0 ? `${VARIANT_LABEL[variant]} ${tool.label}` : tool.label;

  if (tool.kind === "cbor") {
    return decoding
      ? "Reads CBOR bytes, given as hex, and prints the item as JSON."
      : `Encodes the JSON input as CBOR — ${
          readKeyOrder(spec.options) === "sorted"
            ? "keys sorted, RFC 8949 deterministic encoding"
            : "keys in the order written"
        }, output as hex.`;
  }

  if (decoding) {
    return `Reads ${named} text and gives back the bytes — whitespace ignored, padding optional.`;
  }

  const extras: string[] = [];
  if (tool.kind === "hex") {
    extras.push(readCase(spec.options) === "upper" ? "upper case" : "lower case");
    const separator = readSeparator(spec.options);
    if (separator !== "none") extras.push(`${separator}-separated`);
  }
  if (tool.exposes.includes("padding") && variant !== "crockford") {
    extras.push(readPadding(spec.options) === "padded" ? "padded" : "unpadded");
  }

  return `Writes the input as ${named}${extras.length > 0 ? ` — ${extras.join(", ")}` : ""}. ${tool.expansion}.`;
}
