import type { ToolResult, ToolResultField } from "@ocs/engine";
import { requireEncodingTool, VARIANT_ALPHABET, VARIANT_LABEL } from "./catalogue/tool-meta";
import { decodeFromText, encodeToText, type EncodeSettings } from "./codec";
import {
  readCase,
  readDirection,
  readJsonIndent,
  readKeyOrder,
  readPadding,
  readSeparator,
  readVariant,
} from "./pure";
import type { EncodingSpec } from "./spec";

function settingsFor(spec: EncodingSpec): EncodeSettings {
  const meta = requireEncodingTool(spec.variant);
  return {
    kind: meta.kind,
    variant: readVariant(spec.options, meta.variants[0] ?? "standard"),
    padding: readPadding(spec.options),
    upper: readCase(spec.options) === "upper",
    separator: readSeparator(spec.options),
    keyOrder: readKeyOrder(spec.options),
    jsonIndent: readJsonIndent(spec.options),
  };
}

/**
 * What the settings are, for the Info panel: `ToolDefinition.info`.
 *
 * All of it follows from the spec, so it is on screen before anything is typed -- which is the point.
 * The alphabet and the expansion ratio are the two facts that decide whether a format suits a job,
 * and both are things people look up rather than remember.
 */
export function encodingInfo(spec: EncodingSpec): ToolResultField[] {
  const meta = requireEncodingTool(spec.variant);
  const settings = settingsFor(spec);
  const fields: ToolResultField[] = [];

  if (meta.variants.length > 0) {
    fields.push({
      label: "Alphabet",
      value: `${VARIANT_LABEL[settings.variant]} — ${VARIANT_ALPHABET[settings.variant] ?? "—"}`,
      hint: "The characters this variant uses. Text written in one alphabet decodes as different bytes, or as nothing at all, in another.",
    });
  }

  fields.push({
    label: "Size",
    value: meta.expansion,
    hint: "How much bigger the encoded form is than the bytes it carries. The reason an encoding is a transport decision and not a free one.",
  });

  if (meta.kind === "cbor") {
    fields.push({
      label: "Encoding rules",
      value:
        settings.keyOrder === "sorted"
          ? "RFC 8949 deterministic (sorted keys, shortest forms)"
          : "RFC 8949 preferred (shortest forms, keys as written)",
      hint: "This writer always uses the shortest integer, length and float encoding that fits, so the same value always produces the same bytes. Sorting the keys as well is what RFC 8949 section 4.2.1 calls deterministic encoding, and what you need if the bytes will be hashed or signed.",
    });
  }

  const checkInput = meta.checkInput ?? "Hello";
  fields.push({
    label: "Check value",
    value: `${checkInput} → ${meta.check}`,
    hint: `Encode ${checkInput} with these default settings and this is what comes out — a quick way to confirm this tool and whatever you are comparing it against agree on the alphabet.`,
  });

  return fields;
}

export async function computeEncoding(
  spec: EncodingSpec,
  input: Uint8Array,
): Promise<ToolResult> {
  const settings = settingsFor(spec);
  const direction = readDirection(spec.options);

  try {
    if (direction === "encode") {
      const text = encodeToText(input, settings);
      return {
        // `text`, not `bytes`: the output *is* characters, and spelling it through an output encoding
        // would mean re-encoding the encoding. The result panel renders `text` verbatim.
        text,
        fields: [
          { label: "Length", value: `${text.length} characters from ${input.length} bytes` },
        ],
      };
    }

    // Decoding reads the input as text. What arrived is the UTF-8 bytes of whatever was typed or
    // pasted, so this is the inverse of the input panel rather than a second interpretation of it.
    const asText = new TextDecoder("utf-8", { fatal: false }).decode(input);
    const result = decodeFromText(asText, settings);

    if (result.text !== undefined) {
      return {
        text: result.text,
        fields: result.notes.map((note, index) => ({
          label: index === 0 ? "Note" : " ",
          value: note,
        })),
      };
    }
    if (!result.bytes) return {};
    return {
      bytes: result.bytes,
      fields: [
        {
          label: "Length",
          value: `${result.bytes.length} bytes from ${asText.trim().length} characters`,
        },
      ],
    };
  } catch (error) {
    /**
     * A decode failure is a result, not an exception.
     *
     * Half-typed Base64 is the normal state of that field, and `@scure/base` throws on it. The panel
     * renders this as a message under the input; `compute` throwing would unmount the workbench for a
     * missing character.
     */
    return { error: error instanceof Error ? error.message : String(error) };
  }
}
