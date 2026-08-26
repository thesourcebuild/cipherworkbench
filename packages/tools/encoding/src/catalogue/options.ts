import {
  createOptionCatalogue,
  type OptionCatalogue,
  type OptionDef,
  type OptionEnumChoice,
} from "@ocs/engine";
import {
  OPTION_CASE,
  OPTION_DIRECTION,
  OPTION_JSON_INDENT,
  OPTION_KEY_ORDER,
  OPTION_PADDING,
  OPTION_SEPARATOR,
  OPTION_VARIANT,
  type Variant,
} from "../pure";
import { VARIANT_ALPHABET, VARIANT_LABEL, type EncodingToolMeta } from "./tool-meta";
import type { EncodingOptionGroup } from "./groups";

/**
 * The direction control, shared by every tool.
 *
 * An option rather than two tools, and first in the form because it changes what everything below it
 * means: the same alphabet setting is "how to write the output" when encoding and "how to read the
 * input" when decoding.
 */
const DIRECTION: OptionDef<EncodingOptionGroup> = {
  id: OPTION_DIRECTION,
  label: "Direction",
  group: "direction",
  kind: "enum",
  choices: [
    { value: "encode", label: "Encode", summary: "Bytes in, encoded text out" },
    { value: "decode", label: "Decode", summary: "Encoded text in, bytes out" },
  ],
  summary: "Which way the bytes go.",
  detail:
    "Encoding takes whatever the input panel produced and writes it in this alphabet. Decoding reads the input as text in this alphabet and gives back the bytes, which the result panel then spells however you ask — pick Text (UTF-8) to read a decoded string, or hex to look at the bytes themselves.",
  order: 10,
};

/** The alphabet menu, built from the tool's own list so a tool can only offer what it supports. */
function variantOption(variants: readonly Variant[]): OptionDef<EncodingOptionGroup> {
  const choices: OptionEnumChoice[] = variants.map((variant) => ({
    value: variant,
    label: VARIANT_LABEL[variant],
    ...(VARIANT_ALPHABET[variant] ? { summary: VARIANT_ALPHABET[variant] } : {}),
  }));

  return {
    id: OPTION_VARIANT,
    label: "Alphabet",
    group: "format",
    kind: "enum",
    choices,
    summary: "Which characters the encoding uses.",
    detail:
      "The alphabets are not interchangeable: the same bytes produce different text in each, and text written in one will usually decode as garbage or as nothing in another. Where a value came with a name — a Bitcoin address, a JWT segment, a TOTP secret — that name is what picks the row here.",
    order: 10,
  };
}

const PADDING: OptionDef<EncodingOptionGroup> = {
  id: OPTION_PADDING,
  label: "Padding",
  group: "format",
  kind: "enum",
  choices: [
    {
      value: "padded",
      label: "Padded",
      summary: "Trailing = to a whole group, as RFC 4648 says",
    },
    {
      value: "unpadded",
      label: "No padding",
      summary: "As JWTs, and as base64url usually appears",
    },
  ],
  // Crockford's Base32 has no padding in its specification, so the control is hidden there rather
  // than shown and ignored.
  availableOn: ["padded-format"],
  summary: "Whether the output is filled out to a whole group with =.",
  detail:
    "RFC 4648 requires the padding unless the specification using it says otherwise, and plenty do: a JWT's segments carry none, and neither do most base64url values in URLs. It changes nothing about the bytes. Decoding accepts either, because refusing a value over a character that carries no information would be pedantry rather than validation.",
  order: 20,
};

const CASE: OptionDef<EncodingOptionGroup> = {
  id: OPTION_CASE,
  label: "Case",
  group: "format",
  kind: "enum",
  choices: [
    { value: "lower", label: "Lower case", summary: "deadbeef" },
    { value: "upper", label: "Upper case", summary: "DEADBEEF" },
  ],
  summary: "Which case the encoded digits use.",
  detail:
    "Presentation only — hex is case-insensitive on the way back in, and this tool accepts either. Upper case is what certificate fingerprints and a lot of protocol documentation use; lower case is what most tooling prints.",
  order: 30,
};

const SEPARATOR: OptionDef<EncodingOptionGroup> = {
  id: OPTION_SEPARATOR,
  label: "Separator",
  group: "format",
  kind: "enum",
  choices: [
    { value: "none", label: "None", summary: "deadbeef" },
    { value: "space", label: "Space", summary: "de ad be ef" },
    { value: "colon", label: "Colon", summary: "de:ad:be:ef" },
    { value: "dash", label: "Dash", summary: "de-ad-be-ef" },
  ],
  summary: "What goes between the bytes.",
  detail:
    "Colons are how OpenSSL and every certificate viewer print a fingerprint; spaces are how a hex dump reads. Decoding ignores all of them, along with newlines, so a fingerprint pasted straight out of a certificate viewer works without cleaning it up first.",
  order: 40,
};

const KEY_ORDER: OptionDef<EncodingOptionGroup> = {
  id: OPTION_KEY_ORDER,
  label: "Map key order",
  group: "format",
  kind: "enum",
  choices: [
    { value: "as-written", label: "As written", summary: "The order the JSON has them in" },
    {
      value: "sorted",
      label: "Sorted",
      summary: "Deterministic encoding, RFC 8949 section 4.2.1",
    },
  ],
  availableOn: ["encode"],
  summary: "Whether map keys are sorted before encoding.",
  detail:
    "CBOR preserves the order keys were written in, so two encodings of the same JSON object differ if the keys were typed in a different order. Sorting them is what RFC 8949's deterministic encoding requires, and it is what makes the bytes comparable — which matters if you are hashing or signing the result rather than just transmitting it.",
  order: 50,
};

const JSON_INDENT: OptionDef<EncodingOptionGroup> = {
  id: OPTION_JSON_INDENT,
  label: "JSON layout",
  group: "output",
  kind: "enum",
  choices: [
    { value: "indented", label: "Indented", summary: "Two spaces per level, for reading" },
    { value: "compact", label: "Compact", summary: "One line, for pasting somewhere else" },
  ],
  // Decoding only: there is no JSON on the way in to lay out.
  availableOn: ["decode"],
  summary: "How the decoded JSON is laid out.",
  detail:
    "Affects the decoded side only. Indented is for looking at a COSE or WebAuthn structure; compact is for feeding the result into something else.",
  order: 10,
};

const BY_ID: Record<string, OptionDef<EncodingOptionGroup>> = {
  [OPTION_PADDING]: PADDING,
  [OPTION_CASE]: CASE,
  [OPTION_SEPARATOR]: SEPARATOR,
  [OPTION_KEY_ORDER]: KEY_ORDER,
  [OPTION_JSON_INDENT]: JSON_INDENT,
};

const CACHE = new Map<string, OptionCatalogue<EncodingOptionGroup>>();

/** Memoised per tool: `ToolDefinition.catalogue` is resolved once, and this never changes. */
export function encodingCatalogueFor(
  meta: EncodingToolMeta,
): OptionCatalogue<EncodingOptionGroup> {
  let catalogue = CACHE.get(meta.id);
  if (!catalogue) {
    const options: OptionDef<EncodingOptionGroup>[] = [DIRECTION];
    for (const id of meta.exposes) {
      if (id === OPTION_VARIANT) {
        options.push(variantOption(meta.variants));
        continue;
      }
      const option = BY_ID[id];
      if (!option) throw new Error(`${meta.id} exposes unknown encoding option: ${id}`);
      options.push(option);
    }
    catalogue = createOptionCatalogue<EncodingOptionGroup>(options);
    CACHE.set(meta.id, catalogue);
  }
  return catalogue;
}

/** Every option definition in the family, for `validateCatalogue`. */
export const ALL_ENCODING_OPTIONS: readonly OptionDef<EncodingOptionGroup>[] = [
  DIRECTION,
  variantOption(["standard", "urlsafe"]),
  PADDING,
  CASE,
  SEPARATOR,
  KEY_ORDER,
  JSON_INDENT,
];
