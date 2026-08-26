import type { OptionGroupMeta } from "@ocs/engine";

/**
 * Four groups, and none of them is `material`.
 *
 * Nothing in this family takes a key, an IV or a nonce, so nothing belongs beside the message in the
 * Input panel -- every group here lands in the right-hand Settings rail, which is where a choice made
 * once belongs. `placement` is therefore absent throughout, and absence is the default on purpose.
 *
 * `generate` is the exception worth naming: for `uuid` and `password` the rail is not "settings for
 * the thing in the box" but the entire input, because there is no box. It is still the rail rather
 * than the Input panel, because the Input panel would then be an empty container with a heading.
 */
export const OPTION_GROUPS = ["direction", "format", "document", "generate"] as const;
export type FormatOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<
  FormatOptionGroup,
  OptionGroupMeta<FormatOptionGroup>
> = {
  direction: {
    id: "direction",
    label: "Direction",
    summary: "Transform the input, or reverse it.",
    order: 10,
    collapsedByDefault: false,
  },
  format: {
    id: "format",
    label: "Format",
    summary: "Which flavour, and how it is written.",
    order: 20,
    collapsedByDefault: false,
  },
  document: {
    id: "document",
    label: "Layout",
    summary: "How the document is written back out.",
    order: 30,
    collapsedByDefault: false,
  },
  generate: {
    id: "generate",
    label: "Generate",
    summary: "What to produce. This tool reads no input.",
    order: 40,
    collapsedByDefault: false,
  },
};
