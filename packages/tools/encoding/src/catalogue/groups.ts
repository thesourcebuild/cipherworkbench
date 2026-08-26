import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = ["direction", "format", "output"] as const;
export type EncodingOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<
  EncodingOptionGroup,
  OptionGroupMeta<EncodingOptionGroup>
> = {
  direction: {
    id: "direction",
    label: "Direction",
    summary: "Encode the input, or decode it.",
    order: 10,
    collapsedByDefault: false,
  },
  format: {
    id: "format",
    label: "Format",
    summary: "Which alphabet, and how it is written.",
    order: 20,
    collapsedByDefault: false,
  },
  output: {
    id: "output",
    label: "Output",
    summary: "How the decoded side is presented.",
    order: 30,
    collapsedByDefault: false,
  },
};
