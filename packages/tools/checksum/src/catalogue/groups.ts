import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = ["arithmetic", "grouping"] as const;
export type ChecksumOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<
  ChecksumOptionGroup,
  OptionGroupMeta<ChecksumOptionGroup>
> = {
  arithmetic: {
    id: "arithmetic",
    label: "Arithmetic",
    summary: "How wide the result is, and what is done to the sum at the end.",
    order: 10,
    collapsedByDefault: false,
  },
  grouping: {
    id: "grouping",
    label: "Grouping",
    summary: "Whether the input is summed as bytes or as wider words.",
    order: 20,
    collapsedByDefault: false,
  },
};
