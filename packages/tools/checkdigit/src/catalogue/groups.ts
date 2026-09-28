import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = ["general"] as const;
export type CheckDigitOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<
  CheckDigitOptionGroup,
  OptionGroupMeta<CheckDigitOptionGroup>
> = {
  general: {
    id: "general",
    label: "General",
    summary: "Check digit algorithm parameters.",
    order: 10,
    collapsedByDefault: false,
  },
};
