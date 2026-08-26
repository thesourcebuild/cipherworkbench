import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = ["mode", "secret", "cost", "output"] as const;
export type KdfOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<KdfOptionGroup, OptionGroupMeta<KdfOptionGroup>> = {
  mode: {
    id: "mode",
    label: "Mode",
    summary: "Derive a new value, or check an existing one.",
    order: 10,
    collapsedByDefault: false,
  },
  secret: {
    id: "secret",
    label: "Input",
    summary: "The password or key material, and the salt.",
    order: 20,
    collapsedByDefault: false,
    // Already labelled "Input", which rather made the point: this group is what the function is
    // applied to, not how it is configured.
    placement: "input",
  },
  cost: {
    id: "cost",
    label: "Cost",
    summary: "How much work an attacker has to repeat per guess.",
    order: 30,
    collapsedByDefault: false,
  },
  output: {
    id: "output",
    label: "Output",
    summary: "Derived key length.",
    order: 40,
    collapsedByDefault: false,
  },
};
