import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = ["key", "algorithm", "output"] as const;
export type MacOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<MacOptionGroup, OptionGroupMeta<MacOptionGroup>> = {
  key: {
    id: "key",
    label: "Key",
    summary: "The secret. Never included in a share link.",
    order: 10,
    collapsedByDefault: false,
    // A MAC takes two things: a message and a key. Putting them at opposite ends of the screen
    // made one of them look like a setting.
    placement: "input",
  },
  algorithm: {
    id: "algorithm",
    label: "Algorithm",
    summary: "Which primitive the MAC is built on.",
    order: 20,
    collapsedByDefault: false,
  },
  output: {
    id: "output",
    label: "Output",
    summary: "Tag length.",
    order: 30,
    collapsedByDefault: false,
  },
};
