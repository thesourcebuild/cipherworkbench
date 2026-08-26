import type { OptionGroupMeta } from "@ocs/engine";

/**
 * Three groups, all in the right-hand Settings rail.
 *
 * Nothing in this family takes a key, an IV or a message-sized parameter, so nothing belongs beside
 * the input -- `placement` is absent throughout, which is the default on purpose. A family that adds
 * a group and forgets to place it lands in the rail rather than vanishing.
 */
export const OPTION_GROUPS = ["direction", "frame", "output"] as const;
export type ParityOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<ParityOptionGroup, OptionGroupMeta<ParityOptionGroup>> = {
  direction: {
    id: "direction",
    label: "Direction",
    summary: "Add the parity, or check what is already there.",
    order: 10,
    collapsedByDefault: false,
  },
  frame: {
    id: "frame",
    label: "Frame",
    summary: "The settings both ends of a serial link have to agree on.",
    order: 20,
    collapsedByDefault: false,
  },
  output: {
    id: "output",
    label: "Output",
    summary: "How the result is laid out.",
    order: 30,
    collapsedByDefault: false,
  },
};
