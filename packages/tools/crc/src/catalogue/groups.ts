import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = ["model", "parameters"] as const;
export type CrcOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<CrcOptionGroup, OptionGroupMeta<CrcOptionGroup>> = {
  model: {
    id: "model",
    label: "Model",
    summary: "Which named variant to compute.",
    order: 10,
    collapsedByDefault: false,
  },
  parameters: {
    id: "parameters",
    label: "Custom parameters",
    summary: "The seven values that define a CRC. Only used when the model is Custom.",
    order: 20,
    collapsedByDefault: false,
    /**
     * Its own panel between Input and Result, rather than the Settings rail.
     *
     * Reverse engineering an undocumented checksum means trying a polynomial, reading the value it
     * produces, and trying another -- so these want to be near the result, wide enough to sit one
     * per row, and not folded into the message they are not part of. Six controls doing that in an
     * 18rem rail was the wrong place for them. They still appear only in Custom mode, because
     * `availableOn` decides that separately.
     */
    placement: "panel",
  },
};
