import type { OptionGroupMeta } from "@ocs/engine";

export type PasswordArtifactOptionGroup = "extraction";

export const OPTION_GROUP_META: Record<PasswordArtifactOptionGroup, OptionGroupMeta> = {
  extraction: {
    id: "extraction",
    label: "Extraction",
    summary: "Format-specific source location and header selection.",
    order: 10,
    collapsedByDefault: false,
  },
};
