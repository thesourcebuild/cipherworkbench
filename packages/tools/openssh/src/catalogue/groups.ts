import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = [
  "preset",
  "output",
  "key",
  "options",
  "security",
] as const;
export type OpenSshOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<
  OpenSshOptionGroup,
  OptionGroupMeta<OpenSshOptionGroup>
> = {
  preset: {
    id: "preset",
    label: "Configuration Presets",
    summary: "Quick-start templates for common environments.",
    order: 5,
    collapsedByDefault: false,
    // placement: undefined -> renders in Settings tab of right sidebar before Info
  },
  output: {
    id: "output",
    label: "Output Format",
    summary: "Format displayed in the primary Result panel.",
    order: 10,
    collapsedByDefault: false,
    // placement: undefined -> renders in Settings tab of right sidebar before Info
  },
  key: {
    id: "key",
    label: "Key Parameters",
    summary: "Cryptographic algorithm and key parameters.",
    order: 20,
    collapsedByDefault: false,
    placement: "input",
    columns: 2,
  },
  options: {
    id: "options",
    label: "Key Metadata",
    summary: "Public key comment label and default file naming.",
    order: 30,
    collapsedByDefault: false,
    placement: "input",
    columns: 2,
  },
  security: {
    id: "security",
    label: "Passphrase Protection",
    summary: "AES-256-CTR and bcrypt-PBKDF private key encryption settings.",
    order: 40,
    collapsedByDefault: false,
    placement: "input",
    columns: 2,
  },
};
