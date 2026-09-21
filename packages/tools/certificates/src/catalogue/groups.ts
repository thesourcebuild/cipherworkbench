import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = [
  "subject",
  "key",
  "extensions",
  "format",
  "convert",
  "verify",
] as const;
export type CertificateOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<
  CertificateOptionGroup,
  OptionGroupMeta<CertificateOptionGroup>
> = {
  subject: {
    id: "subject",
    label: "Subject Identity",
    summary: "Distinguished Name fields: Common Name, Organization, Country, etc.",
    order: 5,
    collapsedByDefault: false,
  },
  key: {
    id: "key",
    label: "Key & Signature",
    summary: "Key algorithm, curve or key size, and signature hash.",
    order: 10,
    collapsedByDefault: false,
  },
  extensions: {
    id: "extensions",
    label: "Extensions & Validity",
    summary: "Validity duration, CA constraints, SANs, and key usages.",
    order: 15,
    collapsedByDefault: false,
  },
  format: {
    id: "format",
    label: "Format",
    summary: "Input format detection and output layout options.",
    order: 20,
    collapsedByDefault: false,
  },
  convert: {
    id: "convert",
    label: "Conversion",
    summary: "Target format and extraction operations.",
    order: 25,
    collapsedByDefault: false,
  },
  verify: {
    id: "verify",
    label: "Verification",
    summary: "Cryptographic signature validation settings.",
    order: 30,
    collapsedByDefault: false,
  },
};
