import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = [
  "mode",
  "subject",
  "key",
  "extensions",
  "ca",
  "mtls",
  "format",
  "convert",
  "verify",
  "pair",
] as const;
export type CertificateOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<
  CertificateOptionGroup,
  OptionGroupMeta<CertificateOptionGroup>
> = {
  mode: {
    id: "mode",
    label: "Creation Mode",
    summary: "Select between an individual certificate or the full mTLS suite.",
    order: 2,
    collapsedByDefault: false,
  },
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
  ca: {
    id: "ca",
    label: "CA Signing Authority",
    summary: "Issuing CA certificate and private key for CA-signed issuance.",
    order: 16,
    collapsedByDefault: false,
  },
  mtls: {
    id: "mtls",
    label: "mTLS Suite Settings",
    summary: "Settings for client certificate, SANs, and PKCS#12 archive.",
    order: 18,
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
  pair: {
    id: "pair",
    label: "",
    summary: "Second certificate or private key to match or compare against.",
    order: 1,
    collapsedByDefault: false,
    placement: "input",
  },
};
