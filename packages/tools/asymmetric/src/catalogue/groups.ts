import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = ["operation", "algorithm", "keys", "material"] as const;
export type AsymmetricOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<
  AsymmetricOptionGroup,
  OptionGroupMeta<AsymmetricOptionGroup>
> = {
  operation: {
    id: "operation",
    label: "Operation",
    summary: "Generate a keypair, sign, verify, encrypt, decrypt or derive a shared secret.",
    order: 10,
    collapsedByDefault: false,
  },
  algorithm: {
    id: "algorithm",
    label: "Parameters",
    summary: "The curve or key size, and the hash the scheme is built on.",
    order: 20,
    collapsedByDefault: false,
  },
  keys: {
    id: "keys",
    label: "Keys",
    summary:
      "The private key never leaves this machine and is never put in a share link. The public key is not secret.",
    order: 30,
    collapsedByDefault: false,
    placement: "input",
  },
  material: {
    id: "material",
    label: "Signature and labels",
    summary: "What is being checked, and anything bound alongside it.",
    order: 40,
    collapsedByDefault: false,
    // A signature being verified is an input in the same sense the message is: verification is a
    // question asked of the pair.
    placement: "input",
  },
};
