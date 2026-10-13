import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = ["variant", "message", "key", "transform", "output"] as const;
export type HashOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<HashOptionGroup, OptionGroupMeta<HashOptionGroup>> = {
  /**
   * The algorithm variant selector, rendered directly above the Transform section with no extra heading.
   */
  variant: {
    id: "variant",
    label: "",
    summary: "Which variant of the algorithm to compute.",
    order: 1,
    collapsedByDefault: false,
  },
  /**
   * The TupleHash set's tuple, and nothing else in this family.
   *
   * `placement: "input"` because a tuple *is* the message -- and `placement` is a group field
   * precisely so a family can say that about some of its options without saying it about all of them.
   * It sat in `transform` and therefore in the right-hand Settings rail, which put the one thing you
   * change on every computation in the column meant for decisions made once, with the Input panel
   * beside it holding a text box that TupleHash cannot read.
   */
  message: {
    id: "message",
    label: "Message",
    summary: "What is being hashed. TupleHash takes a tuple rather than a byte string.",
    order: 5,
    placement: "input",
    collapsedByDefault: false,
  },
  /**
   * BLAKE2 and BLAKE3 key, salt, personalisation, and context material.
   *
   * `placement: "input"` because a keyed hash / MAC or salted digest is an input asked of the
   * message-key pair, matching how MAC and Cipher tools place key material in the Input canvas
   * rather than the Settings rail.
   */
  key: {
    id: "key",
    label: "Key",
    summary: "Key, salt, and personalisation material for BLAKE2 and BLAKE3.",
    order: 8,
    placement: "input",
    collapsedByDefault: false,
  },
  transform: {
    id: "transform",
    label: "Transform",
    summary: "What happens to the input before, and to the digest after.",
    order: 10,
    collapsedByDefault: false,
  },
  output: {
    id: "output",
    label: "Output",
    summary: "Digest size, where the algorithm lets you choose it.",
    order: 20,
    collapsedByDefault: false,
  },
};
