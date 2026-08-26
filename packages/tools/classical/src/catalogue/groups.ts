import type { OptionGroupMeta } from "@ocs/engine";

/**
 * Two groups, both in the right-hand Settings rail.
 *
 * Nothing here takes a key, an IV or any material that arrives *with* the message -- the shift is a
 * number you set once -- so `placement` is absent throughout, which is the default on purpose: a
 * family that adds a group and forgets to place it lands in the rail rather than vanishing.
 *
 * The shift is deliberately not in an `input`-placed group even though it is the cipher's key. It is a
 * number between 0 and 25, not a byte string, and putting a spinner under the textarea would make it
 * look like the key fields in the cipher family, which take hex.
 */
export const OPTION_GROUPS = ["cipher", "output"] as const;
export type ClassicalOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<
  ClassicalOptionGroup,
  OptionGroupMeta<ClassicalOptionGroup>
> = {
  cipher: {
    id: "cipher",
    label: "Cipher",
    summary: "Which way, and by how much.",
    order: 10,
    collapsedByDefault: false,
  },
  output: {
    id: "output",
    label: "Output",
    summary: "How the result is written.",
    order: 20,
    collapsedByDefault: false,
  },
};
