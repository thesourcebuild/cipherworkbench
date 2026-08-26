import type { OptionGroupMeta } from "@ocs/engine";

export const OPTION_GROUPS = ["direction", "algorithm", "key", "derivation", "aead"] as const;
export type CipherOptionGroup = (typeof OPTION_GROUPS)[number];

export const OPTION_GROUP_META: Record<
  CipherOptionGroup,
  OptionGroupMeta<CipherOptionGroup>
> = {
  direction: {
    id: "direction",
    label: "Direction",
    summary: "Encrypt the input, or decrypt it.",
    order: 10,
    collapsedByDefault: false,
  },
  algorithm: {
    /*
     * Labelled for the group rather than for one of its options. It was "Mode", which was accurate
     * while Mode was the only control in it and became a heading reading "MODE / Key size / Mode"
     * the moment AES gained a key-size select -- with a summary saying the choice matters more than
     * the key size, directly above the key size. What the group actually collects is everything that
     * decides *which function runs*: the mode for a block cipher, the parameter set or instance for a
     * shaped one, the tag length for an AEAD, and AES's key size.
     *
     * The point the old summary made is not lost: it belongs to the Mode option, whose own `detail`
     * says that choosing badly there is far more damaging than choosing a shorter key.
     */
    id: "algorithm",
    label: "Algorithm",
    summary: "Which variant of the cipher runs, and how its blocks are chained.",
    order: 20,
    collapsedByDefault: false,
  },
  key: {
    id: "key",
    label: "Key and nonce",
    summary: "The key never leaves this machine. The nonce is public and must never repeat.",
    order: 30,
    collapsedByDefault: false,
    placement: "input",
  },
  derivation: {
    /**
     * The cost parameters of whatever KDF is deriving the key, and nothing else.
     *
     * Rail rather than `placement: "input"`, which is the split the KDF family's own groups make: the
     * password and the salt travel *with* the message and sit in the Input panel beside where the Key
     * field was, while an iteration count or an Argon2 memory figure is chosen once. Absent entirely
     * while the key source is Custom, because every option in it is gated on a derived source --
     * `visibleOptionGroups` is what makes the heading disappear along with them.
     */
    id: "derivation",
    label: "Key derivation",
    summary: "How the password becomes a key. Both ends must agree on every value here.",
    order: 35,
    collapsedByDefault: false,
  },
  aead: {
    id: "aead",
    label: "Authenticated data",
    summary: "Covered by the tag, but not encrypted.",
    order: 40,
    collapsedByDefault: false,
    // AAD is part of what the tag covers -- as much an input as the plaintext, and the one thing
    // a decrypting party has to reproduce byte for byte.
    placement: "input",
  },
};
