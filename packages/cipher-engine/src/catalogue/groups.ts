/**
 * Shape of one entry in a tool's group taxonomy (its display sections in the
 * options form). The taxonomy itself — which groups exist, in what order —
 * is tool-specific data and lives in `packages/tools/<family>`, not here.
 */
export interface OptionGroupMeta<TGroup extends string = string> {
  id: TGroup;
  label: string;
  summary: string;
  /** Display order in the options form. */
  order: number;
  /** Groups the form collapses by default. */
  collapsedByDefault: boolean;
  /**
   * Where this group renders. Omit for the right-hand Settings rail, which is the default.
   *
   *  - `"input"` -- inside the Input panel, under the message. For what the user hands the tool
   *    *with* the message: a key, an IV, a nonce, a salt, a signature, associated data. The two
   *    things you give a cipher are the plaintext and the key, and they belong next to each other.
   *  - `"panel"` -- its own panel between Input and Result, titled with the group's label. For a
   *    parameter set being worked on rather than a value being supplied: CRC's seven custom
   *    parameters, which someone tries, reads a result from, and tries again. Six controls need the
   *    room, and they are not part of the message.
   *
   * A group-level decision rather than a per-option one, because a group is already the statement
   * that some options belong together -- and because inferring it from `OptionKind` gets RSA wrong,
   * where the private key is a `password` and the public key a multi-line `text`, so a kind-based
   * rule would split the pair across the screen.
   */
  placement?: "input" | "panel";
}

/** Sort a tool's group metadata record into display order. */
export function orderedGroups<TGroup extends string>(
  meta: Record<TGroup, OptionGroupMeta<TGroup>>,
): OptionGroupMeta<TGroup>[] {
  return Object.values<OptionGroupMeta<TGroup>>(meta).sort((a, b) => a.order - b.order);
}
