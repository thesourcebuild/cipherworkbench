import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import { CLASSICAL_TOOLS, type ClassicalToolMeta } from "./catalogue/tool-meta";

/**
 * One entry, which is what hides the Result panel's encoding selector.
 *
 * A Caesar cipher's output is *letters*. Offering to spell it as Base64 or as decimal would be a
 * control that either does nothing useful or answers a question nobody asked -- and it would invite
 * the confusion this family is most likely to attract: that the cipher could be applied to bytes or to
 * hex. It cannot. The alphabet is 26 letters, and anything else in the input passes through.
 */
const TEXT_ONLY: readonly OutputEncoding[] = ["utf-8"];

function toManifest(meta: ClassicalToolMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "classical",
    category: meta.category,
    tags: [...meta.tags],
    summary: meta.summary,
    // Both ways, which is what puts the arrow on the header badge.
    directions: ["forward", "inverse"],
    /**
     * `broken`, and it is the only honest word available.
     *
     * Not `not-encryption`, which the encoding and format families carry: Base64 makes no claim to
     * hide anything, whereas this is a cipher with a key that is meant to. It just has 26 keys, so it
     * is broken in the strongest sense the badge can express -- by exhaustive search, by hand, in
     * seconds, without a computer. `X001` is what says that in a sentence, since a badge is one word.
     */
    security: "broken",
    outputEncodings: TEXT_ONLY,
    readsInput: true,
    /**
     * Yes: a Caesar ciphertext is exactly the kind of value somebody already has.
     *
     * The output is text rather than bytes, so `VerifyPanel` compares it with `verifyText` -- a plain
     * trimmed comparison, which is right here. There is no encoding to auto-detect when the value *is*
     * the string, and no case folding, because case is a setting of this tool and folding it away would
     * make the Letter case control unverifiable.
     */
    supportsVerify: true,
    supportsFile: true,
    /**
     * No streaming, and it is a property of the working rather than of the cipher.
     *
     * The shift itself is perfectly incremental -- it is a per-character map with no state at all. What
     * is not incremental is the 26-shift table below the result, which needs the whole input to lay
     * out. File input still works and reads into memory, which the Input panel says.
     */
    streaming: false,
  };
}

export const CLASSICAL_MANIFESTS: readonly ToolManifest[] = CLASSICAL_TOOLS.map(toManifest);
