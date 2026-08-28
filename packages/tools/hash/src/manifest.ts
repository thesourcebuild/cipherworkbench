import type { OutputEncoding } from "@ocs/contracts/encoding";
import type { ToolManifest } from "@ocs/engine";
import {
  HASH_ALGORITHMS,
  usesInputPanel,
  type HashAlgorithmMeta,
} from "./catalogue/algorithm-meta";

/**
 * Digests have no useful `decimal` or `binary` spelling — nobody quotes a
 * SHA-256 as a 78-digit integer — so the list is narrower than the full
 * `OutputEncoding` union. `latin1` is excluded for the same reason: a digest is
 * not text, and offering to render it as mojibake invites someone to paste that
 * mojibake somewhere.
 */
const DIGEST_OUTPUT_ENCODINGS: readonly OutputEncoding[] = [
  "hex-upper",
  "hex",
  "base64",
  "base64url",
  "base32",
];

function toManifest(meta: HashAlgorithmMeta): ToolManifest {
  return {
    id: meta.id,
    label: meta.label,
    family: "hash",
    category: meta.category,
    tags: [...meta.tags],
    summary: meta.summary,
    // A digest is one-way by definition. There is no "inverse" to offer, and the
    // absence is worth being explicit about: the single most common thing people
    // arrive looking for is a hash *decoder*, which cannot exist.
    directions: ["forward"],
    security: meta.security,
    outputEncodings: DIGEST_OUTPUT_ENCODINGS,
    /**
     * True for every algorithm except the TupleHash set.
     *
     * TupleHash reads a tuple from its own option and its `update()` appends one *element* per
     * call, so feeding a file through in 64 KiB chunks would hash a tuple of chunks -- a
     * well-formed value that means nothing. Rather than buffer the file into a single element and
     * pretend, the file tab is simply not offered. This is the same shape the KDF family uses for
     * tools whose inputs are all options.
     */
    // False for the TupleHash set, whose message is a list option rather than a byte string --
    // which is what `usesInputPanel` has always meant. Until now it only hid the File tab, leaving a
    // textarea on screen that nothing read.
    readsInput: usesInputPanel(meta),
    // TupleHash reads a tuple rather than a byte string, and still produces a digest to check.
    supportsVerify: true,
    supportsFile: usesInputPanel(meta),
    streaming: usesInputPanel(meta),
  };
}

/**
 * One manifest per algorithm — this family contributes many tools to the
 * sidebar, not one. Eager and dependency-free: no `@noble` import is reachable
 * from here (see `catalogue/algorithm-meta.ts`).
 */
export const HASH_MANIFESTS: readonly ToolManifest[] = HASH_ALGORITHMS.map(toManifest);
