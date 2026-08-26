import type { ToolDefinition } from "@ocs/engine";
import { requireHashBinding } from "./bindings";
import { HASH_ALGORITHMS, requireHashAlgorithm, variantTags } from "./catalogue/algorithm-meta";
import { OPTION_GROUP_META } from "./catalogue/groups";
import { hashCatalogueFor } from "./catalogue/options";
import { computeHash, createHashStream, hashVariants } from "./compute";
import { describeSpec } from "./explain/describe";
import { RULES } from "./lint/rules";
import { HASH_MANIFESTS } from "./manifest";
import { createSpec } from "./create-spec";
import { HashSpec } from "./spec";

/**
 * Builds the full contract for one digest algorithm.
 *
 * Every algorithm in this family shares the same lint rules and compute
 * path — the only thing that varies is which manifest and which
 * binding. So this is a function over the manifest list rather than N
 * hand-written definition objects, and adding an algorithm means adding a
 * metadata entry plus a binding, with nothing to wire up here.
 *
 * Deliberately not re-exported from `./index` — importing the barrel must not
 * drag `@noble` in, which is the whole point of the manifest/definition split.
 */
export function hashToolDefinition(algorithmId: string): ToolDefinition<HashSpec> {
  const meta = requireHashAlgorithm(algorithmId);
  const manifest = HASH_MANIFESTS.find((m) => m.id === algorithmId);
  if (!manifest) throw new Error(`No manifest for hash algorithm: ${algorithmId}`);

  return {
    ...manifest,
    groups: OPTION_GROUP_META,
    catalogue: hashCatalogueFor(meta),
    lintRules: RULES,
    createSpec: () => createSpec({ algorithm: algorithmId }),
    specSchema: HashSpec,
    describe: describeSpec,
    compute: computeHash,
    /**
     * Present for every algorithm but the TupleHash set.
     *
     * `ToolDefinition` requires `createStream` exactly when the manifest says `streaming: true`,
     * and TupleHash says false -- its `update()` appends a tuple element rather than more of a
     * message. Offering a stream that threw would satisfy the type and violate the contract.
     */
    ...(manifest.streaming ? { createStream: createHashStream } : {}),
    /**
     * Every algorithm in the family over the same input, at each one's own defaults.
     *
     * Offered on every hash tool including the TupleHash ones, which are simply absent from the
     * *rows*: the panel is about the family, not about the tool it happens to be viewed from, and a
     * tool that cannot appear in its own table can still show it.
     */
    variants: hashVariants,
    /**
     * One tag, so the extra controls are mutually exclusive: a variable-output algorithm
     * shows `outputLength`, a seeded one shows `seed`, and a plain fixed digest shows
     * neither. No algorithm currently needs both — SHAKE and the BLAKEs take no seed, and
     * the xxHash pair have fixed output — and if one ever does, this is the line that has
     * to grow rather than the option definitions.
     */
    /**
     * Every axis this algorithm sits on, not just one.
     *
     * cSHAKE is variable-output *and* customisable *and* takes a function name, so a single tag
     * could not describe it -- which is what pushed `ToolDefinition.variantTag` to accept an array.
     * Derived from the metadata by `variantTags`, so a new control is one boolean on one entry.
     */
    variantTag: () => variantTags(meta),
  };
}

/** Every tool this family provides, for the registry's loader to dispatch over. */
export const HASH_TOOL_IDS: readonly string[] = HASH_ALGORITHMS.map((a) => a.id);

// Re-exported from this side of the manifest/definition split, not from `./index`:
// these reach `@noble`, and the test suite needs them to check the declared
// output lengths against the real ones.
export { computeHash, createHashStream, hashVariants } from "./compute";
export { getHashBinding, requireHashBinding } from "./bindings";

/**
 * Await any one-time setup this algorithm needs before its definition is used.
 *
 * Only FSB has any: its matrix table is a dynamic import, so that the other 138 hash tools are not made
 * to download 266 KB for a withdrawn SHA-3 round-1 submission. `loadTool()` calls this, which is what
 * lets the `Hasher` and `ToolStream` contracts stay synchronous.
 *
 * A no-op for every other algorithm, and safe to call repeatedly.
 */
export async function prepareHashAlgorithm(id: string): Promise<void> {
  await requireHashBinding(id).prepare?.();
}
