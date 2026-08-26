/**
 * The cheap half of the family: constants, the spec schema, the tool list, the option group
 * taxonomy, and the manifests.
 *
 * Nothing here imports `@ocs/algos`. Note that this family's `lint/rules` and `explain/describe`
 * *are* barrel-safe — unlike `@ocs/crc`'s, which both call `resolveModel` and so need the model
 * catalogue — but they stay on the lazy side anyway, because keeping the two families' shapes
 * identical is worth more than the handful of bytes.
 */
export * from "./pure";
export * from "./spec";
export * from "./catalogue/tool-meta";
export * from "./catalogue/groups";
export * from "./manifest";
