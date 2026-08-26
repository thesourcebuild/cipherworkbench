/**
 * Barrel for everything except `./definition` — that module imports `@noble`,
 * and keeping it out of here is what lets the app list every algorithm in the
 * sidebar without loading a single compression function. Only the registry's
 * `loadTool()` reaches into `./definition`, on demand.
 */
export * from "./pure";
export * from "./spec";
export * from "./catalogue/algorithm-meta";
export * from "./catalogue/groups";
export * from "./catalogue/options";
export * from "./explain/describe";
export * from "./lint/rules";
export * from "./lint/run";
export * from "./create-spec";
export * from "./manifest";

// Bindings and compute are safe to name here as types, but their modules import
// @noble, so they are exported from `./definition`'s side of the split instead.
export type { HashBinding, Hasher } from "./bindings";
