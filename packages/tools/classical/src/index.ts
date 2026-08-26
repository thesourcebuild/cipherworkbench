/**
 * The cheap half of the family: constants, the spec schema, the tool list and the group taxonomy.
 * Nothing here imports `@ocs/algos` -- which is what lets the sidebar list this for the price of the
 * strings.
 */
export * from "./pure";
export * from "./spec";
export * from "./catalogue/tool-meta";
export * from "./catalogue/groups";
export * from "./manifest";
