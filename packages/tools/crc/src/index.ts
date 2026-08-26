/**
 * The cheap half of the family: constants, the spec schema, the tool list, the option
 * group taxonomy, and the manifests.
 *
 * Nothing here imports `@ocs/algos`. That rules out more modules than it might look
 * like — `./explain/describe` and `./lint/rules` both call `resolveModel`, which needs
 * the model catalogue, so they live on the other side of the split and are re-exported
 * from `./definition` instead. The payoff is that listing five tools in
 * the sidebar does not load sixty-seven model definitions.
 */
export * from "./pure";
export * from "./spec";
export * from "./catalogue/tool-meta";
export * from "./catalogue/groups";
export * from "./manifest";
