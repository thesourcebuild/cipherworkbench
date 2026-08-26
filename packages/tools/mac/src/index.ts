/**
 * The cheap half of the MAC family. Nothing here imports @noble or @ocs/algos —
 * `./explain/describe` and `./lint/rules` both call `resolveMac`, which decodes a key and
 * therefore reaches the engine's codec, so they live on the lazy side and are re-exported
 * from `./definition`.
 */
export * from "./pure";
export * from "./spec";
export * from "./catalogue/tool-meta";
export * from "./catalogue/groups";
export * from "./manifest";
