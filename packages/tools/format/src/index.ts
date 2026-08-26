/**
 * The cheap half of the family: constants, the spec schema, the tool list, the group taxonomy and the
 * manifests. Nothing here imports `uuid`, `entities`, `jsonc-parser`, `@xmldom/xmldom` or
 * `change-case` -- which is what lets the sidebar list eight tools for the price of the strings.
 */
export * from "./pure";
export * from "./spec";
export * from "./catalogue/tool-meta";
export * from "./catalogue/groups";
export * from "./manifest";
