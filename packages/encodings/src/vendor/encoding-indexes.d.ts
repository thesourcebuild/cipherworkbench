/**
 * The WHATWG index tables. Typed as `unknown` on purpose: the shape is a heterogeneous mix of
 * sparse arrays, nested arrays and range objects that only the vendored engine reads, and
 * describing it accurately would be a large type nobody would ever consult.
 */
declare const indexes: unknown;
export default indexes;
