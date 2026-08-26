import {
  hasVariableOutput,
  requireHashAlgorithm,
  resolveOutputLen,
  resolvePasses,
} from "../catalogue/algorithm-meta";
import {
  readHashVariant,
  readIterations,
  readPasses,
  readRequestedOutputLength,
  readSeed,
} from "../pure";
import type { HashSpec } from "../spec";

/**
 * One sentence, shown under the tool header — what these exact settings will do.
 *
 * The length goes through the same `resolveOutputLen` the compute path uses, so what
 * this claims is what will actually come out. Asking BLAKE2s for 64 bytes is clamped
 * to 32, and a header that said "64 bytes" while the result panel showed 32 would be
 * worse than no header at all.
 */
export function describeSpec(spec: HashSpec): string {
  const meta = requireHashAlgorithm(spec.algorithm);
  const length = resolveOutputLen(
    meta,
    hasVariableOutput(meta) ? readRequestedOutputLength(spec.options) : undefined,
    meta.variants ? readHashVariant(spec.options) : undefined,
  );
  const iterations = readIterations(spec.options);

  const size = `${length} bytes (${length * 8} bits)`;

  // A non-zero seed changes the answer completely, so it belongs in the one-line summary
  // rather than only in the settings panel.
  const seed = meta.seeded ? readSeed(spec.options) : 0;
  const seedNote = seed !== 0 ? `, seed ${seed}` : "";

  /**
   * The pass count belongs in the one-line summary because it changes the digest completely.
   *
   * Someone reproducing a stored HAVAL value has to match it, and the difference between three and
   * five passes is not a variation on an answer -- it is a different function.
   */
  const passes = resolvePasses(meta, readPasses(spec.options));
  const passNote = passes === undefined ? "" : `, ${passes} passes`;

  if (iterations === 1) {
    return `Computes a ${meta.label} digest — ${size}${passNote}${seedNote}.`;
  }
  if (iterations === 2) {
    return `Computes a double ${meta.label} digest — ${meta.label} applied twice, ${size}.`;
  }
  return `Computes a ${meta.label} digest re-hashed ${iterations} times — ${size}.`;
}
