import { requireCrcTool } from "../catalogue/tool-meta";
import { formatHexParam, isCustom } from "../pure";
import { resolveModel } from "../resolve";
import type { CrcSpec } from "../spec";

/** One sentence, shown under the tool header — what these exact settings will do. */
export function describeSpec(spec: CrcSpec): string {
  const tool = requireCrcTool(spec.variant);
  const resolved = resolveModel(spec);

  if (!resolved.ok) {
    return `${tool.label} with custom parameters — ${resolved.problem}`;
  }

  const { model } = resolved;
  const bytes = Math.ceil(model.width / 8);
  const reflection =
    model.refIn === model.refOut
      ? model.refIn
        ? "reflected"
        : "not reflected"
      : `reflected on ${model.refIn ? "input" : "output"} only`;

  // The parameters, not just the name. "CRC-16" tells you nothing when there are
  // thirty-one of them; the polynomial tells you which one you are looking at.
  const parameters = `poly ${formatHexParam(model.poly, model.width)}, init ${formatHexParam(
    model.init,
    model.width,
  )}, ${reflection}, xor ${formatHexParam(model.xorOut, model.width)}`;

  return isCustom(spec.options)
    ? `Computes a custom ${model.width}-bit CRC — ${bytes} bytes; ${parameters}.`
    : `Computes ${model.name} — ${bytes} bytes; ${parameters}.`;
}
