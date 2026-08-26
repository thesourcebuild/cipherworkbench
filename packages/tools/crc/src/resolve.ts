import { CRC_CATALOGUE, getCrcModel, mask, type CrcModel } from "@ocs/algos";
import { requireCrcTool } from "./catalogue/tool-meta";
import {
  CUSTOM_MODEL,
  OPTION_INIT,
  OPTION_POLY,
  OPTION_XOR_OUT,
  readHexParam,
  readModel,
  readRefIn,
  readRefOut,
} from "./pure";
import type { CrcSpec } from "./spec";

/**
 * Turns a spec into the `CrcModel` that will actually be computed, or explains why it
 * cannot.
 *
 * Shared by the compute path, the lint rules and `describeSpec`, which is what stops
 * the three from disagreeing — a lint rule that said the polynomial was fine while
 * compute refused it would be worse than no lint rule.
 */
export type ResolvedModel =
  | { ok: true; model: CrcModel; custom: boolean }
  | { ok: false; problem: string; optionId: string };

export function resolveModel(spec: CrcSpec): ResolvedModel {
  const tool = requireCrcTool(spec.variant);
  if (tool.width === undefined) {
    throw new Error(`${spec.variant} has no CRC width — it is not a parametrised CRC.`);
  }

  const name = readModel(spec.options, tool.defaultModel ?? "");

  if (name !== CUSTOM_MODEL) {
    const model = getCrcModel(name);
    if (model) return { ok: true, model, custom: false };
    // A share link or stale saved state can name a model that no longer exists.
    // Falling back to the tool's default beats refusing to render anything.
    const fallback = getCrcModel(tool.defaultModel ?? "");
    if (fallback) return { ok: true, model: fallback, custom: false };
    return { ok: false, problem: `Unknown CRC model: ${name}`, optionId: "model" };
  }

  const width = tool.width;
  const limit = mask(width);

  const poly = readHexParam(spec.options, OPTION_POLY);
  if (poly === undefined) {
    return {
      ok: false,
      problem: "Enter a polynomial in hex — for example 0x04C11DB7.",
      optionId: OPTION_POLY,
    };
  }
  if (poly > limit) {
    return {
      ok: false,
      problem: `The polynomial does not fit in ${width} bits.`,
      optionId: OPTION_POLY,
    };
  }

  // Init and the final xor default to zero, which is a real and common
  // configuration — unlike the polynomial, whose absence means "not configured yet".
  const init = readHexParam(spec.options, OPTION_INIT) ?? 0n;
  if (init > limit) {
    return {
      ok: false,
      problem: `The initial value does not fit in ${width} bits.`,
      optionId: OPTION_INIT,
    };
  }

  const xorOut = readHexParam(spec.options, OPTION_XOR_OUT) ?? 0n;
  if (xorOut > limit) {
    return {
      ok: false,
      problem: `The final xor does not fit in ${width} bits.`,
      optionId: OPTION_XOR_OUT,
    };
  }

  return {
    ok: true,
    custom: true,
    model: {
      name: `Custom CRC-${width}`,
      width,
      poly,
      init,
      refIn: readRefIn(spec.options),
      refOut: readRefOut(spec.options),
      xorOut,
      // No published check value for a model the user invented. Kept at zero and
      // never asserted — `tests/crc.test.ts` only checks `check` for catalogue
      // entries, where it means something.
      check: 0n,
    },
  };
}

/**
 * The catalogue entry whose parameters match these exactly, if there is one.
 *
 * Worth telling the user about: someone hand-entering parameters to reverse-engineer
 * an unknown checksum has, more often than not, just rediscovered MODBUS. Naming it
 * saves them the rest of the search.
 */
export function matchingCatalogueEntry(model: CrcModel): CrcModel | undefined {
  return CRC_CATALOGUE.find(
    (candidate) =>
      candidate.width === model.width &&
      candidate.poly === model.poly &&
      candidate.init === model.init &&
      candidate.refIn === model.refIn &&
      candidate.refOut === model.refOut &&
      candidate.xorOut === model.xorOut,
  );
}
