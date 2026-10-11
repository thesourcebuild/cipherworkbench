import { requireClassicalTool, type ClassicalToolMeta } from "./catalogue/tool-meta";
import {
  OPTION_MULTIPLIER,
  OPTION_OFFSET,
  readAffineMultiplier,
  readAffineOffset,
  readDirection,
  readLetterCase,
  readRotVariant,
  readShift,
  type Direction,
  type LetterCase,
  type RotVariant,
} from "./pure";
import type { ClassicalSpec } from "./spec";

export interface ResolvedClassical {
  tool: ClassicalToolMeta;
  direction: Direction;
  letterCase: LetterCase;
  shift: number;
  affineMultiplier: number;
  affineOffset: number;
  rotVariant: RotVariant;
}

export type ClassicalResolution =
  { ok: true; value: ResolvedClassical } | { ok: false; problem: string; optionId: string };

function gcd(a: number, b: number): number {
  let x = Math.abs(a);
  let y = Math.abs(b);
  while (y !== 0) [x, y] = [y, x % y];
  return x;
}

/** One option resolution shared by compute, lint, describe and info. */
export function resolveClassical(spec: ClassicalSpec): ClassicalResolution {
  const tool = requireClassicalTool(spec.variant);
  const affineMultiplier = readAffineMultiplier(spec.options);
  const affineOffset = readAffineOffset(spec.options);

  if (
    tool.kind === "affine" &&
    (!Number.isInteger(affineMultiplier) ||
      affineMultiplier < 1 ||
      affineMultiplier > 25 ||
      gcd(affineMultiplier, 26) !== 1)
  ) {
    return {
      ok: false,
      problem: "The affine multiplier must be an integer from 1 to 25 that is coprime with 26.",
      optionId: OPTION_MULTIPLIER,
    };
  }
  if (
    tool.kind === "affine" &&
    (!Number.isInteger(affineOffset) || affineOffset < 0 || affineOffset > 25)
  ) {
    return {
      ok: false,
      problem: "The affine offset must be an integer from 0 to 25.",
      optionId: OPTION_OFFSET,
    };
  }

  return {
    ok: true,
    value: {
      tool,
      direction: readDirection(spec.options),
      letterCase: readLetterCase(spec.options),
      shift: readShift(spec.options),
      affineMultiplier,
      affineOffset,
      rotVariant: readRotVariant(spec.options),
    },
  };
}
