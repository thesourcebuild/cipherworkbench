import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { MacSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: MacSpec): LintResult<MacSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: MacSpec): MacSpec {
  return applyAllFixesGeneric(spec, RULES);
}
