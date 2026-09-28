import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { CheckDigitSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: CheckDigitSpec): LintResult<CheckDigitSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: CheckDigitSpec): CheckDigitSpec {
  return applyAllFixesGeneric(spec, RULES);
}
