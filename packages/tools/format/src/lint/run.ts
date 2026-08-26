import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { FormatSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: FormatSpec): LintResult<FormatSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: FormatSpec): FormatSpec {
  return applyAllFixesGeneric(spec, RULES);
}
