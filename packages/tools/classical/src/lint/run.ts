import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { ClassicalSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: ClassicalSpec): LintResult<ClassicalSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: ClassicalSpec): ClassicalSpec {
  return applyAllFixesGeneric(spec, RULES);
}
