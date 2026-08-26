import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { AsymmetricSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: AsymmetricSpec): LintResult<AsymmetricSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: AsymmetricSpec): AsymmetricSpec {
  return applyAllFixesGeneric(spec, RULES);
}
