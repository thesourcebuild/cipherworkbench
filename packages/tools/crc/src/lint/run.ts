import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { CrcSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: CrcSpec): LintResult<CrcSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: CrcSpec): CrcSpec {
  return applyAllFixesGeneric(spec, RULES);
}
