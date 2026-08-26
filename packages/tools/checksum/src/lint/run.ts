import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { ChecksumSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: ChecksumSpec): LintResult<ChecksumSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: ChecksumSpec): ChecksumSpec {
  return applyAllFixesGeneric(spec, RULES);
}
