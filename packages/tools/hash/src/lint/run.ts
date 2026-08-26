import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { HashSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: HashSpec): LintResult<HashSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: HashSpec): HashSpec {
  return applyAllFixesGeneric(spec, RULES);
}
