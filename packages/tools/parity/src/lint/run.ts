import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { ParitySpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: ParitySpec): LintResult<ParitySpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: ParitySpec): ParitySpec {
  return applyAllFixesGeneric(spec, RULES);
}
