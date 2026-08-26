import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { KdfSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: KdfSpec): LintResult<KdfSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: KdfSpec): KdfSpec {
  return applyAllFixesGeneric(spec, RULES);
}
