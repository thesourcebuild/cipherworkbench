import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { EncodingSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: EncodingSpec): LintResult<EncodingSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: EncodingSpec): EncodingSpec {
  return applyAllFixesGeneric(spec, RULES);
}
