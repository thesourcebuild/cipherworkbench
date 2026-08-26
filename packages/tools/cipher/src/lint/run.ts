import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { CipherSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: CipherSpec): LintResult<CipherSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: CipherSpec): CipherSpec {
  return applyAllFixesGeneric(spec, RULES);
}
