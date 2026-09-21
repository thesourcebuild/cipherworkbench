import {
  applyAllFixes as applyAllFixesGeneric,
  lint as lintGeneric,
  type LintResult,
} from "@ocs/engine";
import type { CertificateSpec } from "../spec";
import { RULES } from "./rules";

export function lint(spec: CertificateSpec): LintResult<CertificateSpec> {
  return lintGeneric(spec, RULES);
}

export function applyAllFixes(spec: CertificateSpec): CertificateSpec {
  return applyAllFixesGeneric(spec, RULES);
}
