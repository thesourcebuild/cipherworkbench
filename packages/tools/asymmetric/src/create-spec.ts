import {
  DEFAULT_ECDH_CURVE,
  DEFAULT_ECDSA_CURVE,
  DEFAULT_PARAM_SETS,
  DEFAULT_RSA_HASH,
  DEFAULT_RSA_MODULUS,
  requireAsymmetricTool,
} from "./catalogue/tool-meta";
import {
  DEFAULT_RSA_SCHEME,
  DEFAULT_SIGNATURE_FORMAT,
  OPTION_CURVE,
  OPTION_HASH,
  OPTION_MODULUS_LENGTH,
  OPTION_OPERATION,
  OPTION_PARAM_SET,
  OPTION_SCHEME,
  OPTION_SIGNATURE_FORMAT,
  SPEC_VERSION,
} from "./pure";
import type { AsymmetricSpec } from "./spec";

/** The canonical default-spec factory. Every tool opens on its first operation. */
export function createSpec(options?: { variant?: string }): AsymmetricSpec {
  const variant = options?.variant ?? "ed25519";
  const tool = requireAsymmetricTool(variant);

  const values: AsymmetricSpec["options"] = {
    [OPTION_OPERATION]: tool.operations[0] ?? "generate",
  };

  if (variant === "rsa") {
    values[OPTION_MODULUS_LENGTH] = String(DEFAULT_RSA_MODULUS);
    values[OPTION_SCHEME] = DEFAULT_RSA_SCHEME;
    values[OPTION_HASH] = DEFAULT_RSA_HASH;
  }
  if (variant === "ecdsa") {
    values[OPTION_CURVE] = DEFAULT_ECDSA_CURVE;
    values[OPTION_HASH] = DEFAULT_RSA_HASH;
    values[OPTION_SIGNATURE_FORMAT] = DEFAULT_SIGNATURE_FORMAT;
  }
  if (variant === "ecdh") {
    values[OPTION_CURVE] = DEFAULT_ECDH_CURVE;
  }
  // The parameter set has to be in the default spec: every length the form checks comes from it.
  const defaultSet = DEFAULT_PARAM_SETS[variant];
  if (defaultSet !== undefined) values[OPTION_PARAM_SET] = defaultSet;

  return { specVersion: SPEC_VERSION, variant, options: values };
}
