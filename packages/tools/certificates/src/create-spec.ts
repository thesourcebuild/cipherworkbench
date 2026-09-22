import { requireCertificateTool } from "./catalogue/tool-meta";
import {
  OPTION_CONVERTER_OP,
  OPTION_CREATOR_MODE,
  OPTION_DETAIL_LEVEL,
  OPTION_INPUT_FORMAT,
  OPTION_ISSUANCE_MODE,
  OPTION_PKI_HIERARCHY,
  OPTION_VERIFY_CSR_SIG,
  SPEC_VERSION,
} from "./pure";
import type { CertificateSpec } from "./spec";

export function createSpec(options?: { variant?: string }): CertificateSpec {
  const variant = options?.variant ?? "x509";
  requireCertificateTool(variant);

  const opts: Record<string, string | boolean | number> = {};

  if (variant === "x509") {
    opts[OPTION_INPUT_FORMAT] = "auto";
    opts[OPTION_DETAIL_LEVEL] = "summary";
  } else if (variant === "csr") {
    opts[OPTION_INPUT_FORMAT] = "auto";
    opts[OPTION_VERIFY_CSR_SIG] = true;
    opts[OPTION_DETAIL_LEVEL] = "summary";
  } else if (variant === "cert-converter") {
    opts[OPTION_CONVERTER_OP] = "auto";
    opts[OPTION_INPUT_FORMAT] = "auto";
  } else if (variant === "crl") {
    opts[OPTION_INPUT_FORMAT] = "auto";
    opts[OPTION_DETAIL_LEVEL] = "summary";
  } else if (variant === "cert-verifier") {
    opts[OPTION_INPUT_FORMAT] = "auto";
    opts[OPTION_DETAIL_LEVEL] = "summary";
  } else if (variant === "cert-creator") {
    opts[OPTION_CREATOR_MODE] = "single-cert";
    opts[OPTION_ISSUANCE_MODE] = "self-signed";
    opts[OPTION_PKI_HIERARCHY] = "2-tier";
    opts["commonName"] = "localhost";
    opts["san"] = "localhost, 127.0.0.1";
    opts["organization"] = "Cipher Workbench";
    opts["organizationalUnit"] = "Security";
    opts["country"] = "US";
    opts["state"] = "California";
    opts["locality"] = "San Francisco";
    opts["keyType"] = "ecdsa-p256";
    opts["hashType"] = "sha256";
    opts["validityDays"] = "365";
    opts["isCa"] = false;
    opts["serverAuth"] = true;
    opts["clientAuth"] = true;
    opts["codeSigning"] = false;
  } else if (variant === "csr-creator") {
    opts["commonName"] = "example.com";
    opts["san"] = "example.com, www.example.com";
    opts["organization"] = "Cipher Workbench";
    opts["organizationalUnit"] = "Engineering";
    opts["country"] = "US";
    opts["state"] = "California";
    opts["locality"] = "San Francisco";
    opts["keyType"] = "ecdsa-p256";
    opts["hashType"] = "sha256";
    opts["serverAuth"] = true;
    opts["clientAuth"] = true;
    opts["codeSigning"] = false;
  }

  return {
    specVersion: SPEC_VERSION,
    variant,
    options: opts,
  };
}
