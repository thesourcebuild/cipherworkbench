import { requireCertificateTool } from "./catalogue/tool-meta";
import {
  OPTION_CONVERTER_OP,
  OPTION_CREATOR_MODE,
  OPTION_DETAIL_LEVEL,
  OPTION_INPUT_FORMAT,
  OPTION_ISSUANCE_MODE,
  OPTION_HASH_TYPE,
  OPTION_PKI_HIERARCHY,
  OPTION_VERIFY_CSR_SIG,
  OPTION_CA_MODE,
  OPTION_OCSP_OP,
  OPTION_ACME_DOMAIN,
  OPTION_ACME_TOKEN,
  OPTION_ACME_ACCOUNT_KEY,
  OPTION_PRIVATE_KEY,
  OPTION_COMPARISON_CERT,
  OPTION_ROOT_KEY_TYPE,
  OPTION_ROOT_HASH_TYPE,
  OPTION_INTERMEDIATE_KEY_TYPE,
  OPTION_INTERMEDIATE_HASH_TYPE,
  OPTION_SERVER_KEY_TYPE,
  OPTION_SERVER_HASH_TYPE,
  OPTION_CLIENT_KEY_TYPE,
  OPTION_CLIENT_HASH_TYPE,
  SPEC_VERSION,
} from "./pure";
import { RSA_CERTIFICATE_PEM, RSA_PRIVATE_KEY_PEM } from "./samples";
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
    opts[OPTION_ROOT_KEY_TYPE] = "ecdsa-p256";
    opts[OPTION_ROOT_HASH_TYPE] = "sha256";
    opts[OPTION_INTERMEDIATE_KEY_TYPE] = "ecdsa-p256";
    opts[OPTION_INTERMEDIATE_HASH_TYPE] = "sha256";
    opts[OPTION_SERVER_KEY_TYPE] = "ecdsa-p256";
    opts[OPTION_SERVER_HASH_TYPE] = "sha256";
    opts[OPTION_CLIENT_KEY_TYPE] = "ecdsa-p256";
    opts[OPTION_CLIENT_HASH_TYPE] = "sha256";
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
  } else if (variant === "csr-signer") {
    opts[OPTION_CA_MODE] = "ephemeral-ca";
    opts[OPTION_HASH_TYPE] = "sha256";
    opts["validityDays"] = "365";
    opts["serverAuth"] = true;
    opts["clientAuth"] = true;
    opts["codeSigning"] = false;
  } else if (variant === "ocsp") {
    opts[OPTION_OCSP_OP] = "inspect-response";
  } else if (variant === "acme") {
    opts[OPTION_ACME_DOMAIN] = "example.com";
    opts[OPTION_ACME_TOKEN] = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    opts[OPTION_ACME_ACCOUNT_KEY] = "kRLr_6fsVn8_93J9l7Xp89V44W5R5-kZ3v3Y1b2_ABC";
  } else if (variant === "cert-matcher") {
    opts[OPTION_PRIVATE_KEY] = RSA_PRIVATE_KEY_PEM;
  } else if (variant === "cert-diff") {
    opts[OPTION_COMPARISON_CERT] = RSA_CERTIFICATE_PEM;
  }

  return {
    specVersion: SPEC_VERSION,
    variant,
    options: opts,
  };
}
