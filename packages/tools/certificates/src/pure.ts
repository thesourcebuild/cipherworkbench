import type { OptionValues } from "@ocs/contracts/options";
import { optBool, optString } from "@ocs/contracts/pure";

export const SPEC_VERSION = 1;

export const OPTION_INPUT_FORMAT = "inputFormat";
export const OPTION_DETAIL_LEVEL = "detailLevel";
export const OPTION_VERIFY_CSR_SIG = "verifyCsrSig";
export const OPTION_CONVERTER_OP = "converterOp";

// Creator Options
export const OPTION_COMMON_NAME = "commonName";
export const OPTION_ORGANIZATION = "organization";
export const OPTION_ORG_UNIT = "organizationalUnit";
export const OPTION_COUNTRY = "country";
export const OPTION_STATE = "state";
export const OPTION_LOCALITY = "locality";
export const OPTION_KEY_TYPE = "keyType";
export const OPTION_HASH_TYPE = "hashType";
export const OPTION_VALIDITY_DAYS = "validityDays";
export const OPTION_IS_CA = "isCa";
export const OPTION_SAN = "san";
export const OPTION_SERVER_AUTH = "serverAuth";
export const OPTION_CLIENT_AUTH = "clientAuth";
export const OPTION_CODE_SIGNING = "codeSigning";

export const OPTION_CREATOR_MODE = "creatorMode";
export const OPTION_ISSUANCE_MODE = "issuanceMode";
export const OPTION_PKI_HIERARCHY = "pkiHierarchy";
export const OPTION_INTERMEDIATE_COMMON_NAME = "intermediateCommonName";
export const OPTION_CA_CERT = "caCert";
export const OPTION_CA_PRIVATE_KEY = "caPrivateKey";
export const OPTION_CLIENT_COMMON_NAME = "clientCommonName";
export const OPTION_MTLS_P12_PASSWORD = "mtlsP12Password";

export const OPTION_PASSWORD = "password";
export const OPTION_PRIVATE_KEY = "privateKey";

export type CreatorModeOption = "single-cert" | "mtls-suite";
export type IssuanceModeOption = "self-signed" | "ca-signed";
export type PkiHierarchyOption = "2-tier" | "3-tier";

export type InputFormatOption = "auto" | "pem" | "der" | "hex";
export type DetailLevelOption = "summary" | "full-dump";
export type ConverterOpOption =
  | "auto"
  | "pem-to-der"
  | "der-to-pem"
  | "pem-to-cer"
  | "cer-to-pem"
  | "pem-to-pkcs7"
  | "pkcs7-to-pem"
  | "pem-to-pkcs12"
  | "pkcs12-to-pem"
  | "extract-public-key"
  | "split-chain";

export type KeyTypeOption =
  | "ecdsa-p256"
  | "ecdsa-p384"
  | "rsa-2048"
  | "rsa-4096"
  | "ed25519";

export type HashTypeOption = "sha256" | "sha384" | "sha512";

export function readInputFormat(options: OptionValues): InputFormatOption {
  const val = optString(options, OPTION_INPUT_FORMAT);
  if (val === "pem" || val === "der" || val === "hex") return val;
  return "auto";
}

export function readDetailLevel(options: OptionValues): DetailLevelOption {
  const val = optString(options, OPTION_DETAIL_LEVEL);
  if (val === "full-dump") return "full-dump";
  return "summary";
}

export function readVerifyCsrSig(options: OptionValues): boolean {
  return optBool(options, OPTION_VERIFY_CSR_SIG) ?? true;
}

export function readConverterOp(options: OptionValues): ConverterOpOption {
  const val = optString(options, OPTION_CONVERTER_OP);
  if (
    val === "pem-to-der" ||
    val === "der-to-pem" ||
    val === "pem-to-cer" ||
    val === "cer-to-pem" ||
    val === "pem-to-pkcs7" ||
    val === "pkcs7-to-pem" ||
    val === "pem-to-pkcs12" ||
    val === "pkcs12-to-pem" ||
    val === "extract-public-key" ||
    val === "split-chain"
  ) {
    return val;
  }
  return "auto";
}

export function readPassword(options: OptionValues): string {
  return optString(options, OPTION_PASSWORD) ?? "";
}

export function readPrivateKey(options: OptionValues): string {
  return optString(options, OPTION_PRIVATE_KEY) ?? "";
}

export function readCommonName(options: OptionValues, defaultVal = "localhost"): string {
  return optString(options, OPTION_COMMON_NAME) ?? defaultVal;
}

export function readOrganization(options: OptionValues, defaultVal = "Cipher Workbench"): string {
  return optString(options, OPTION_ORGANIZATION) ?? defaultVal;
}

export function readOrgUnit(options: OptionValues, defaultVal = "Security"): string {
  return optString(options, OPTION_ORG_UNIT) ?? defaultVal;
}

export function readCountry(options: OptionValues, defaultVal = "US"): string {
  return optString(options, OPTION_COUNTRY) ?? defaultVal;
}

export function readState(options: OptionValues, defaultVal = "California"): string {
  return optString(options, OPTION_STATE) ?? defaultVal;
}

export function readLocality(options: OptionValues, defaultVal = "San Francisco"): string {
  return optString(options, OPTION_LOCALITY) ?? defaultVal;
}

export function readKeyType(options: OptionValues, defaultVal: KeyTypeOption = "ecdsa-p256"): KeyTypeOption {
  const val = optString(options, OPTION_KEY_TYPE);
  if (
    val === "ecdsa-p256" ||
    val === "ecdsa-p384" ||
    val === "rsa-2048" ||
    val === "rsa-4096" ||
    val === "ed25519"
  ) {
    return val;
  }
  return defaultVal;
}

export function readHashType(options: OptionValues, defaultVal: HashTypeOption = "sha256"): HashTypeOption {
  const val = optString(options, OPTION_HASH_TYPE);
  if (val === "sha256" || val === "sha384" || val === "sha512") return val;
  return defaultVal;
}

export function readValidityDays(options: OptionValues, defaultVal = 365): number {
  const val = optString(options, OPTION_VALIDITY_DAYS);
  if (val) {
    const parsed = parseInt(val, 10);
    if (!isNaN(parsed) && parsed > 0) return parsed;
  }
  return defaultVal;
}

export function readIsCa(options: OptionValues, defaultVal = false): boolean {
  return optBool(options, OPTION_IS_CA) ?? defaultVal;
}

export function readSan(options: OptionValues, defaultVal = "localhost, 127.0.0.1"): string {
  return optString(options, OPTION_SAN) ?? defaultVal;
}

export function readServerAuth(options: OptionValues, defaultVal = true): boolean {
  return optBool(options, OPTION_SERVER_AUTH) ?? defaultVal;
}

export function readClientAuth(options: OptionValues, defaultVal = true): boolean {
  return optBool(options, OPTION_CLIENT_AUTH) ?? defaultVal;
}

export function readCodeSigning(options: OptionValues, defaultVal = false): boolean {
  return optBool(options, OPTION_CODE_SIGNING) ?? defaultVal;
}

export function readCreatorMode(options: OptionValues): CreatorModeOption {
  const val = optString(options, OPTION_CREATOR_MODE);
  if (val === "mtls-suite") return "mtls-suite";
  return "single-cert";
}

export function readIssuanceMode(options: OptionValues): IssuanceModeOption {
  const val = optString(options, OPTION_ISSUANCE_MODE);
  if (val === "ca-signed") return "ca-signed";
  return "self-signed";
}

export function readCaCert(options: OptionValues): string {
  return optString(options, OPTION_CA_CERT) ?? "";
}

export function readCaPrivateKey(options: OptionValues): string {
  return optString(options, OPTION_CA_PRIVATE_KEY) ?? "";
}

export function readClientCommonName(options: OptionValues, defaultVal = "client-app-01"): string {
  return optString(options, OPTION_CLIENT_COMMON_NAME) ?? defaultVal;
}

export function readMtlsP12Password(options: OptionValues, defaultVal = "changeit"): string {
  return optString(options, OPTION_MTLS_P12_PASSWORD) ?? defaultVal;
}

export function readPkiHierarchy(options: OptionValues): PkiHierarchyOption {
  const val = optString(options, OPTION_PKI_HIERARCHY);
  if (val === "3-tier") return "3-tier";
  return "2-tier";
}

export function readIntermediateCommonName(options: OptionValues, defaultVal = "Internal Issuing CA"): string {
  return optString(options, OPTION_INTERMEDIATE_COMMON_NAME) ?? defaultVal;
}


