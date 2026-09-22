import type { LintRule } from "@ocs/contracts/diagnostic";
import {
  OPTION_CLIENT_AUTH,
  OPTION_CODE_SIGNING,
  OPTION_IS_CA,
  OPTION_SAN,
  OPTION_SERVER_AUTH,
  OPTION_VALIDITY_DAYS,
  OPTION_VERIFY_CSR_SIG,
  readClientAuth,
  readCodeSigning,
  readCreatorMode,
  readIsCa,
  readSan,
  readServerAuth,
  readValidityDays,
  readVerifyCsrSig,
} from "../pure";
import type { CertificateSpec } from "../spec";

export const RULE_CODES = [
  "CERT001",
  "CERT002",
  "CERT003",
  "CERT004",
  "CERT005",
  "CERT006",
] as const;

export const RULES: readonly LintRule<CertificateSpec>[] = [
  {
    /**
     * CERT001: CSR self-signature verification disabled.
     */
    code: "CERT001",
    check(spec) {
      if (spec.variant !== "csr") return [];
      const verify = readVerifyCsrSig(spec.options);
      if (!verify) {
        return [
          {
            code: "CERT001",
            level: "warning",
            optionIds: [OPTION_VERIFY_CSR_SIG],
            message: "CSR self-signature verification is turned off.",
            detail:
              "A Certificate Signing Request includes a self-signature to prove that the requester possesses the corresponding private key (Proof of Possession). Disabling verification accepts unauthenticated public key requests.",
          },
        ];
      }
      return [];
    },
  },
  {
    /**
     * CERT002: Apple / Google CAB Forum 398-day validity limit.
     * Leaf TLS certificates valid for more than 398 days are rejected by modern browsers.
     */
    code: "CERT002",
    check(spec) {
      if (spec.variant !== "cert-creator") return [];
      const mode = readCreatorMode(spec.options);
      // In mtls-suite, Root CA has 3650 days (valid for Root CA), but in single-cert leaf:
      const isCa = readIsCa(spec.options);
      if (mode === "single-cert" && !isCa) {
        const validity = readValidityDays(spec.options);
        if (validity > 398) {
          return [
            {
              code: "CERT002",
              level: "warning",
              optionIds: [OPTION_VALIDITY_DAYS],
              message: "Leaf certificate validity exceeds 398 days.",
              detail:
                "Apple Safari, Google Chrome, and modern TLS clients reject TLS server certificates with validity periods exceeding 398 days under CA/Browser Forum Baseline Requirements.",
            },
          ];
        }
      }
      return [];
    },
  },
  {
    /**
     * CERT003: Missing Subject Alternative Name (SAN).
     * RFC 2818 and modern browsers reject certificates without SANs (CN-only is deprecated).
     */
    code: "CERT003",
    check(spec) {
      if (spec.variant !== "cert-creator" && spec.variant !== "csr-creator") return [];
      const san = readSan(spec.options, "").trim();
      const isCa = readIsCa(spec.options);
      if (!isCa && san === "") {
        return [
          {
            code: "CERT003",
            level: "warning",
            optionIds: [OPTION_SAN],
            message: "Subject Alternative Name (SAN) is empty.",
            detail:
              "RFC 2818, RFC 6125, and modern TLS stacks require hostnames and IP addresses to be specified in the Subject Alternative Name (SAN) extension. Browsers no longer match hostnames against the Subject Common Name (CN).",
          },
        ];
      }
      return [];
    },
  },
  {
    /**
     * CERT004: Inconsistent CA Basic Constraints.
     * Flag when isCa is enabled on a leaf certificate when not intended as a Certificate Authority.
     */
    code: "CERT004",
    check(spec) {
      if (spec.variant !== "cert-creator") return [];
      const isCa = readIsCa(spec.options);
      const serverAuth = readServerAuth(spec.options);
      const clientAuth = readClientAuth(spec.options);

      // Warning when someone marks a certificate as both a CA and end-entity server/client
      if (isCa && (serverAuth || clientAuth)) {
        return [
          {
            code: "CERT004",
            level: "warning",
            optionIds: [OPTION_IS_CA],
            message: "Certificate is configured as both a CA and an end-entity TLS certificate.",
            detail:
              "Under X.509 PKI best practices, Certificate Authorities should not be directly deployed as end-entity TLS servers or clients. Separate the issuing CA from operational leaf identities.",
          },
        ];
      }
      return [];
    },
  },
  {
    /**
     * CERT005: Missing Key Usages for Leaf Certificate.
     * Leaf certificates should declare at least one intended usage (serverAuth, clientAuth, or codeSigning).
     */
    code: "CERT005",
    check(spec) {
      if (spec.variant !== "cert-creator") return [];
      const isCa = readIsCa(spec.options);
      if (isCa) return [];

      const serverAuth = readServerAuth(spec.options, false);
      const clientAuth = readClientAuth(spec.options, false);
      const codeSigning = readCodeSigning(spec.options, false);

      if (!serverAuth && !clientAuth && !codeSigning) {
        return [
          {
            code: "CERT005",
            level: "warning",
            optionIds: [OPTION_SERVER_AUTH, OPTION_CLIENT_AUTH, OPTION_CODE_SIGNING],
            message: "No Extended Key Usage (EKU) is selected.",
            detail:
              "A TLS certificate should specify at least one Extended Key Usage (e.g. TLS Web Server Authentication or TLS Web Client Authentication) to define its authorized operational roles.",
          },
        ];
      }
      return [];
    },
  },
];
