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
  "CERT007",
  "CERT008",
  "CERT009",
  "CERT010",
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
            message: "CSR self-signature verification is disabled.",
            detail:
              "Disabling proof-of-possession verification permits processing forged or corrupted Certificate Signing Requests.",
            fix: {
              id: "enable-csr-verify",
              label: "Enable cryptographic CSR self-signature verification",
              apply(s: CertificateSpec) {
                return {
                  ...s,
                  options: {
                    ...s.options,
                    [OPTION_VERIFY_CSR_SIG]: "true",
                  },
                };
              },
            },
          },
        ];
      }
      return [];
    },
  },
  {
    /**
     * CERT002: Certificate validity exceeds CAB Forum 398-day leaf limit.
     */
    code: "CERT002",
    check(spec) {
      if (spec.variant !== "cert-creator") return [];
      const mode = readCreatorMode(spec.options);
      if (mode === "mtls-suite") return [];

      const isCa = readIsCa(spec.options);
      if (isCa) return [];

      const days = readValidityDays(spec.options);
      if (days > 398) {
        return [
          {
            code: "CERT002",
            level: "warning",
            optionIds: [OPTION_VALIDITY_DAYS],
            message: `Validity of ${days} days exceeds the 398 days (398-day) limit for public leaf certificates.`,
            detail:
              "Under CA/Browser Forum Baseline Requirements §6.3.2 and Apple/Google root store policies, publicly trusted TLS leaf certificates issued on or after September 1, 2020 must not have a validity period exceeding 398 days.",
            fix: {
              id: "clamp-398-days",
              label: "Clamp validity period to 397 days (CAB Forum compliant)",
              apply(s: CertificateSpec) {
                return {
                  ...s,
                  options: {
                    ...s.options,
                    [OPTION_VALIDITY_DAYS]: "397",
                  },
                };
              },
            },
          },
        ];
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
  {
    /**
     * CERT006: Weak RSA Key Length.
     * Flags RSA key sizes below 2048 bits (NIST SP 800-57 / CAB Forum BR §6.1.5).
     */
    code: "CERT006",
    check(spec) {
      if (spec.variant !== "cert-creator" && spec.variant !== "csr-creator") return [];
      const rawKey = String(spec.options["keyType"] ?? "");
      if (rawKey === "rsa-1024" || rawKey === "rsa-512") {
        return [
          {
            code: "CERT006",
            level: "error",
            optionIds: ["keyType"],
            message: `Insecure RSA key size (${rawKey}).`,
            detail:
              "NIST SP 800-57 and CAB Forum Baseline Requirements §6.1.5 mandate a minimum RSA modulus of 2048 bits. Keys below 2048 bits are vulnerable to factorization.",
          },
        ];
      }
      return [];
    },
  },
  {
    /**
     * CERT007: Deprecated Signature Hash Algorithm.
     * Flags MD5 or SHA-1 signature algorithms.
     */
    code: "CERT007",
    check(spec) {
      if (spec.variant !== "cert-creator" && spec.variant !== "csr-creator") return [];
      const hash = String(spec.options["hashType"] ?? "").toLowerCase();
      if (hash === "sha1" || hash === "md5") {
        return [
          {
            code: "CERT007",
            level: "error",
            optionIds: ["hashType"],
            message: `Insecure signature digest algorithm (${hash.toUpperCase()}).`,
            detail:
              "SHA-1 and MD5 suffer from known collision attacks and are completely deprecated across all modern TLS trust stores. Use SHA-256, SHA-384, or SHA-512.",
          },
        ];
      }
      return [];
    },
  },
  {
    /**
     * CERT008: Malformed Subject Alternative Name (SAN).
     * Flags wildcards in TLDs (*.com), invalid IP addresses, or spaces.
     */
    code: "CERT008",
    check(spec) {
      if (spec.variant !== "cert-creator" && spec.variant !== "csr-creator") return [];
      const sanText = readSan(spec.options, "").trim();
      if (!sanText) return [];

      const parts = sanText.split(",").map((s) => s.trim()).filter(Boolean);
      for (const part of parts) {
        // TLD wildcard check (e.g. *.com, *.net, *.org)
        if (/^\*\.[a-z]{2,}$/i.test(part)) {
          return [
            {
              code: "CERT008",
              level: "error",
              optionIds: [OPTION_SAN],
              message: `Illegal wildcard SAN for top-level domain: "${part}".`,
              detail:
                "CAB Forum Baseline Requirements §3.2.2.6 explicitly forbids issuing wildcard certificates directly on Top-Level Domains (TLDs).",
            },
          ];
        }
        // Invalid IPv4 syntax check (e.g. octets > 255)
        if (/^\d+\.\d+\.\d+\.\d+$/.test(part)) {
          const octets = part.split(".").map(Number);
          if (octets.some((o) => o < 0 || o > 255)) {
            return [
              {
                code: "CERT008",
                level: "error",
                optionIds: [OPTION_SAN],
                message: `Malformed IPv4 SAN address: "${part}".`,
                detail: "Each IPv4 address octet must be between 0 and 255.",
              },
            ];
          }
        }
        // Disallowed characters in DNS names
        if (/[^a-zA-Z0-9.*_:-]/.test(part)) {
          return [
            {
              code: "CERT008",
              level: "warning",
              optionIds: [OPTION_SAN],
              message: `SAN contains illegal characters: "${part}".`,
              detail: "DNS names should only contain alphanumeric characters, hyphens, periods, and wildcards.",
            },
          ];
        }
      }
      return [];
    },
  },
  {
    /**
     * CERT009: Serial Number Bounds (RFC 5280 §4.1.2.2).
     */
    code: "CERT009",
    check(spec) {
      if (spec.variant !== "cert-creator") return [];
      const serial = String(spec.options["serialNumber"] ?? "").trim();
      if (!serial) return [];

      if (serial.startsWith("-")) {
        return [
          {
            code: "CERT009",
            level: "error",
            optionIds: ["serialNumber"],
            message: "Serial number must be a positive integer.",
            detail: "RFC 5280 §4.1.2.2 specifies that certificate serial numbers must be positive integers.",
          },
        ];
      }

      // Check octet length (> 20 octets / 40 hex digits)
      const cleanHex = serial.startsWith("0x") ? serial.slice(2) : serial;
      if (/^[0-9a-fA-F]+$/.test(cleanHex) && cleanHex.length > 40) {
        return [
          {
            code: "CERT009",
            level: "error",
            optionIds: ["serialNumber"],
            message: "Serial number exceeds 20 octets (160 bits).",
            detail: "RFC 5280 §4.1.2.2 limits certificate serial numbers to a maximum of 20 octets.",
          },
        ];
      }
      return [];
    },
  },
  {
    /**
     * CERT010: Missing BasicConstraints on CA Certificate.
     */
    code: "CERT010",
    check(spec) {
      if (spec.variant !== "cert-creator") return [];
      const isCa = readIsCa(spec.options);
      if (isCa && spec.options["basicConstraints"] === "false") {
        return [
          {
            code: "CERT010",
            level: "error",
            optionIds: [OPTION_IS_CA],
            message: "Certificate Authority must have BasicConstraints extension enabled (CA:TRUE).",
            detail:
              "RFC 5280 §4.2.1.9 requires the BasicConstraints extension with isCA set to TRUE for all certificate authority certificates.",
          },
        ];
      }
      return [];
    },
  },
];
