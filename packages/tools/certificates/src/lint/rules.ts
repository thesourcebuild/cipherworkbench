import type { LintRule } from "@ocs/contracts/diagnostic";
import { OPTION_VERIFY_CSR_SIG, readVerifyCsrSig } from "../pure";
import type { CertificateSpec } from "../spec";

export const RULE_CODES = ["CERT001", "CERT002"] as const;

export const RULES: readonly LintRule<CertificateSpec>[] = [
  {
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
    code: "CERT002",
    check(spec) {
      if (spec.variant !== "x509") return [];
      return [];
    },
  },
];
