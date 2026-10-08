import type { LintRule } from "@ocs/contracts/diagnostic";
import {
  readSshKeyType,
  readSshPassphrase,
  readSshRounds,
} from "../pure";
import type { OpenSshSpec } from "../spec";

export const RULE_CODES = ["SSH001", "SSH002", "SSH003"] as const;

export const RULES: readonly LintRule<OpenSshSpec>[] = [
  {
    code: "SSH001",
    check(spec) {
      const passphrase = readSshPassphrase(spec);
      if (passphrase.length === 0) {
        return [
          {
            code: "SSH001",
            level: "warning",
            message:
              "Private key is unencrypted. Anyone with read access to the key file or backups can authenticate with this key. Consider specifying a passphrase.",
          },
        ];
      }
      return [];
    },
  },
  {
    code: "SSH002",
    check(spec) {
      const keyType = readSshKeyType(spec);
      if (keyType === "rsa-2048") {
        return [
          {
            code: "SSH002",
            level: "info",
            message:
              "RSA 2048-bit keys provide approximately 112 bits of security and larger signature payloads. Ed25519 is recommended for modern infrastructure.",
          },
        ];
      }
      return [];
    },
  },
  {
    code: "SSH003",
    check(spec) {
      const passphrase = readSshPassphrase(spec);
      const rounds = readSshRounds(spec);
      if (passphrase.length > 0 && rounds < 16) {
        return [
          {
            code: "SSH003",
            level: "warning",
            message:
              "Low bcrypt-PBKDF iteration count. At least 16 rounds (OpenSSH default) or 64 rounds (hardened) are recommended to resist offline passphrase brute-forcing.",
          },
        ];
      }
      return [];
    },
  },
];
