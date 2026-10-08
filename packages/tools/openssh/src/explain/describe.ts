import {
  readSshKeyType,
  readSshComment,
  readSshPassphrase,
  readSshRounds,
} from "../pure";
import type { OpenSshSpec } from "../spec";

export function describeSpec(spec: OpenSshSpec): string {
  const keyType = readSshKeyType(spec);
  const comment = readSshComment(spec);
  const passphrase = readSshPassphrase(spec);
  const rounds = readSshRounds(spec);

  const keyLabel =
    keyType === "ed25519"
      ? "Ed25519"
      : keyType === "rsa-2048"
        ? "RSA 2048-bit"
        : keyType === "rsa-4096"
          ? "RSA 4096-bit"
          : keyType === "ecdsa-p256"
            ? "ECDSA P-256"
            : keyType === "ecdsa-p384"
              ? "ECDSA P-384"
              : "ECDSA P-521";

  const encInfo =
    passphrase.length > 0
      ? `encrypted with AES-256-CTR & bcrypt-PBKDF (${rounds} rounds)`
      : "unencrypted";

  return `Generates ${keyLabel} OpenSSH keypair for "${comment}" (${encInfo}).`;
}
