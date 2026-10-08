import {
  createOptionCatalogue,
  type OptionCatalogue,
  type OptionDef,
} from "@ocs/engine";
import type { OpenSshOptionGroup } from "./groups";
import {
  OPTION_SSH_PRESET,
  OPTION_SSH_KEY_TYPE,
  OPTION_SSH_COMMENT,
  OPTION_SSH_PASSPHRASE,
  OPTION_SSH_ROUNDS,
  OPTION_SSH_FILENAME,
  OPTION_SSH_OUTPUT_FORMAT,
} from "../pure";

export const SSH_PRESET: OptionDef<OpenSshOptionGroup> = {
  id: OPTION_SSH_PRESET,
  label: "Configuration Preset",
  group: "preset",
  kind: "enum",
  choices: [
    {
      value: "modern-ed25519",
      label: "Modern Default",
      summary: "Ed25519 256-bit Edwards curve, id_ed25519, 16 rounds",
    },
    {
      value: "enterprise-rsa4096",
      label: "Enterprise RSA 4096",
      summary: "RSA 4096-bit, id_rsa, 16 rounds",
    },
    {
      value: "cloud-ecdsa256",
      label: "Cloud NIST P-256",
      summary: "ECDSA NIST P-256, id_ecdsa, 16 rounds",
    },
    {
      value: "hardened-ed25519",
      label: "Hardened 64-Round",
      summary: "Ed25519, id_ed25519_hardened, 64 bcrypt-PBKDF rounds",
    },
    {
      value: "custom",
      label: "Custom",
      summary: "Custom key algorithm, filename, and rounds",
    },
  ],
  summary: "Quick-start configuration templates for common environments.",
  detail:
    "Select a preset to automatically apply recommended key algorithm, standard filenames, and KDF rounds. Adjusting individual parameters will switch the preset to Custom.",
  order: 10,
};

export const SSH_OUTPUT_FORMAT: OptionDef<OpenSshOptionGroup> = {
  id: OPTION_SSH_OUTPUT_FORMAT,
  label: "Primary Output View",
  group: "output",
  kind: "enum",
  choices: [
    {
      value: "authorized_keys",
      label: "authorized_keys (.pub line)",
      summary: "Single-line public key entry for ~/.ssh/authorized_keys",
    },
    {
      value: "bubblebabble",
      label: "Bubblebabble Fingerprint (ssh-keygen -B)",
      summary: "Pronounceable fingerprint encoding (xebab-bybab-...)",
    },
    {
      value: "randomart",
      label: "Drunken Bishop Randomart (ssh-keygen -lv)",
      summary: "Visual 17x9 ASCII art matrix for host verification",
    },
    {
      value: "sha256",
      label: "SHA-256 Fingerprint (ssh-keygen -l)",
      summary: "RFC 4716 SHA-256 base64 digest",
    },
    {
      value: "md5",
      label: "MD5 Fingerprint (ssh-keygen -E md5)",
      summary: "Legacy 16-hex-byte colon-separated fingerprint",
    },
    {
      value: "private-openssh",
      label: "OpenSSH Private Key (id_*)",
      summary: "Native openssh-key-v1 PEM format (-----BEGIN OPENSSH PRIVATE KEY-----)",
    },
    {
      value: "private-pkcs8",
      label: "PKCS#8 PEM Private Key (.pem)",
      summary: "Standard PKCS#8 format (-----BEGIN PRIVATE KEY-----)",
    },
    {
      value: "rfc4716",
      label: "RFC 4716 SECSH Public Key (_ssh2.pub)",
      summary: "IETF SSH2 public key format (---- BEGIN SSH2 PUBLIC KEY ----)",
    },
    {
      value: "config",
      label: "SSH Client Config Snippet",
      summary: "Host configuration snippet for ~/.ssh/config",
    },
  ],
  summary: "Format displayed in the primary Result panel.",
  detail:
    "Choose which representation or fingerprint to display in the main Result box for one-click copying. All formats and files are always available in the Export drawer.",
  order: 10,
};

export const SSH_KEY_TYPE: OptionDef<OpenSshOptionGroup> = {
  id: OPTION_SSH_KEY_TYPE,
  label: "Key Algorithm",
  group: "key",
  kind: "enum",
  colSpan: 2,
  choices: [
    {
      value: "ed25519",
      label: "Ed25519 (256-bit Edwards Curve) [Recommended]",
      summary: "Modern OpenSSH default: fast, constant-time, compact 68-char keys",
    },
    {
      value: "rsa-2048",
      label: "RSA 2048-bit",
      summary: "Standard RSA key for legacy server compatibility",
    },
    {
      value: "rsa-4096",
      label: "RSA 4096-bit (High Security)",
      summary: "Maximum security RSA key (longer signatures)",
    },
    {
      value: "ecdsa-p256",
      label: "ECDSA NIST P-256",
      summary: "Standard NIST curve for compliance environments",
    },
    {
      value: "ecdsa-p384",
      label: "ECDSA NIST P-384",
      summary: "High-security 384-bit NIST elliptic curve",
    },
    {
      value: "ecdsa-p521",
      label: "ECDSA NIST P-521",
      summary: "521-bit NIST curve for maximum curve security",
    },
  ],
  summary: "Cryptographic algorithm and key size for the SSH keypair.",
  detail:
    "Ed25519 is the modern default and recommended choice for OpenSSH. RSA 2048/4096 is supported for legacy servers. ECDSA (P-256/P-384/P-521) is supported for NIST-compliant environments.",
  order: 10,
};

export const SSH_COMMENT: OptionDef<OpenSshOptionGroup> = {
  id: OPTION_SSH_COMMENT,
  label: "Key Comment",
  group: "options",
  kind: "text",
  arg: { placeholder: "user@cipherworkbench" },
  summary: "Comment tag appended to public key (matching ssh-keygen -C).",
  detail:
    "OpenSSH appends this label to the end of the public key file to help administrators identify the key owner.",
  order: 10,
};

export const SSH_FILENAME: OptionDef<OpenSshOptionGroup> = {
  id: OPTION_SSH_FILENAME,
  label: "Key Filename Base",
  group: "options",
  kind: "text",
  arg: { placeholder: "id_ed25519" },
  summary: "Base filename for generated private and public key files (matching ssh-keygen -f).",
  detail:
    "The default filename for the key pair (e.g. id_ed25519, id_rsa, id_ecdsa).",
  order: 20,
};

export const SSH_PASSPHRASE: OptionDef<OpenSshOptionGroup> = {
  id: OPTION_SSH_PASSPHRASE,
  label: "Key Passphrase",
  group: "security",
  kind: "password",
  secret: true,
  arg: { placeholder: "Leave empty for unencrypted key" },
  summary:
    "Passphrase for AES-256-CTR & bcrypt-PBKDF private key encryption (matching ssh-keygen -N).",
  detail:
    "If provided, the private key will be encrypted using AES-256-CTR and OpenSSH's native bcrypt-PBKDF key derivation function.",
  order: 10,
};

export const SSH_ROUNDS: OptionDef<OpenSshOptionGroup> = {
  id: OPTION_SSH_ROUNDS,
  label: "KDF Rounds (-a)",
  group: "security",
  kind: "number",
  arg: { placeholder: "16", min: 1, max: 1000, step: 1 },
  summary: "Number of bcrypt-PBKDF rounds (matching ssh-keygen -a 16).",
  detail:
    "OpenSSH defaults to 16 rounds. Increasing this makes offline passphrase attacks more computationally expensive.",
  order: 20,
};

export const ALL_OPENSSH_OPTIONS: OptionDef<OpenSshOptionGroup>[] = [
  SSH_PRESET,
  SSH_OUTPUT_FORMAT,
  SSH_KEY_TYPE,
  SSH_COMMENT,
  SSH_FILENAME,
  SSH_PASSPHRASE,
  SSH_ROUNDS,
];

export function opensshCatalogue(): OptionCatalogue<OpenSshOptionGroup> {
  return createOptionCatalogue(ALL_OPENSSH_OPTIONS);
}
