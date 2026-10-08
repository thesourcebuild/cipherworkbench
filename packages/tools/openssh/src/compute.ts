import type { ToolResult, ToolResultField } from "@ocs/engine";
import type { CliProviderCommand } from "@ocs/contracts";
import {
  generateOpenSshSuite,
  type OpenSshSuiteResult,
} from "./crypto/openssh";
import {
  readSshKeyType,
  readSshComment,
  readSshPassphrase,
  readSshRounds,
  readSshFilename,
  readSshOutputFormat,
} from "./pure";
import type { OpenSshSpec } from "./spec";

export function opensshInfo(spec: OpenSshSpec): ToolResultField[] {
  const keyType = readSshKeyType(spec);
  const comment = readSshComment(spec);
  const passphrase = readSshPassphrase(spec);
  const rounds = readSshRounds(spec);

  const keyLabel =
    keyType === "ed25519"
      ? "Ed25519 (256-bit Edwards Curve)"
      : keyType === "rsa-2048"
        ? "RSA 2048-bit"
        : keyType === "rsa-4096"
          ? "RSA 4096-bit"
          : keyType === "ecdsa-p256"
            ? "ECDSA NIST P-256"
            : keyType === "ecdsa-p384"
              ? "ECDSA NIST P-384"
              : "ECDSA NIST P-521";

  return [
    {
      label: "Algorithm",
      value: keyLabel,
      hint: "Selected cryptographic signature scheme for OpenSSH.",
    },
    {
      label: "Comment",
      value: comment,
      hint: "Identity tag appended to the public key line.",
    },
    {
      label: "Encryption",
      value: passphrase.length > 0 ? "AES-256-CTR (bcrypt-PBKDF)" : "None (unencrypted)",
      hint:
        passphrase.length > 0
          ? `Private key is protected using ${rounds} bcrypt-PBKDF rounds.`
          : "Private key stored in plaintext openssh-key-v1 format.",
    },
  ];
}

export async function computeOpenSsh(spec: OpenSshSpec): Promise<ToolResult> {
  const keyType = readSshKeyType(spec);
  const comment = readSshComment(spec);
  const passphrase = readSshPassphrase(spec);
  const rounds = readSshRounds(spec);
  const filename = readSshFilename(spec);

  const suite: OpenSshSuiteResult = await generateOpenSshSuite({
    keyType,
    comment,
    passphrase,
    rounds,
    filename,
  });

  const fields: ToolResultField[] = [
    {
      label: "Algorithm",
      value: suite.algorithmLabel,
      hint: "OpenSSH key type",
    },
    {
      label: "Bit length",
      value: `${suite.bits} bits`,
    },
    {
      label: "Comment",
      value: suite.comment,
    },
    {
      label: "SHA-256 Fingerprint",
      value: suite.sha256Fingerprint,
      hint: "Standard OpenSSH fingerprint (RFC 4716 SHA-256 base64)",
    },
    {
      label: "MD5 Fingerprint",
      value: suite.md5Fingerprint,
      hint: "Legacy OpenSSH fingerprint format (ssh-keygen -E md5)",
    },
    {
      label: "Bubblebabble",
      value: suite.bubblebabble,
      hint: "Human-pronounceable key fingerprint (ssh-keygen -B)",
    },
    {
      label: "Encrypted",
      value: suite.isEncrypted ? "Yes (AES-256-CTR + bcrypt-PBKDF)" : "No",
    },
  ];

  if (suite.isEncrypted) {
    fields.push({
      label: "KDF rounds",
      value: `${suite.kdfRounds}`,
      hint: "Number of bcrypt-PBKDF hashing iterations",
    });
  }

  // Build CLI commands
  let typeFlag = "ed25519";
  let bitsFlag = "";
  if (keyType.startsWith("rsa-")) {
    typeFlag = "rsa";
    bitsFlag = ` -b ${suite.bits}`;
  } else if (keyType.startsWith("ecdsa-")) {
    typeFlag = "ecdsa";
    bitsFlag = ` -b ${suite.bits}`;
  }

  const passArgBash = suite.isEncrypted
    ? ` -N "${passphrase.replace(/"/g, '\\"')}" -a ${suite.kdfRounds}`
    : ' -N ""';
  const passArgPs = suite.isEncrypted
    ? ` -N '${passphrase.replace(/'/g, "''")}' -a ${suite.kdfRounds}`
    : ` -N '""'`;
  const passArgBat = suite.isEncrypted
    ? ` -N "${passphrase.replace(/"/g, '""')}" -a ${suite.kdfRounds}`
    : ' -N ""';

  const bashCmd = `ssh-keygen -t ${typeFlag}${bitsFlag} -C "${comment}" -f ~/.ssh/${filename}${passArgBash}`;
  const psCmd = `ssh-keygen -t ${typeFlag}${bitsFlag} -C "${comment}" -f "$HOME/.ssh/${filename}"${passArgPs}`;
  const batCmd = `ssh-keygen -t ${typeFlag}${bitsFlag} -C "${comment}" -f "%USERPROFILE%\\.ssh\\${filename}"${passArgBat}`;

  const cliProviders: CliProviderCommand[] = [
    {
      id: "openssh",
      label: "OpenSSH ssh-keygen",
      commands: {
        bash: [{ parts: [bashCmd] }],
        powershell: [{ parts: [psCmd] }],
        cmd: [{ parts: [batCmd] }],
      },
    },
    {
      id: "fingerprint",
      label: "Inspect Fingerprint & Randomart",
      commands: {
        bash: [{ parts: [`ssh-keygen -lv -f ~/.ssh/${filename}.pub`] }],
        powershell: [{ parts: [`ssh-keygen -lv -f "$HOME/.ssh/${filename}.pub"`] }],
        cmd: [{ parts: [`ssh-keygen -lv -f "%USERPROFILE%\\.ssh\\${filename}.pub"`] }],
      },
    },
    {
      id: "bubblebabble",
      label: "Inspect Bubblebabble",
      commands: {
        bash: [{ parts: [`ssh-keygen -B -f ~/.ssh/${filename}.pub`] }],
        powershell: [{ parts: [`ssh-keygen -B -f "$HOME/.ssh/${filename}.pub"`] }],
        cmd: [{ parts: [`ssh-keygen -B -f "%USERPROFILE%\\.ssh\\${filename}.pub"`] }],
      },
    },
  ];

  const working = [
    `=== OpenSSH Keypair Specification ===`,
    `Algorithm:      ${suite.algorithmLabel}`,
    `Bit length:     ${suite.bits} bits`,
    `Comment:        ${suite.comment}`,
    `Fingerprint:    ${suite.sha256Fingerprint}`,
    `MD5:            ${suite.md5Fingerprint}`,
    `Bubblebabble:   ${suite.bubblebabble}`,
    `Encrypted:      ${suite.isEncrypted ? `Yes (AES-256-CTR, ${suite.kdfRounds} rounds)` : "No"}`,
    ``,
    `=== Drunken Bishop Randomart (ssh-keygen -lv) ===`,
    suite.randomart,
    ``,
    `=== Server Deployment ===`,
    suite.knownHostsExample,
  ].join("\n");

  const files = [
    {
      name: `${filename}.pub`,
      content: `${suite.authorizedKeysLine}\n`,
      mimeType: "text/plain",
    },
    {
      name: filename,
      content: `${suite.opensshPrivateKeyPem}\n`,
      mimeType: "text/plain",
    },
    {
      name: `${filename}.pem`,
      content: `${suite.pkcs8PrivateKeyPem}\n`,
      mimeType: "text/plain",
    },
    {
      name: `${filename}_ssh2.pub`,
      content: `${suite.rfc4716Format}\n`,
      mimeType: "text/plain",
    },
    {
      name: "config",
      content: `${suite.sshConfig}\n`,
      mimeType: "text/plain",
    },
    {
      name: "commands.sh",
      content: `#!/usr/bin/env bash\nset -euo pipefail\n\n${bashCmd}\n`,
      mimeType: "text/x-shellscript",
    },
    {
      name: "commands.ps1",
      content: `${psCmd}\n`,
      mimeType: "text/plain",
    },
    {
      name: "commands.bat",
      content: `@echo off\r\n${batCmd}\r\n`,
      mimeType: "text/plain",
    },
  ];

  const outputFormat = readSshOutputFormat(spec);
  let primaryText = suite.authorizedKeysLine;
  if (outputFormat === "bubblebabble") {
    primaryText = suite.bubblebabble;
  } else if (outputFormat === "randomart") {
    primaryText = suite.randomart;
  } else if (outputFormat === "sha256") {
    primaryText = suite.sha256Fingerprint;
  } else if (outputFormat === "md5") {
    primaryText = suite.md5Fingerprint;
  } else if (outputFormat === "private-openssh") {
    primaryText = suite.opensshPrivateKeyPem;
  } else if (outputFormat === "private-pkcs8") {
    primaryText = suite.pkcs8PrivateKeyPem;
  } else if (outputFormat === "rfc4716") {
    primaryText = suite.rfc4716Format;
  } else if (outputFormat === "config") {
    primaryText = suite.sshConfig;
  }

  return {
    text: primaryText,
    working,
    fields,
    files,
    cliProviders,
  };
}
