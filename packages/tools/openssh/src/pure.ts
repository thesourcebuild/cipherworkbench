import type { OptionValue } from "@ocs/contracts";
import { setOption } from "@ocs/contracts";
import type { ToolSpecBase } from "@ocs/engine";
import type { SshKeyAlgorithm } from "./crypto/openssh";

export const OPTION_SSH_PRESET = "preset";
export const OPTION_SSH_KEY_TYPE = "key-type";
export const OPTION_SSH_COMMENT = "comment";
export const OPTION_SSH_PASSPHRASE = "passphrase";
export const OPTION_SSH_ROUNDS = "rounds";
export const OPTION_SSH_FILENAME = "filename";
export const OPTION_SSH_OUTPUT_FORMAT = "output-format";

export const SSH_PRESETS = [
  "modern-ed25519",
  "enterprise-rsa4096",
  "cloud-ecdsa256",
  "hardened-ed25519",
  "custom",
] as const;
export type SshPreset = (typeof SSH_PRESETS)[number];

export const SSH_OUTPUT_FORMATS = [
  "authorized_keys",
  "bubblebabble",
  "randomart",
  "sha256",
  "md5",
  "private-openssh",
  "private-pkcs8",
  "rfc4716",
  "config",
] as const;
export type SshOutputFormat = (typeof SSH_OUTPUT_FORMATS)[number];

export function detectSshPreset(spec: ToolSpecBase): SshPreset {
  const kt = readSshKeyType(spec);
  const fn = readSshFilename(spec);
  const rd = readSshRounds(spec);
  if (kt === "ed25519" && fn === "id_ed25519" && rd === 16) return "modern-ed25519";
  if (kt === "rsa-4096" && fn === "id_rsa" && rd === 16) return "enterprise-rsa4096";
  if (kt === "ecdsa-p256" && fn === "id_ecdsa" && rd === 16) return "cloud-ecdsa256";
  if (kt === "ed25519" && fn === "id_ed25519_hardened" && rd === 64) return "hardened-ed25519";
  return "custom";
}

export function readSshPreset(spec: ToolSpecBase): SshPreset {
  return detectSshPreset(spec);
}

export function readSshKeyType(spec: ToolSpecBase): SshKeyAlgorithm {
  const val = spec.options[OPTION_SSH_KEY_TYPE];
  if (
    val === "ed25519" ||
    val === "rsa-2048" ||
    val === "rsa-4096" ||
    val === "ecdsa-p256" ||
    val === "ecdsa-p384" ||
    val === "ecdsa-p521"
  ) {
    return val;
  }
  return "ed25519";
}

export function readSshComment(spec: ToolSpecBase): string {
  const val = spec.options[OPTION_SSH_COMMENT];
  return typeof val === "string" ? val : "user@cipherworkbench";
}

export function readSshPassphrase(spec: ToolSpecBase): string {
  const val = spec.options[OPTION_SSH_PASSPHRASE];
  return typeof val === "string" ? val : "";
}

export function readSshRounds(spec: ToolSpecBase): number {
  const val = spec.options[OPTION_SSH_ROUNDS];
  if (typeof val === "number" && val > 0) {
    return Math.floor(val);
  }
  return 16;
}

export function readSshFilename(spec: ToolSpecBase): string {
  const val = spec.options[OPTION_SSH_FILENAME];
  if (typeof val === "string" && val.trim().length > 0) {
    return val.trim();
  }
  const kt = readSshKeyType(spec);
  if (kt === "ed25519") return "id_ed25519";
  if (kt.startsWith("rsa")) return "id_rsa";
  return "id_ecdsa";
}

export function readSshOutputFormat(spec: ToolSpecBase): SshOutputFormat {
  const val = spec.options[OPTION_SSH_OUTPUT_FORMAT];
  if (typeof val === "string" && (SSH_OUTPUT_FORMATS as readonly string[]).includes(val)) {
    return val as SshOutputFormat;
  }
  return "authorized_keys";
}

/**
 * Handles option updates for OpenSSH tool, propagating preset changes to parameters
 * and recalculating active preset status when parameters change.
 */
export function handleSshOptionChange<TSpec extends ToolSpecBase>(
  spec: TSpec,
  id: string,
  value: OptionValue | undefined,
): TSpec {
  let nextOptions = setOption(spec.options, id, value);

  if (id === OPTION_SSH_PRESET) {
    if (value === "modern-ed25519") {
      nextOptions = setOption(nextOptions, OPTION_SSH_KEY_TYPE, "ed25519");
      nextOptions = setOption(nextOptions, OPTION_SSH_FILENAME, "id_ed25519");
      nextOptions = setOption(nextOptions, OPTION_SSH_ROUNDS, 16);
    } else if (value === "enterprise-rsa4096") {
      nextOptions = setOption(nextOptions, OPTION_SSH_KEY_TYPE, "rsa-4096");
      nextOptions = setOption(nextOptions, OPTION_SSH_FILENAME, "id_rsa");
      nextOptions = setOption(nextOptions, OPTION_SSH_ROUNDS, 16);
    } else if (value === "cloud-ecdsa256") {
      nextOptions = setOption(nextOptions, OPTION_SSH_KEY_TYPE, "ecdsa-p256");
      nextOptions = setOption(nextOptions, OPTION_SSH_FILENAME, "id_ecdsa");
      nextOptions = setOption(nextOptions, OPTION_SSH_ROUNDS, 16);
    } else if (value === "hardened-ed25519") {
      nextOptions = setOption(nextOptions, OPTION_SSH_KEY_TYPE, "ed25519");
      nextOptions = setOption(nextOptions, OPTION_SSH_FILENAME, "id_ed25519_hardened");
      nextOptions = setOption(nextOptions, OPTION_SSH_ROUNDS, 64);
    }
  } else if (id === OPTION_SSH_KEY_TYPE) {
    // If the key type changed, adjust default filename if previous filename was default
    const prevFn = spec.options[OPTION_SSH_FILENAME];
    if (
      !prevFn ||
      prevFn === "id_ed25519" ||
      prevFn === "id_ed25519_hardened" ||
      prevFn === "id_rsa" ||
      prevFn === "id_ecdsa"
    ) {
      if (value === "ed25519") {
        nextOptions = setOption(nextOptions, OPTION_SSH_FILENAME, "id_ed25519");
      } else if (typeof value === "string" && value.startsWith("rsa")) {
        nextOptions = setOption(nextOptions, OPTION_SSH_FILENAME, "id_rsa");
      } else {
        nextOptions = setOption(nextOptions, OPTION_SSH_FILENAME, "id_ecdsa");
      }
    }
    const tempSpec: ToolSpecBase = { ...spec, options: nextOptions };
    nextOptions = setOption(nextOptions, OPTION_SSH_PRESET, readSshPreset(tempSpec));
  } else if (id === OPTION_SSH_FILENAME || id === OPTION_SSH_ROUNDS) {
    const tempSpec: ToolSpecBase = { ...spec, options: nextOptions };
    nextOptions = setOption(nextOptions, OPTION_SSH_PRESET, readSshPreset(tempSpec));
  }

  return { ...spec, options: nextOptions };
}
