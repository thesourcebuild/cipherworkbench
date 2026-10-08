import { requireOpenSshTool } from "./catalogue/tool-meta";
import {
  OPTION_SSH_PRESET,
  OPTION_SSH_KEY_TYPE,
  OPTION_SSH_COMMENT,
  OPTION_SSH_PASSPHRASE,
  OPTION_SSH_ROUNDS,
  OPTION_SSH_FILENAME,
  OPTION_SSH_OUTPUT_FORMAT,
} from "./pure";
import { type OpenSshSpec, SPEC_VERSION } from "./spec";

export function createSpec(options?: { variant?: string }): OpenSshSpec {
  const variant = options?.variant ?? "ssh-keygen";
  requireOpenSshTool(variant);

  return {
    specVersion: SPEC_VERSION,
    variant: "ssh-keygen",
    options: {
      [OPTION_SSH_PRESET]: "modern-ed25519",
      [OPTION_SSH_OUTPUT_FORMAT]: "authorized_keys",
      [OPTION_SSH_KEY_TYPE]: "ed25519",
      [OPTION_SSH_COMMENT]: "user@cipherworkbench",
      [OPTION_SSH_PASSPHRASE]: "",
      [OPTION_SSH_ROUNDS]: 16,
      [OPTION_SSH_FILENAME]: "id_ed25519",
    },
  };
}
