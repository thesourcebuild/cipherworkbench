import { createOptionCatalogue, type OptionDef } from "@ocs/engine";
import type { PasswordArtifactOptionGroup } from "./groups";

export const OPTION_TRUECRYPT_BOOT_MODE = "boot-mode";
export const OPTION_BITLOCKER_OFFSET = "partition-offset";

const OPTIONS: readonly OptionDef<PasswordArtifactOptionGroup>[] = [
  {
    id: OPTION_TRUECRYPT_BOOT_MODE,
    label: "System volume boot mode",
    group: "extraction",
    kind: "boolean",
    availableOn: ["truecrypt"],
    summary:
      "Emit the TrueCrypt RIPEMD-160 boot descriptor instead of normal volume descriptors.",
    detail:
      "Enable only for a TrueCrypt system-encryption boot volume. Like upstream truecrypt2john, this changes the primary-header tag; a present hidden-volume header still emits the three normal tags.",
    order: 10,
  },
  {
    id: OPTION_BITLOCKER_OFFSET,
    label: "Partition offset",
    group: "extraction",
    kind: "number",
    arg: {
      placeholder: "0",
      unit: "bytes",
      min: 0,
      max: Number.MAX_SAFE_INTEGER,
      step: 1,
    },
    availableOn: ["bitlocker"],
    summary: "Byte offset at which the BitLocker partition begins in a full-disk image.",
    detail:
      "Leave at zero for a partition image. Use the exact partition start for a whole-disk image.",
    order: 20,
  },
];

export const PASSWORD_ARTIFACT_CATALOGUE = createOptionCatalogue(OPTIONS);
