import type { LintRule } from "@ocs/contracts/diagnostic";
import { requireCrcTool } from "../catalogue/tool-meta";
import { isCustom, OPTION_INIT, OPTION_POLY } from "../pure";
import { matchingCatalogueEntry, resolveModel } from "../resolve";
import type { CrcSpec } from "../spec";

export const RULE_CODES = ["CRC001", "CRC002", "CRC003", "CRC004", "CRC005"] as const;

export const RULES: readonly LintRule<CrcSpec>[] = [
  {
    /**
     * The rule this whole family exists to surface.
     *
     * `info` rather than `warning`, deliberately: nothing is wrong with computing a
     * CRC, and crying wolf on the tool's own core function would train people to
     * ignore the panel. But the misuse it describes — treating a checksum as proof a
     * file was not tampered with — is genuinely the most common cryptographic mistake
     * there is, so it says so every time, in the terms that matter.
     */
    code: "CRC001",
    check(spec) {
      const tool = requireCrcTool(spec.variant);
      return [
        {
          code: "CRC001",
          level: "info",
          message: `${tool.label} detects accidental corruption, not tampering.`,
          detail:
            "Given any target CRC and the freedom to change a few bytes, producing data that matches it is straightforward arithmetic — not a search, a calculation. Use it to catch a bad cable, a truncated download or a flipped bit in RAM. If the question is whether a file is the file someone published, that needs SHA-256 and a signature.",
        },
      ];
    },
  },
  {
    code: "CRC002",
    check(spec) {
      if (!isCustom(spec.options)) return [];
      const resolved = resolveModel(spec);
      if (resolved.ok) return [];
      return [
        {
          code: "CRC002",
          level: "error",
          message: resolved.problem,
          detail:
            "Custom mode computes nothing until the polynomial is a valid hex value that fits the width. The other parameters default to zero, which is a real configuration; the polynomial has no sensible default.",
          optionIds: [resolved.optionId],
        },
      ];
    },
  },
  {
    code: "CRC003",
    check(spec) {
      if (!isCustom(spec.options)) return [];
      const resolved = resolveModel(spec);
      if (!resolved.ok) return [];

      const known = matchingCatalogueEntry(resolved.model);
      if (!known) return [];

      return [
        {
          code: "CRC003",
          level: "info",
          message: `These parameters are ${known.name}.`,
          detail: `${
            known.aliases?.length ? `Also known as ${known.aliases.join(", ")}. ` : ""
          }Selecting it from the Model list gives an identical result, plus its published check value to verify against.`,
          fix: {
            label: `Use ${known.name}`,
            apply: (s) => ({ ...s, options: { ...s.options, model: known.name } }),
          },
        },
      ];
    },
  },
  {
    code: "CRC004",
    check(spec) {
      if (!isCustom(spec.options)) return [];
      const resolved = resolveModel(spec);
      if (!resolved.ok || resolved.model.poly !== 0n) return [];
      return [
        {
          code: "CRC004",
          level: "warning",
          message: "A zero polynomial is not a CRC.",
          detail:
            "With no polynomial the register never feeds back, so the result is a function of the last few bytes alone and ignores everything before them. It will compute, and it will not detect anything.",
          optionIds: [OPTION_POLY],
        },
      ];
    },
  },
  {
    code: "CRC005",
    check(spec) {
      if (!isCustom(spec.options)) return [];
      const resolved = resolveModel(spec);
      if (!resolved.ok || resolved.model.init !== 0n) return [];
      return [
        {
          code: "CRC005",
          level: "info",
          message: "A zero initial value makes leading zero bytes invisible.",
          detail:
            "Starting from zero, any number of leading 0x00 bytes leaves the register at zero, so a message that gained or lost some checks out unchanged. Most standard variants use an all-ones init for exactly this reason. It is a legitimate choice — CRC-16/ARC and CRC-32/CKSUM both do it — just one worth knowing about.",
          optionIds: [OPTION_INIT],
        },
      ];
    },
  },
];
