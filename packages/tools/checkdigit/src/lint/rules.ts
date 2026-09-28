import type { LintRule } from "@ocs/contracts/diagnostic";
import { requireCheckDigitTool } from "../catalogue/tool-meta";
import type { CheckDigitSpec } from "../spec";

export const RULE_CODES = ["CD001"] as const;

export const RULES: readonly LintRule<CheckDigitSpec>[] = [
  {
    code: "CD001",
    check(spec) {
      const tool = requireCheckDigitTool(spec.variant);
      return [
        {
          code: "CD001",
          level: "info",
          message: `${tool.label} catches transcription mistakes, not cryptographic tampering.`,
          detail:
            "Check digit algorithms are designed to detect human typing errors — such as single-digit typos and adjacent swapped digits (e.g., typing 45 instead of 54). They have negligible computational cost and small output widths, but they offer zero security against deliberate forgery or alteration.",
        },
      ];
    },
  },
];
