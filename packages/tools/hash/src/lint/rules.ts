import type { LintRule } from "@ocs/contracts/diagnostic";
import {
  effectiveSecurity,
  maxOutputLen,
  requireHashAlgorithm,
  resolvePasses,
} from "../catalogue/algorithm-meta";
import {
  DOUBLE_HASH_ITERATIONS,
  ITERATIONS_WARN_ABOVE,
  OPTION_ITERATIONS,
  OPTION_OUTPUT_LENGTH,
  readPasses,
  withOutputLength,
  withPasses,
  withoutIterations,
} from "../pure";
import type { HashSpec } from "../spec";

export const RULE_CODES = ["H001", "H002", "H003", "H004", "H005"] as const;

/**
 * One rule per real footgun. Note what is deliberately absent: there is no rule
 * saying "you used SHA-256, well done". Diagnostics the user cannot act on are
 * noise, and noise is what stops people reading the ones that matter.
 */
export const RULES: readonly LintRule<HashSpec>[] = [
  {
    // The posture lives on the algorithm metadata rather than in a hardcoded id
    // list here, so adding a broken algorithm in a later phase gets this rule for
    // free instead of needing this file edited too.
    code: "H001",
    check(spec) {
      const meta = requireHashAlgorithm(spec.algorithm);
      /**
       * The posture of what is selected, not of the worst thing the tool can do.
       *
       * HAVAL is one tool covering fifteen functions, and its badge carries the worst of them. At
       * five passes nothing published breaks it, so saying "broken" here would be an overclaim --
       * and the pass count is named in the message so it is clear which configuration is meant.
       */
      const passes = resolvePasses(meta, readPasses(spec.options));
      const security = effectiveSecurity(meta, passes);
      const label = passes === undefined ? meta.label : `${meta.label} at ${passes} passes`;
      if (security === "modern") return [];

      if (security === "not-a-mac") {
        return [
          {
            code: "H001",
            level: "info",
            message: `${label} detects accidental corruption, not tampering.`,
            // One sentence for every non-cryptographic hash, where this used to prefer the
            // algorithm's own `securityNote` and fall back to this. The fallback was the better
            // half: it says what to do, which is what a diagnostic is for.
            detail:
              "Anyone who can change the data can trivially recompute a matching value. Use it to catch a bad cable or a truncated download; never to establish that a file is the one you expected.",
          },
        ];
      }

      return [
        {
          code: "H001",
          level: security === "broken" ? "insecure" : "warning",
          message:
            security === "broken"
              ? `${label} is broken — do not use it to identify data an attacker can influence.`
              : `${label} is no longer a first choice for new work.`,
          /**
           * No auto-fix for the algorithm itself: switching would change which tool you are on, and
           * silently moving the user to a different page would discard the input they came here to
           * check. The header's SHA-256 link is the affordance.
           *
           * A pass count is different. Raising it stays inside this tool, so where the metadata says
           * a higher count is not broken, that fix is offered -- and it is a pure function of the
           * spec it is handed, as `applyAllFixes` requires.
           */
          ...(security === "broken" && meta.brokenBelowPasses !== undefined
            ? {
                fix: {
                  label: `Use ${meta.brokenBelowPasses} passes`,
                  apply: (current: HashSpec) => ({
                    ...current,
                    options: withPasses(current.options, meta.brokenBelowPasses!),
                  }),
                },
              }
            : {}),
        },
      ];
    },
  },
  {
    code: "H002",
    check(spec) {
      const iterations = spec.options[OPTION_ITERATIONS];
      if (typeof iterations !== "number" || iterations <= ITERATIONS_WARN_ABOVE) return [];

      const meta = requireHashAlgorithm(spec.algorithm);
      return [
        {
          code: "H002",
          level: "warning",
          message: `Iterating ${meta.label} ${iterations}× is not password hashing.`,
          detail: `A plain digest is designed to be fast, and repeating it ${iterations} times is still fast — a GPU will try billions of candidates per second either way. If you are hashing a password or a passphrase, use PBKDF2, scrypt or Argon2, which are built to be expensive. ${DOUBLE_HASH_ITERATIONS} passes is legitimate for reproducing double-SHA256 (Bitcoin block and transaction ids), which is why that count is not flagged; above it there is no established construction to reproduce.`,
          optionIds: [OPTION_ITERATIONS],
          fix: {
            label: "Back to a single pass",
            apply: (s) => ({ ...s, options: withoutIterations(s.options) }),
          },
        },
      ];
    },
  },
  {
    code: "H003",
    check(spec) {
      const meta = requireHashAlgorithm(spec.algorithm);
      if (meta.outputMode !== "xof") return [];
      return [
        {
          code: "H003",
          level: "info",
          message: `${meta.label} output length is yours to choose.`,
          detail:
            "This is an extendable-output function, so a shorter output is exactly the prefix of a longer one — asking for 16 bytes and truncating 32 bytes to 16 give identical results. Security is bounded by the output you actually take, not by the number in the name: 16 bytes of SHAKE256 buys 128-bit collision resistance at best.",
          optionIds: [OPTION_OUTPUT_LENGTH],
        },
      ];
    },
  },
  {
    // The distinction this rule exists for is the single easiest thing to get wrong
    // about BLAKE2, and getting it wrong produces a digest that looks plausible and
    // matches nothing.
    code: "H004",
    check(spec) {
      const meta = requireHashAlgorithm(spec.algorithm);
      if (meta.outputMode !== "parameterized") return [];
      return [
        {
          code: "H004",
          level: "info",
          message: `${meta.label} output length changes the function, not just its length.`,
          detail: `The digest size is mixed into ${meta.label}'s initial state, so ${meta.label} at 32 bytes is not the first 32 bytes of ${meta.label} at ${meta.outputLen} — the two are unrelated values. If you are trying to match a digest from elsewhere, set the same length that produced it rather than truncating a longer one. The ceiling is ${maxOutputLen(meta)} bytes.`,
          optionIds: [OPTION_OUTPUT_LENGTH],
        },
      ];
    },
  },
  {
    code: "H005",
    check(spec) {
      const meta = requireHashAlgorithm(spec.algorithm);
      const requested = spec.options[OPTION_OUTPUT_LENGTH];
      if (typeof requested !== "number" || meta.outputMode === "fixed") return [];

      const ceiling = maxOutputLen(meta);
      if (requested <= ceiling) return [];

      return [
        {
          code: "H005",
          level: "warning",
          message: `${meta.label} cannot produce ${requested} bytes — it stops at ${ceiling}.`,
          detail: `The result above is ${ceiling} bytes, not ${requested}. The value is clamped rather than refused so the tool still shows you a correct digest, but the number in the field is not what you are looking at.`,
          optionIds: [OPTION_OUTPUT_LENGTH],
          fix: {
            label: `Set it to ${ceiling} bytes`,
            apply: (s) => ({ ...s, options: withOutputLength(s.options, ceiling) }),
          },
        },
      ];
    },
  },
];
