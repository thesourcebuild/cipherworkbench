import type { LintRule } from "@ocs/contracts/diagnostic";
import { encodingOptionId } from "@ocs/engine";
import { optString } from "@ocs/contracts/pure";
import { macCatalogueFor } from "../catalogue/options";
import { requireHmacHash, requireMacTool } from "../catalogue/tool-meta";
import { OPTION_HASH, OPTION_KEY, OPTION_TRUNCATE, withHash, withTruncate } from "../pure";
import { resolveMac } from "../resolve";
import type { MacSpec } from "../spec";

export const RULE_CODES = ["M001", "M002", "M003", "M004", "M005", "M006", "M007"] as const;

/** RFC 2104 section 5: never below half the digest, and never below 80 bits. */
const MIN_TRUNCATE_BITS = 80;

export const RULES: readonly LintRule<MacSpec>[] = [
  {
    code: "M001",
    check(spec) {
      const result = resolveMac(spec);
      if (!result.ok) {
        return [
          {
            code: "M001",
            level: "error",
            message: result.problem,
            optionIds: [result.optionId],
          },
        ];
      }
      return [];
    },
  },
  {
    /**
     * The key-length rule, and the reason blockLen is tracked on every hash's metadata.
     *
     * HMAC's strength is bounded by whichever is smaller, the key or the digest, and a
     * short key is invisible in the output. That is all the more reason to say it here.
     */
    code: "M002",
    check(spec) {
      if (spec.variant !== "hmac") return [];
      const result = resolveMac(spec);
      if (!result.ok) return [];

      const { key, hashId } = result.resolved;
      const hash = requireHmacHash(hashId);
      if (key.length >= hash.outputLen) return [];

      return [
        {
          code: "M002",
          level: key.length < 16 ? "insecure" : "warning",
          message: `A ${key.length}-byte key gives at most ${key.length * 8} bits of security, whatever the hash.`,
          detail: `HMAC's forgery resistance is bounded by the smaller of the key and the digest. ${hash.label} produces ${hash.outputLen} bytes, so anything shorter makes the key the weak half, and a key under 16 bytes is brute-forceable. Use at least ${hash.outputLen} random bytes; the Generate button next to the field produces exactly that.`,
          optionIds: [OPTION_KEY],
        },
      ];
    },
  },
  {
    /**
     * HMAC over a broken hash is not itself broken, and saying otherwise would be wrong.
     * There is no practical forgery against HMAC-MD5. But it is not something to choose,
     * and the distinction is worth stating precisely rather than flattened into a warning
     * that overclaims.
     *
     * Since the hash list grew to cover everything PHP will key, there are two claims to make rather
     * than one. MD5, SHA-1, MD2, MD4 and 3- or 4-pass HAVAL have demonstrated collisions; Tiger,
     * Snefru, GOST R 34.11-94 and the RIPEMD widths do not -- they are superseded or attacked at
     * reduced rounds. Telling a reader that Tiger is broken would be false, and a diagnostic that is
     * false about the easy case is not trusted about the hard one.
     */
    code: "M003",
    check(spec) {
      if (spec.variant !== "hmac") return [];
      const result = resolveMac(spec);
      if (!result.ok) return [];

      const hash = requireHmacHash(result.resolved.hashId);
      if (!hash.legacy) return [];

      const message = hash.broken
        ? `HMAC-${hash.label} is not broken, and ${hash.label} is.`
        : `${hash.label} is superseded, though HMAC over it is sound.`;
      const detail = hash.broken
        ? `HMAC only needs its hash to resist a keyed-collision attack, which is a weaker requirement than collision resistance, so HMAC-${hash.label} has no practical forgery even though ${hash.label} is unfit for signatures. It remains the wrong choice for anything new: the security margin is thinner than it needs to be and there is no cost to using SHA-256. Keep it only to reproduce an existing value.`
        : `No collision attack on the full ${hash.label} is published, and HMAC needs less of its hash than a signature does — so this tag is not weak. What it is, is unnecessary: ${hash.label} has been superseded, is unmaintained, and has had far less analysis than SHA-2 or SHA-3. Reproducing an existing value is a good reason to be here; choosing it for something new is not.`;

      return [
        {
          code: "M003",
          level: "warning",
          message,
          detail,
          optionIds: [OPTION_HASH],
          fix: {
            label: "Switch to SHA-256",
            apply: (s) => ({ ...s, options: withHash(s.options, "sha256") }),
          },
        },
      ];
    },
  },
  {
    code: "M004",
    check(spec) {
      if (spec.variant !== "hmac") return [];
      const result = resolveMac(spec);
      if (!result.ok) return [];

      const { truncateTo, hashId } = result.resolved;
      if (truncateTo === undefined) return [];

      const hash = requireHmacHash(hashId);
      const bits = truncateTo * 8;
      const tooShort = bits < MIN_TRUNCATE_BITS;
      const belowHalf = truncateTo * 2 < hash.outputLen;
      if (!tooShort && !belowHalf) return [];

      return [
        {
          code: "M004",
          level: tooShort ? "insecure" : "warning",
          message: tooShort
            ? `A ${bits}-bit tag can be guessed with probability 2^-${bits} per attempt.`
            : `${bits} bits is below half of ${hash.label}'s output.`,
          detail: `RFC 2104 section 5 says a truncated HMAC should keep at least half the digest and never fewer than ${MIN_TRUNCATE_BITS} bits. Truncation is otherwise entirely legitimate, and IPsec uses HMAC-SHA-256 cut to 128 bits, but the tag length directly sets the forgery probability. It is a number to choose deliberately rather than to shave.`,
          optionIds: [OPTION_TRUNCATE],
          fix: {
            label: "Use the full tag",
            apply: (s) => ({ ...s, options: withTruncate(s.options, undefined) }),
          },
        },
      ];
    },
  },
  {
    /**
     * Poly1305's one-time requirement, stated every time.
     *
     * Level info rather than a warning: the tool cannot tell whether the key is being
     * reused, so there is nothing to accuse the user of. But it is the single fact that
     * makes Poly1305 safe or catastrophic, and a user who reaches for it bare probably
     * wants ChaCha20-Poly1305 instead.
     */
    code: "M005",
    check(spec) {
      if (spec.variant !== "poly1305") return [];
      return [
        {
          code: "M005",
          level: "info",
          message: "This key must authenticate exactly one message, ever.",
          detail:
            "Poly1305 is a one-time authenticator. Two tags under one key give an attacker two equations in the key's two halves, which solves directly, with no search involved. Real protocols never reuse it: ChaCha20-Poly1305 derives a fresh Poly1305 key from the nonce for every message. If you are protecting data rather than implementing a spec, use that cipher instead.",
          optionIds: [OPTION_KEY],
        },
      ];
    },
  },
  {
    /**
     * The key that reads two ways.
     *
     * A key of `1234` is four bytes as text and two as hex, both are valid keys, and the tag says
     * nothing about which one produced it — so someone comparing this tool against another gets a
     * mismatch with no evidence about where it came from. That is not hypothetical: it is the one
     * thing about this family a user has actually been caught by.
     *
     * Narrow on purpose. It fires only while the key is being read as text *and* the text would
     * also parse as hex, which needs an even number of characters and nothing outside `0-9a-f`.
     * `password` never triggers it; `deadbeef` and `1234` do, and those are precisely the values
     * where the reading is genuinely ambiguous. `info`, because both readings are legitimate and
     * the tool cannot know which was meant — but with a fix, because if the guess is wrong the user
     * needs one click rather than a hunt for the selector.
     */
    code: "M007",
    check(spec) {
      const key = optString(spec.options, OPTION_KEY);
      if (key === undefined) return [];

      const catalogue = macCatalogueFor(spec.variant);
      const encodingId = encodingOptionId(OPTION_KEY);
      const encoding =
        optString(spec.options, encodingId) ??
        catalogue.get(OPTION_KEY)?.defaultBytesEncoding ??
        "utf-8";
      if (encoding !== "utf-8") return [];
      if (key.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(key)) return [];

      const asText = new TextEncoder().encode(key).length;
      const asHex = key.length / 2;
      return [
        {
          code: "M007",
          level: "info",
          message: `This key is being read as text — ${asText} bytes, not ${asHex}.`,
          detail: `Every character of "${key}" is a hex digit, so it could equally be ${asHex} raw bytes. Both are valid keys and the tag looks the same either way, which is why this is worth stating rather than guessing at: a value that will not match another tool is very often this and nothing else. Text is the default because a MAC key is usually a typed secret; switch the encoding beside the field if these are bytes you copied from somewhere.`,
          optionIds: [OPTION_KEY],
          fix: {
            label: "Read the key as hex",
            // Reads the key out of the spec it is handed, never out of the closure: `applyAllFixes`
            // runs every fix in one pass and another may already have changed it.
            apply: (s) => ({
              ...s,
              options: { ...s.options, [encodingOptionId(OPTION_KEY)]: "hex" },
            }),
          },
        },
      ];
    },
  },
  {
    code: "M006",
    check(spec) {
      const tool = requireMacTool(spec.variant);
      if (tool.streaming) return [];
      return [
        {
          code: "M006",
          level: "info",
          message: `${tool.label} cannot process input incrementally.`,
          detail:
            "The whole input is held in memory before the tag is computed. Fine for a message; a poor idea for a large file. Every hash-based MAC here streams, so this is a property of the construction rather than a limitation of the implementation.",
        },
      ];
    },
  },
];
