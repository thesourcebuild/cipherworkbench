import type { LintRule } from "@ocs/contracts/diagnostic";
import { bytesEncodingOf, randomBytesValue } from "@ocs/engine";
import { requireKdfTool } from "../catalogue/tool-meta";
import {
  BCRYPT_PASSWORD_LIMIT,
  MIN_SALT_BYTES,
  OPTION_ARGON2_MEMORY,
  OPTION_BCRYPT_COST,
  OPTION_ITERATIONS,
  OPTION_PASSWORD,
  OPTION_ROUNDS,
  OPTION_SALT,
  OPTION_SCRYPT_N,
  OWASP_ARGON2_MEMORY_KIB,
  OPENSSH_DEFAULT_ROUNDS,
  OWASP_BCRYPT_COST,
  OWASP_SCRYPT_N,
  RECOMMENDED_SALT_BYTES,
  owaspPbkdf2Minimum,
  withOption,
} from "../pure";
import { kdfCatalogueFor } from "../catalogue/options";
import { resolveKdf } from "../resolve";
import type { KdfSpec } from "../spec";

export const RULE_CODES = [
  "K001",
  "K002",
  "K003",
  "K004",
  "K005",
  "K006",
  "K007",
  "K008",
  "K009",
] as const;

/** Above this, a single derivation is likely to make the tab unresponsive. */
const SLOW_MEMORY_KIB = 512 * 1024;
const SLOW_PBKDF2_ITERATIONS = 5_000_000;

export const RULES: readonly LintRule<KdfSpec>[] = [
  {
    code: "K001",
    check(spec) {
      const result = resolveKdf(spec);
      if (result.ok) return [];
      return [
        {
          code: "K001",
          level: "error",
          message: result.problem,
          optionIds: [result.optionId],
        },
      ];
    },
  },
  {
    /**
     * The cost-too-low rule, and the reason `pure.ts` records OWASP's figures as named
     * constants. Each tool has its own recommendation and its own units, so one rule covers
     * all four rather than four near-identical rules — the shape of the advice is the same
     * even though the numbers are not.
     */
    code: "K002",
    check(spec) {
      const result = resolveKdf(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      // In Verify mode the parameters come from the stored hash, so the form's cost settings
      // are not what will be used and complaining about them would be wrong.
      if (r.mode === "verify") return [];

      if (r.toolId === "pbkdf2") {
        const floor = owaspPbkdf2Minimum(r.hashId);
        if (r.iterations >= floor) return [];
        return [
          {
            code: "K002",
            level: r.iterations < floor / 10 ? "insecure" : "warning",
            message: `${r.iterations.toLocaleString()} iterations is below the recommended ${floor.toLocaleString()} for ${r.hashId.toUpperCase()}.`,
            detail:
              "OWASP's figure is calibrated so that a single derivation costs a server a few hundred milliseconds, which is the only thing standing between a leaked hash table and a full password recovery. The recommendation differs per hash because each iteration costs more with a wider digest.",
            optionIds: [OPTION_ITERATIONS],
            fix: {
              label: `Raise to ${floor.toLocaleString()}`,
              apply: (s) => ({
                ...s,
                options: withOption(s.options, OPTION_ITERATIONS, floor),
              }),
            },
          },
        ];
      }

      if (r.toolId === "scrypt") {
        if (r.scryptN >= OWASP_SCRYPT_N) return [];
        return [
          {
            code: "K002",
            level: r.scryptN < OWASP_SCRYPT_N / 16 ? "insecure" : "warning",
            message: `N=${r.scryptN} is below the recommended ${OWASP_SCRYPT_N}.`,
            detail: `Memory used is roughly 128 * N * r bytes, so at r=${r.scryptR} this configuration costs an attacker only about ${Math.round((128 * r.scryptN * r.scryptR) / 1024)} KiB per guess. OWASP's floor of 2^17 puts that at roughly 128 MiB, which is what makes large-scale cracking expensive.`,
            optionIds: [OPTION_SCRYPT_N],
            fix: {
              label: `Raise N to ${OWASP_SCRYPT_N}`,
              apply: (s) => ({
                ...s,
                options: withOption(s.options, OPTION_SCRYPT_N, OWASP_SCRYPT_N),
              }),
            },
          },
        ];
      }

      if (r.toolId === "argon2") {
        if (r.argon2MemoryKib >= OWASP_ARGON2_MEMORY_KIB) return [];
        return [
          {
            code: "K002",
            level: r.argon2MemoryKib < OWASP_ARGON2_MEMORY_KIB / 4 ? "insecure" : "warning",
            message: `${r.argon2MemoryKib} KiB is below the recommended ${OWASP_ARGON2_MEMORY_KIB} KiB.`,
            detail:
              "Memory is the axis that makes Argon2 worth choosing: cores are cheap and RAM is not, so a low memory setting throws away most of its advantage over PBKDF2. RFC 9106's second recommended profile is 64 MiB at t=3; OWASP's floor is 19 MiB at t=2.",
            optionIds: [OPTION_ARGON2_MEMORY],
            fix: {
              label: `Raise to ${OWASP_ARGON2_MEMORY_KIB} KiB`,
              apply: (s) => ({
                ...s,
                options: withOption(s.options, OPTION_ARGON2_MEMORY, OWASP_ARGON2_MEMORY_KIB),
              }),
            },
          },
        ];
      }

      if (r.toolId === "bcrypt") {
        if (r.bcryptCost >= OWASP_BCRYPT_COST) return [];
        return [
          {
            code: "K002",
            level: r.bcryptCost < 8 ? "insecure" : "warning",
            message: `Cost ${r.bcryptCost} is below the recommended ${OWASP_BCRYPT_COST}.`,
            detail: `The cost is logarithmic, so ${r.bcryptCost} does ${2 ** (OWASP_BCRYPT_COST - r.bcryptCost)}x less work than ${OWASP_BCRYPT_COST}. Anything at or below 8 is fast enough to brute-force a weak password on commodity hardware.`,
            optionIds: [OPTION_BCRYPT_COST],
            fix: {
              label: `Raise to ${OWASP_BCRYPT_COST}`,
              apply: (s) => ({
                ...s,
                options: withOption(s.options, OPTION_BCRYPT_COST, OWASP_BCRYPT_COST),
              }),
            },
          },
        ];
      }

      if (r.toolId === "bcryptpbkdf") {
        if (r.rounds >= OPENSSH_DEFAULT_ROUNDS) return [];
        return [
          {
            code: "K002",
            level: r.rounds < 8 ? "insecure" : "warning",
            /**
             * Measured against `ssh-keygen`'s default rather than an OWASP figure, because
             * nobody publishes a password-storage recommendation for this construction -- it
             * is used to unlock a key interactively, not to fill a hash table.
             */
            message: `${r.rounds} rounds is below \`ssh-keygen\`'s default of ${OPENSSH_DEFAULT_ROUNDS}.`,
            detail:
              "The rounds count here is linear, not a log2 exponent like bcrypt's cost -- so 8 rounds really is half the work of 16, rather than 1/256th. Anything below the default makes an encrypted private key cheaper to attack offline than every OpenSSH key in existence, for no benefit beyond a few milliseconds at unlock time.",
            optionIds: [OPTION_ROUNDS],
            fix: {
              label: `Raise to ${OPENSSH_DEFAULT_ROUNDS}`,
              apply: (s) => ({
                ...s,
                options: withOption(s.options, OPTION_ROUNDS, OPENSSH_DEFAULT_ROUNDS),
              }),
            },
          },
        ];
      }

      return [];
    },
  },
  {
    /**
     * HKDF is not a password hash, and this is the rule that says so.
     *
     * It is the one genuine category error this family can make. HKDF looks like the others,
     * takes a salt like the others, and provides no protection at all for a low-entropy
     * input — it is designed for material that is already unguessable and does deliberately
     * little work. Someone who reaches for it to store passwords gets something that runs
     * fast and defends nothing.
     */
    code: "K003",
    check(spec) {
      if (spec.variant !== "hkdf") return [];
      return [
        {
          code: "K003",
          level: "info",
          message: "HKDF is a key derivation function, not a password hash.",
          detail:
            "It assumes its input is already high-entropy — a Diffie-Hellman shared secret, a master key, CSPRNG output — and does no work to slow an attacker down. That is the correct design for its job and useless for a password: an attacker can test guesses as fast as you can derive. For a password, use Argon2id.",
        },
      ];
    },
  },
  {
    code: "K004",
    check(spec) {
      const result = resolveKdf(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (r.mode === "verify" || r.toolId === "bcrypt") return [];
      // HKDF's salt is optional by RFC 5869, so a short or absent one is not a fault there.
      if (r.toolId === "hkdf") return [];
      if (r.salt.length >= RECOMMENDED_SALT_BYTES) return [];

      const absent = r.salt.length === 0;
      return [
        {
          code: "K004",
          // No salt at all is the rainbow-table case, which is a different order of problem
          // from a salt that is merely on the short side.
          level: absent ? "insecure" : r.salt.length < MIN_SALT_BYTES ? "warning" : "info",
          message: absent
            ? "No salt: two identical passwords will produce identical hashes."
            : `A ${r.salt.length}-byte salt is shorter than the recommended ${RECOMMENDED_SALT_BYTES}.`,
          detail: absent
            ? "Without a salt, one precomputed table attacks every stored password at once, and a leaked table immediately reveals which users share a password. It is permitted here because the published test vectors use it, not because it is a configuration to ship."
            : "The salt does not need to be secret; it needs to be unique per password. Sixteen random bytes makes a collision across any realistic user table vanishingly unlikely, and stops one precomputed table attacking every stored password at once. Shorter salts start to repeat.",
          optionIds: [OPTION_SALT],
          fix: {
            label: `Generate ${RECOMMENDED_SALT_BYTES} random bytes`,
            /*
             * Uses the same `randomBytesValue` the form's Generate button calls, so the two cannot
             * disagree about what a good salt is *or* about which encoding to write it in.
             *
             * The encoding is now written only when the field's own choice cannot hold arbitrary
             * bytes. It used to be set to hex unconditionally, which was the reported bug one field
             * along: a salt being entered in Base64 had the selector moved out from under it. Where
             * the fallback does happen it is still essential -- a hex salt read as UTF-8 is a
             * different, shorter salt -- so the value and the encoding move together or not at all.
             */
            apply: (s) => {
              const current = bytesEncodingOf(
                kdfCatalogueFor(s.variant),
                s.options,
                OPTION_SALT,
              );
              const produced = randomBytesValue(RECOMMENDED_SALT_BYTES, current);
              return {
                ...s,
                options: {
                  ...s.options,
                  [OPTION_SALT]: produced.value,
                  ...(produced.encoding === current ? {} : { saltEncoding: produced.encoding }),
                },
              };
            },
          },
        },
      ];
    },
  },
  {
    /**
     * bcrypt's 72-byte truncation, which is silent in every implementation.
     *
     * Worth a rule of its own because the failure is invisible and counterintuitive: a
     * 100-character passphrase is strictly no better than its first 72 bytes, and a user who
     * chose a long passphrase specifically for safety gets none of the benefit past that
     * point. UTF-8 makes it worse — a passphrase of CJK characters hits the limit at 24
     * characters.
     */
    code: "K005",
    check(spec) {
      if (spec.variant !== "bcrypt") return [];
      const result = resolveKdf(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (r.password.length <= BCRYPT_PASSWORD_LIMIT) return [];

      const characters = r.passwordText.length;
      return [
        {
          code: "K005",
          level: "warning",
          message: `bcrypt will ignore everything past byte ${BCRYPT_PASSWORD_LIMIT} — this password is ${r.password.length} bytes.`,
          detail: `The truncation is silent and part of bcrypt's definition, not a bug in this tool. Your ${characters}-character password contributes only its first ${BCRYPT_PASSWORD_LIMIT} bytes, so the rest adds no security whatsoever. Note that the limit is in bytes: non-ASCII characters take two to four each. Argon2id and scrypt have no such limit.`,
          optionIds: [OPTION_PASSWORD],
        },
      ];
    },
  },
  {
    /**
     * The cost-too-high rule, which exists because this runs in a browser tab.
     *
     * Both directions matter. `K002` catches settings that fail to protect anyone; this
     * catches settings that will make the page stop responding. Warning is the right answer
     * rather than capping — capping would produce a hash that silently disagrees with the
     * parameters shown next to it.
     */
    code: "K006",
    check(spec) {
      const result = resolveKdf(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (r.mode === "verify") return [];

      const memoryKib =
        r.toolId === "argon2"
          ? r.argon2MemoryKib
          : r.toolId === "scrypt"
            ? (128 * r.scryptN * r.scryptR) / 1024
            : 0;

      if (memoryKib > SLOW_MEMORY_KIB) {
        return [
          {
            code: "K006",
            level: "info",
            message: `This will allocate roughly ${Math.round(memoryKib / 1024)} MiB and take a noticeable time.`,
            detail:
              "That is the point of a memory-hard function, and it applies to this page as much as to an attacker. The computation is synchronous, so a very large setting will make the tab unresponsive until it finishes. Nothing is wrong; it is simply working.",
          },
        ];
      }

      if (r.toolId === "pbkdf2" && r.iterations > SLOW_PBKDF2_ITERATIONS) {
        return [
          {
            code: "K006",
            level: "info",
            message: `${r.iterations.toLocaleString()} iterations will take a noticeable time in a browser.`,
            detail:
              "Well above any published recommendation. Iterating harder is also the least effective way to spend that time — the same budget in Argon2 buys memory cost, which is far more expensive for an attacker to parallelise.",
          },
        ];
      }

      return [];
    },
  },
  {
    code: "K007",
    check(spec) {
      const tool = requireKdfTool(spec.variant);
      const result = resolveKdf(spec);
      if (!result.ok || result.resolved.mode !== "derive") return [];
      if (tool.supportsVerify) return [];

      return [
        {
          code: "K007",
          level: "info",
          message: `${tool.label} output cannot be verified later on its own.`,
          detail:
            "There is no standard string format for it, so the parameters and salt are not part of the output — you have to store them yourself, and get them right again when you check. scrypt, Argon2 and bcrypt all emit a self-describing string instead, which is why those three have a Verify mode and this does not.",
        },
      ];
    },
  },
  {
    /**
     * An empty password, which the resolver deliberately allows.
     *
     * RFC 7914's own scrypt vector uses one, so refusing to compute it would make the tool
     * unable to reproduce the standard. Saying it protects nothing is the useful response —
     * the cost parameters are irrelevant when there is nothing to guess.
     */
    code: "K008",
    check(spec) {
      if (spec.variant === "hkdf") return [];
      const result = resolveKdf(spec);
      if (!result.ok) return [];
      const r = result.resolved;
      if (r.mode === "verify" || r.password.length > 0) return [];

      return [
        {
          code: "K008",
          level: "warning",
          message: "The password is empty, so none of the cost settings matter.",
          detail:
            "There is nothing to guess: an attacker who knows the salt and parameters can produce this hash directly, however expensive it is to compute. Permitted because these functions are defined over any byte string and the published test vectors use it — but it is not a password.",
          optionIds: [OPTION_PASSWORD],
        },
      ];
    },
  },
  {
    /**
     * EvpKDF, whatever it is configured with.
     *
     * Unconditional on the tool rather than on its parameters, because no parameter choice makes
     * this construction adequate: the work is one hash chain with no memory cost, so it
     * parallelises perfectly on a GPU no matter how high the count goes. That is different from
     * `K001`'s complaint about a low PBKDF2 iteration count, which a higher number genuinely
     * fixes -- so this does not offer a fix, because there is not one within the tool.
     *
     * `insecure` rather than `error`: it computes correctly and reproducing an old file is exactly
     * what it is for. Blocking it would make the tool unable to do its only job.
     */
    code: "K009",
    check(spec) {
      if (spec.variant !== "evpkdf") return [];
      return [
        {
          code: "K009",
          level: "insecure",
          message:
            "EVP_BytesToKey is not a password KDF. Use it to read old files, not to make new ones.",
          detail:
            "OpenSSL's original derivation, and the default was a single MD5 pass over an 8-byte salt -- recoverable at billions of guesses a second on a GPU. Raising the iteration count does not change the shape of the problem: there is no memory cost, so an attacker's parallel advantage is unbounded, which is precisely what scrypt and Argon2 exist to remove. Note also that `openssl enc` output is unauthenticated, so a file encrypted this way can be altered undetectably regardless of the key derivation. For new work: PBKDF2 at OWASP's floor, or better, Argon2id.",
          optionIds: [OPTION_ITERATIONS],
        },
      ];
    },
  },
];
