import type { LintRule } from "@ocs/contracts/diagnostic";
import { optBool, optNumber, setOption } from "@ocs/contracts/pure";
import { requireFormatTool } from "../catalogue/tool-meta";
import {
  OPTION_ENTITY_FORM,
  OPTION_LENGTH,
  OPTION_RANDOM_BYTES,
  OPTION_SORT_KEYS,
  PASSWORD_ALPHABETS,
  PASSWORD_CLASS_OPTIONS,
  readClasses,
  readEntityForm,
  readLength,
  readUuidVersion,
} from "../pure";
import type { FormatSpec } from "../spec";

export const RULE_CODES = ["F001", "F002", "F003", "F004", "F005", "F006", "F007"] as const;

/**
 * One rule per real footgun, and the bar is the same as everywhere else here: would this change what
 * someone does. A rule confirming a good choice is noise, and noise is why people stop reading.
 *
 * Note what is *absent*. There is no "URL encoding is not encryption" rule, even though
 * `@ocs/encoding` has exactly that for Base64 -- because nobody mistakes a percent-encoded string for
 * a secret, where "Base64 is encryption" is a belief that reaches production. And there is no rule
 * about JSON key sorting or XML whitespace being lossy: both are opt-in controls whose own `detail`
 * says what they do, and a diagnostic that fires because you used a setting deliberately is the
 * definition of noise.
 */
export const RULES: readonly LintRule<FormatSpec>[] = [
  {
    /**
     * The rule this family most needs, and the only one at `insecure`.
     *
     * Decoding a JWT is trivial; *verifying* one needs the key. A tool that laid out the claims
     * without saying so would invite the exact mistake RFC 8725 opens with -- trusting a payload that
     * anybody holding the token can rewrite. No fix, because the fix is a different tool: the MAC
     * family for HS256, the asymmetric family for RS256 and ES256.
     */
    code: "F003",
    check(spec) {
      if (requireFormatTool(spec.variant).kind !== "jwt") return [];
      return [
        {
          code: "F003",
          level: "insecure",
          message: "Nothing here is verified. These claims are unauthenticated.",
          detail:
            "A JWT's header and payload are Base64url, not encrypted — anyone holding the token can read them, and anyone can produce a token with any claims they like. Only the signature makes a claim trustworthy, and checking it needs the key. Read the `alg` in the header, then verify with HMAC-SHA256 in the MAC family, or with RSA-PSS or ECDSA in the asymmetric family. Never decide anything on a decoded payload alone.",
        },
      ];
    },
  },
  {
    /**
     * Named entities outside HTML.
     *
     * XML defines five named references and takes every other one from a DTD, so `&nbsp;` in an XML
     * document is a well-formedness error rather than a space. The tool cannot know where the output
     * is going, which is exactly why this is `info` and offers the fix rather than blocking.
     */
    code: "F001",
    check(spec) {
      if (requireFormatTool(spec.variant).kind !== "htmlentity") return [];
      if (readEntityForm(spec.options) !== "named") return [];
      return [
        {
          code: "F001",
          level: "info",
          message: "Named references beyond the five XML ones only work in HTML.",
          detail:
            "XML defines exactly &amp; &lt; &gt; &quot; and &apos;. Everything else — &nbsp;, &eacute;, &mdash; — comes from a DTD, so an XML or SVG parser treats it as an undefined entity and refuses the document. Numeric references work in both, which is why they are the safe choice when the destination is not certainly HTML.",
          optionIds: [OPTION_ENTITY_FORM],
          fix: {
            label: "Use hexadecimal references",
            apply: (s) => ({ ...s, options: setOption(s.options, OPTION_ENTITY_FORM, "hex") }),
          },
        },
      ];
    },
  },
  {
    /**
     * v1 and v6 embed a timestamp; v3 and v5 embed a hash of their input.
     *
     * Worth one sentence because people reach for a UUID expecting an *opaque* identifier, and two of
     * these six are not. A v1 in a URL tells anybody who reads it roughly when the row was created;
     * a v5 of an email address is a stable, offline-guessable handle for that address.
     */
    code: "F002",
    check(spec) {
      if (requireFormatTool(spec.variant).kind !== "uuid") return [];
      const version = readUuidVersion(spec.options);
      if (version === "v1" || version === "v6") {
        return [
          {
            code: "F002",
            level: "info",
            message: `UUID${version} contains the time it was generated.`,
            detail:
              "The timestamp is not obscured — it is a 60-bit count of 100-nanosecond intervals, readable by anyone holding the identifier. That is fine for a database key and a leak in a public URL, where it discloses when a record was created. The node field here is random rather than a MAC address, so the machine is not disclosed. Use v4 or v7 if the value will be public and the creation time should not be.",
          },
        ];
      }
      if (version === "v3" || version === "v5") {
        return [
          {
            code: "F002",
            level: "info",
            message: `UUID${version} is a hash of the name, not a random value.`,
            detail:
              "Deterministic by design: the same namespace and name always give the same identifier, which is the point. It also means the identifier is guessable by anyone who can guess the name — a v5 of an email address can be recomputed offline from that address. Do not treat one as a secret or as a capability token.",
          },
        ];
      }
      return [];
    },
  },
  {
    /**
     * The password length floor, measured in entropy rather than characters.
     *
     * A character count alone says little: 16 characters over lower case only is weaker than 11 over
     * all four classes. So the rule computes what the settings actually produce and compares that,
     * which also means it fires correctly when someone narrows the alphabet rather than the length.
     */
    code: "F004",
    check(spec) {
      if (requireFormatTool(spec.variant).kind !== "password") return [];
      const selected = readClasses(spec.options);
      // The same fallback `compute.ts` applies, so the figure describes what the tool will produce.
      const classes = selected.length > 0 ? selected : (["lower", "upper", "digit"] as const);
      // Sizes read off the alphabets rather than restated: a fifth class would otherwise count as zero.
      const pool = classes.reduce((sum, id) => sum + PASSWORD_ALPHABETS[id].length, 0);
      if (pool === 0) return [];
      const bits = Math.floor(readLength(spec.options) * Math.log2(pool));
      if (bits >= 75) return [];
      return [
        {
          code: "F004",
          level: bits < 50 ? "warning" : "info",
          message: `These settings give about ${bits} bits of entropy.`,
          detail:
            "Roughly 75 bits is the point past which offline cracking stops being the cheapest attack on a password, so it is a reasonable floor for anything protecting something that matters. Below about 50 bits a determined attacker with a modern GPU is measured in hours. Raise the length, or add a character class — adding symbols to lower/upper/digit is worth about 3 bits per character.",
          optionIds: [OPTION_LENGTH],
          fix: {
            label: "Lengthen to 24 characters",
            // A pure function of the spec it is handed, as `applyAllFixes` requires: it reads nothing
            // from the closure, so it composes with any other fix landing in the same pass.
            apply: (s) => ({ ...s, options: setOption(s.options, OPTION_LENGTH, 24) }),
          },
        },
      ];
    },
  },
  {
    /** No classes selected at all: the compute path falls back, and silence would hide that. */
    code: "F005",
    check(spec) {
      if (requireFormatTool(spec.variant).kind !== "password") return [];
      if (readClasses(spec.options).length > 0) return [];
      return [
        {
          code: "F005",
          level: "warning",
          message: "No character classes are selected, so lower, upper and digits are being used.",
          detail:
            "The generator needs an alphabet, so it falls back rather than refusing. That is a reasonable default and it is not the one you chose, which is worth knowing before you compare this output against a policy.",
          optionIds: Object.values(PASSWORD_CLASS_OPTIONS),
          fix: {
            label: "Turn all four classes on",
            apply: (s) => ({
              ...s,
              options: Object.values(PASSWORD_CLASS_OPTIONS).reduce(
                (options, id) => setOption(options, id, true),
                s.options,
              ),
            }),
          },
        },
      ];
    },
  },
  {
    /**
     * Sorting keys changes the document.
     *
     * `info` rather than `warning`, and only when it is *on*: the control's own detail says what it
     * does, so this is here to make the consequence visible in the panel someone checks after
     * copying the output, not to argue against a deliberate choice.
     */
    code: "F006",
    check(spec) {
      if (requireFormatTool(spec.variant).kind !== "json") return [];
      if (!optBool(spec.options, OPTION_SORT_KEYS)) return [];
      return [
        {
          code: "F006",
          level: "info",
          message: "Sorting keys rewrites the document, not just its layout.",
          detail:
            "Everything else this tool does preserves what the document says — numbers keep their spelling, duplicate keys are both kept, key order survives. Sorting is the one setting that does not, which is exactly what makes it useful for diffing two files. Just do not sort the copy you are about to sign or hash.",
          optionIds: [OPTION_SORT_KEYS],
        },
      ];
    },
  },
  {
    /**
     * A random byte string too short to be a secret.
     *
     * The bar for a rule here is "would this change what someone does", and this one clears it: 4 or 8
     * bytes is 32 or 64 bits, which is guessable, and somebody generating a session token or an API key
     * at that length has made a mistake they cannot see -- the output looks exactly as random as a
     * 32-byte one. The fix raises it to 32, which is the length almost everyone actually wants.
     *
     * `insecure` rather than `warning`, on this family's own scale: it computes fine and should not be
     * trusted. And the threshold is 16 rather than something stricter, because 16 bytes is a real
     * answer for an IV or a salt, where freshness rather than unguessability is the point -- so
     * warning above it would be warning
     * about the tool's own commonest legitimate use, which is how a panel stops being read.
     */
    code: "F007",
    check(spec) {
      if (requireFormatTool(spec.variant).kind !== "randombytes") return [];
      const length = optNumber(spec.options, OPTION_RANDOM_BYTES) ?? 32;
      if (length >= 16) return [];
      const bits = length * 8;
      return [
        {
          code: "F007",
          level: "insecure",
          message: `${length} bytes is ${bits} bits, which is short for a secret.`,
          detail:
            "Short lengths are legitimate where the requirement is uniqueness rather than unguessability -- an IV or a salt does not have to be unpredictable, only fresh. They are not legitimate for a key, a session token, a password-reset link or an API key: at 64 bits an attacker who can test guesses offline gets there, and a short draw looks exactly as random as a long one, so nothing on screen will tell you. 16 bytes is the floor for a secret and 32 is the usual answer. Which of the two you need is a question about the thing consuming these bytes; that tool's own checks can answer it.",
          optionIds: [OPTION_RANDOM_BYTES],
          fix: {
            label: "Use 32 bytes",
            apply: (current) => ({
              ...current,
              options: setOption(current.options, OPTION_RANDOM_BYTES, 32),
            }),
          },
        },
      ];
    },
  },
];
