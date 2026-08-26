import type { LintRule } from "@ocs/contracts/diagnostic";
import { requireEncodingTool } from "../catalogue/tool-meta";
import {
  OPTION_KEY_ORDER,
  OPTION_PADDING,
  OPTION_VARIANT,
  readDirection,
  readKeyOrder,
  readPadding,
  readVariant,
} from "../pure";
import type { EncodingSpec } from "../spec";

export const RULE_CODES = ["E001", "E002", "E003", "E004", "E005"] as const;

export const RULES: readonly LintRule<EncodingSpec>[] = [
  {
    /**
     * The rule this family exists to state.
     *
     * `info`, like `CRC001` and `S001`: nothing is wrong with encoding something, and a warning on a
     * tool's own core function teaches people to ignore the panel. But "Base64 is encryption" is a
     * belief that reaches production regularly -- in config files, in query strings, in "obfuscated"
     * API keys -- and the one place to correct it is next to the Base64 tool.
     */
    code: "E001",
    check(spec) {
      const tool = requireEncodingTool(spec.variant);
      return [
        {
          code: "E001",
          level: "info",
          message: `${tool.label} is an encoding, not encryption.`,
          detail:
            "There is no key and no secret. Anyone holding the output can get the input back, with this tool or a one-line command, and the transformation is public by design — its whole purpose is that both ends can do it. If a value has to stay secret, encrypt it; if it has to be tamper-evident, sign it or MAC it. Encoding is about what a byte is allowed to look like in transit, nothing more.",
        },
      ];
    },
  },
  {
    /**
     * Standard Base64 in a URL.
     *
     * `+`, `/` and `=` all have meanings in a URL and a form body, so a standard-alphabet value put
     * in one either breaks or arrives changed -- and the failure is intermittent, because it depends
     * on whether the particular bytes happened to produce those characters. That is exactly the kind
     * of bug that survives testing.
     */
    code: "E002",
    check(spec) {
      const tool = requireEncodingTool(spec.variant);
      if (tool.kind !== "base64") return [];
      if (readVariant(spec.options, "standard") !== "standard") return [];
      return [
        {
          code: "E002",
          level: "info",
          message: "Standard Base64 is not safe in a URL or a filename.",
          detail:
            "The standard alphabet uses `+` and `/`, and pads with `=`. In a URL, `+` decodes as a space in a query string, `/` ends a path segment, and `=` separates a parameter from its value — so a value that happens to contain them is corrupted rather than rejected, intermittently, depending on the bytes. RFC 4648 section 5 defines the URL-safe alphabet for this: `-` and `_` in their place. JWTs use it unpadded.",
          optionIds: [OPTION_VARIANT],
          fix: {
            label: "Use the URL-safe alphabet",
            apply: (s) => ({ ...s, options: { ...s.options, [OPTION_VARIANT]: "urlsafe" } }),
          },
        },
      ];
    },
  },
  {
    code: "E003",
    check(spec) {
      const tool = requireEncodingTool(spec.variant);
      if (!tool.exposes.includes(OPTION_PADDING)) return [];
      if (readPadding(spec.options) !== "unpadded") return [];
      if (readDirection(spec.options) !== "encode") return [];
      return [
        {
          code: "E003",
          level: "info",
          message: "Some decoders require the padding this leaves out.",
          detail:
            "RFC 4648 requires `=` padding unless the specification using the encoding says otherwise. Plenty do say otherwise — a JWT carries none — but a strict decoder handed an unpadded value will reject it, and Python's `base64.b64decode` is one. This tool accepts either form on the way back in, which is why the setting is safe to experiment with here and worth checking before you send it somewhere else.",
          optionIds: [OPTION_PADDING],
        },
      ];
    },
  },
  {
    /**
     * Base58 without its checksum.
     *
     * The reason Base58 exists is that a human might retype the value, and the reason base58check
     * exists is that a human retyping a value gets it wrong. Bitcoin has never used bare Base58 for
     * an address; a tool that made the bare form the obvious default without saying so would be
     * teaching the wrong lesson.
     */
    code: "E004",
    check(spec) {
      const tool = requireEncodingTool(spec.variant);
      if (tool.kind !== "base58") return [];
      if (readVariant(spec.options, "bitcoin") === "check") return [];
      return [
        {
          code: "E004",
          level: "info",
          message: "Plain Base58 carries no checksum, so a typo decodes to different bytes.",
          detail:
            "The alphabet drops 0, O, I and l so a value survives being read aloud or retyped, but nothing detects a mistake that gets through. Base58check appends four bytes of SHA-256d over the payload, which is what every Bitcoin address, WIF key and extended key actually uses — a single wrong character then fails to decode instead of quietly becoming somebody else's address.",
          optionIds: [OPTION_VARIANT],
          fix: {
            label: "Use Base58check",
            apply: (s) => ({ ...s, options: { ...s.options, [OPTION_VARIANT]: "check" } }),
          },
        },
      ];
    },
  },
  {
    code: "E005",
    check(spec) {
      const tool = requireEncodingTool(spec.variant);
      if (tool.kind !== "cbor") return [];
      if (readDirection(spec.options) !== "encode") return [];
      if (readKeyOrder(spec.options) === "sorted") return [];
      return [
        {
          code: "E005",
          level: "info",
          message:
            "Map keys are encoded in the order written, so these bytes are one of several.",
          detail:
            "CBOR preserves key order, which means the same JSON object typed two ways produces two different encodings — both valid, and not equal. That is fine for transmitting data and wrong for anything that hashes or signs the result, where the two ends have to agree byte for byte. RFC 8949 section 4.2.1 defines deterministic encoding: sorted keys, shortest forms. This writer always uses the shortest forms; sorting is the switch.",
          optionIds: [OPTION_KEY_ORDER],
          fix: {
            label: "Sort the keys",
            apply: (s) => ({ ...s, options: { ...s.options, [OPTION_KEY_ORDER]: "sorted" } }),
          },
        },
      ];
    },
  },
];
